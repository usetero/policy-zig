const std = @import("std");
const proto = @import("proto");
const types = @import("./types.zig");
const redact_mod = @import("./redact.zig");

const LogTransform = proto.policy.LogTransform;
const LogRemove = proto.policy.LogRemove;
const LogRedact = proto.policy.LogRedact;
const LogRename = proto.policy.LogRename;
const LogAdd = proto.policy.LogAdd;
const AttributePath = proto.policy.AttributePath;

// Re-export types for convenience
pub const FieldRef = types.FieldRef;
pub const LogAccessor = types.LogAccessor;
pub const TransformResult = types.TransformResult;

/// Optional configuration for transform application.
///
/// Defaults disable the regex-redact path: redacts behave as whole-value
/// replacement when `compiled_redacts` is empty and `scratch` is null.
pub const TransformOptions = struct {
    /// Parallel slice over `transform.redact.items`. Each non-null entry holds
    /// a pre-compiled regex + replacement template; null slots (or indices past
    /// the end of this slice) fall through to whole-value redaction.
    compiled_redacts: []const ?redact_mod.Compiled = &.{},
    /// Scratch allocator for regex substitution output. Required for regex-
    /// redact; if null, regex rules degrade to no-op (they cannot allocate
    /// their substituted output).
    ///
    /// Must be an arena-style allocator (or otherwise long-lived): the
    /// substituted bytes are handed to the mutator by reference and are not
    /// freed by `applyRedact`. Callers that retain references past the call
    /// must keep `scratch` alive at least that long, and should reset/deinit
    /// the arena at a natural boundary (e.g. per log record).
    scratch: ?std.mem.Allocator = null,
};

/// Optional configuration for a single redact rule.
pub const RedactOptions = struct {
    /// Pre-compiled regex + replacement template. When non-null, the regex
    /// path runs; when null, whole-value replacement runs.
    compiled: ?*const redact_mod.Compiled = null,
    /// Scratch allocator for regex substitution output. Ignored when
    /// `compiled` is null; required (non-null) for the regex path to run.
    ///
    /// Must outlive any mutator-retained reference to the substituted bytes:
    /// `applyRedact` allocates into `scratch` and hands the slice to the
    /// mutator by reference without freeing it. Use an arena that the caller
    /// resets at an appropriate boundary.
    scratch: ?std.mem.Allocator = null,
};

/// Apply all transforms from a LogTransform in order: remove → redact → rename → add.
///
/// The engine owns transform dispatch: it pre-checks existence, resolves
/// upsert semantics, and calls accessor primitives directly. Snapshot-compile
/// time validation guarantees that any primitive used here is wired on the
/// accessor — unwrapping the optional function pointers (`accessor.set.?`,
/// `accessor.delete.?`, `accessor.move.?`) is safe at runtime.
pub fn applyTransforms(
    transform: *const LogTransform,
    ctx: *anyopaque,
    accessor: *const LogAccessor,
    options: TransformOptions,
) TransformResult {
    var result = TransformResult{};

    // 1. Remove
    result.removes_attempted = transform.remove.items.len;
    for (transform.remove.items) |*rule| {
        if (applyRemove(rule, ctx, accessor)) {
            result.removes_applied += 1;
        }
    }

    // 2. Redact
    result.redacts_attempted = transform.redact.items.len;
    for (transform.redact.items, 0..) |*rule, idx| {
        const compiled: ?*const redact_mod.Compiled = blk: {
            if (idx >= options.compiled_redacts.len) break :blk null;
            const slot = &options.compiled_redacts[idx];
            break :blk if (slot.*) |*c| c else null;
        };
        if (applyRedact(rule, ctx, accessor, .{
            .compiled = compiled,
            .scratch = options.scratch,
        })) {
            result.redacts_applied += 1;
        }
    }

    // 3. Rename
    result.renames_attempted = transform.rename.items.len;
    for (transform.rename.items) |*rule| {
        if (applyRename(rule, ctx, accessor)) {
            result.renames_applied += 1;
        }
    }

    // 4. Add
    result.adds_attempted = transform.add.items.len;
    for (transform.add.items) |*rule| {
        if (applyAdd(rule, ctx, accessor)) {
            result.adds_applied += 1;
        }
    }

    return result;
}

/// Apply a single remove rule. Returns true if the field existed and was removed.
pub fn applyRemove(
    rule: *const LogRemove,
    ctx: *anyopaque,
    accessor: *const LogAccessor,
) bool {
    const field_ref = FieldRef.fromRemoveField(rule.field) orelse return false;
    return accessor.delete.?(ctx, field_ref);
}

/// Apply a single redact rule.
///
/// When `options.compiled` is null, replaces the entire field value with
/// `rule.replacement`. When non-null, runs the pre-compiled regex over the
/// textual representation returned by `accessor.value` and substitutes each
/// match using the pre-parsed replacement template. If the accessor returns
/// null (field missing or non-string), or the regex finds no match, the
/// operation is a no-op.
///
/// Returns true if the field was redacted.
pub fn applyRedact(
    rule: *const LogRedact,
    ctx: *anyopaque,
    accessor: *const LogAccessor,
    options: RedactOptions,
) bool {
    const field_ref = FieldRef.fromRedactField(rule.field) orelse return false;

    if (options.compiled) |c| {
        const allocator = options.scratch orelse return false;
        const value = accessor.value(ctx, field_ref) orelse return false;

        var out: std.ArrayListUnmanaged(u8) = .empty;
        // No deinit: `out.items` is handed to the accessor.set by reference
        // and must remain valid after this function returns. The caller's
        // `scratch` is documented as arena-lifetime; ownership of the bytes
        // effectively transfers to that arena.

        // Cast away const for replaceAll which mutates engine state internally.
        const mut: *redact_mod.Compiled = @constCast(c);
        const count = mut.replaceAll(value, &out, allocator) catch return false;
        if (count == 0) return false;

        accessor.set.?(ctx, field_ref, out.items);
        return true;
    }

    // Whole-value redact: only fires if the field exists.
    if (accessor.value(ctx, field_ref) == null) return false;

    accessor.set.?(ctx, field_ref, rule.replacement);
    return true;
}

/// Apply a single rename rule. Moves the value from `rule.from` to a new
/// attribute keyed by `rule.to` in the same field family. Handles upsert
/// semantics engine-side: with `upsert=false`, no-ops when target exists;
/// with `upsert=true`, deletes target first.
///
/// Returns true if the rename actually moved a value.
pub fn applyRename(
    rule: *const LogRename,
    ctx: *anyopaque,
    accessor: *const LogAccessor,
) bool {
    const from_ref = FieldRef.fromRenameFrom(rule.from) orelse return false;

    // Source must exist (presence check honors non-string values).
    if (!accessor.callExists(ctx, from_ref)) return false;

    // Construct the target FieldRef in the same family as `from`, keyed by
    // `rule.to`. Only attribute families are renameable; log_field sources
    // are rejected by the spec.
    const to_path = [_][]const u8{rule.to};
    const to_attr = AttributePath{ .path = .{ .items = @constCast(&to_path), .capacity = 1 } };
    const to_ref: FieldRef = switch (from_ref) {
        .log_field => return false,
        .log_attribute => .{ .log_attribute = to_attr },
        .resource_attribute => .{ .resource_attribute = to_attr },
        .scope_attribute => .{ .scope_attribute = to_attr },
    };

    const target_exists = accessor.callExists(ctx, to_ref);
    if (target_exists) {
        if (!rule.upsert) return false;
        _ = accessor.delete.?(ctx, to_ref);
    }

    accessor.move.?(ctx, from_ref, rule.to);
    return true;
}

/// Apply a single add rule. Inserts a field with the given value. If
/// `upsert=false`, no-ops when the target already exists.
///
/// Returns true if the field was added/updated.
pub fn applyAdd(
    rule: *const LogAdd,
    ctx: *anyopaque,
    accessor: *const LogAccessor,
) bool {
    const field_ref = FieldRef.fromAddField(rule.field) orelse return false;

    const exists = accessor.callExists(ctx, field_ref);
    if (!rule.upsert and exists) return false;

    accessor.set.?(ctx, field_ref, rule.value);
    return true;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// Test context that holds a simple key-value store
const TestContext = struct {
    fields: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) TestContext {
        return .{
            .fields = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    fn deinit(self: *TestContext) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.fields.deinit();
    }

    fn set(self: *TestContext, key: []const u8, value: []const u8) !void {
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        const gop = try self.fields.getOrPut(key);
        if (gop.found_existing) {
            // Key already exists - just update the value
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = value_copy;
        } else {
            // New key - need to dupe it
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = value_copy;
        }
    }

    /// Get first path segment for flat test storage
    fn getFirstPathSegment(path: []const []const u8) ?[]const u8 {
        if (path.len == 0) return null;
        return path[0];
    }

    fn fieldKey(field: FieldRef) ?[]const u8 {
        return switch (field) {
            .log_field => |f| @tagName(f),
            .log_attribute => |p| getFirstPathSegment(p.path.items),
            .resource_attribute => |p| getFirstPathSegment(p.path.items),
            .scope_attribute => |p| getFirstPathSegment(p.path.items),
        };
    }

    fn accessorValue(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
        const self: *const TestContext = @ptrCast(@alignCast(ctx));
        const key = fieldKey(field) orelse return null;
        return self.fields.get(key);
    }

    fn accessorSet(ctx: *anyopaque, field: FieldRef, value: []const u8) void {
        const self: *TestContext = @ptrCast(@alignCast(ctx));
        const key = fieldKey(field) orelse return;
        self.set(key, value) catch {};
    }

    fn accessorDelete(ctx: *anyopaque, field: FieldRef) bool {
        const self: *TestContext = @ptrCast(@alignCast(ctx));
        const key = fieldKey(field) orelse return false;
        if (self.fields.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return true;
        }
        return false;
    }

    fn accessorMove(ctx: *anyopaque, from: FieldRef, to: []const u8) void {
        const self: *TestContext = @ptrCast(@alignCast(ctx));
        const from_key = fieldKey(from) orelse return;
        const removed = self.fields.fetchRemove(from_key) orelse return;
        defer self.allocator.free(removed.key);
        self.set(to, removed.value) catch {
            // restore on failure
            self.fields.put(removed.key, removed.value) catch {};
            return;
        };
        self.allocator.free(removed.value);
    }

    const accessor: LogAccessor = .{
        .value = accessorValue,
        .set = accessorSet,
        .delete = accessorDelete,
        .move = accessorMove,
    };
};

/// Helper to create AttributePath for tests
fn testAttrPath(comptime key: []const u8) proto.policy.AttributePath {
    return .{ .path = .{ .items = @constCast(&[_][]const u8{key}), .capacity = 1 } };
}

test "applyRemove: removes existing field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("service", "payment-api");

    var rule = LogRemove{
        .field = .{ .log_attribute = testAttrPath("service") },
    };

    const result = applyRemove(&rule, @ptrCast(&ctx), &TestContext.accessor);
    try testing.expect(result);
    try testing.expect(ctx.fields.get("service") == null);
}

test "applyRemove: returns false for non-existent field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogRemove{
        .field = .{ .log_attribute = testAttrPath("nonexistent") },
    };

    const result = applyRemove(&rule, @ptrCast(&ctx), &TestContext.accessor);
    try testing.expect(!result);
}

test "TestContext: set and update" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("key", "value1");
    try testing.expectEqualStrings("value1", ctx.fields.get("key").?);

    try ctx.set("key", "value2");
    try testing.expectEqualStrings("value2", ctx.fields.get("key").?);
}

test "applyRedact: replaces field value" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("password", "secret123");
    try testing.expectEqualStrings("secret123", ctx.fields.get("password").?);

    var rule = LogRedact{
        .field = .{ .log_attribute = testAttrPath("password") },
        .replacement = "[REDACTED]",
    };

    const result = applyRedact(&rule, @ptrCast(&ctx), &TestContext.accessor, .{});
    try testing.expect(result);
    try testing.expectEqualStrings("[REDACTED]", ctx.fields.get("password").?);
}

test "applyRedact: returns false for non-existent field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogRedact{
        .field = .{ .log_attribute = testAttrPath("nonexistent") },
        .replacement = "[REDACTED]",
    };

    const result = applyRedact(&rule, @ptrCast(&ctx), &TestContext.accessor, .{});
    try testing.expect(!result);
}

test "applyRedact: regex targeted replacement" {
    const allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("body", "?user=alice&password=secret123&session=xyz");

    var rule = LogRedact{
        .field = .{ .log_attribute = testAttrPath("body") },
        .replacement = "$1[REDACTED]$2",
        .regex = "([?&]password=)[^&\\s]+(&session=)",
    };

    var compiled = try redact_mod.Compiled.init(allocator, rule.regex.?, rule.replacement);
    defer compiled.deinit();

    const result = applyRedact(&rule, @ptrCast(&ctx), &TestContext.accessor, .{
        .compiled = &compiled,
        .scratch = arena.allocator(),
    });
    try testing.expect(result);
    try testing.expectEqualStrings("?user=alice&password=[REDACTED]&session=xyz", ctx.fields.get("body").?);
}

test "applyRedact: regex no-match is a no-op" {
    const allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("body", "no secrets here");

    var rule = LogRedact{
        .field = .{ .log_attribute = testAttrPath("body") },
        .replacement = "X",
        .regex = "password=\\S+",
    };

    var compiled = try redact_mod.Compiled.init(allocator, rule.regex.?, rule.replacement);
    defer compiled.deinit();

    const result = applyRedact(&rule, @ptrCast(&ctx), &TestContext.accessor, .{
        .compiled = &compiled,
        .scratch = arena.allocator(),
    });
    try testing.expect(!result);
    try testing.expectEqualStrings("no secrets here", ctx.fields.get("body").?);
}

test "applyRedact: regex output outlives applyRedact return" {
    // Regression: applyRedact used to free its scratch ArrayList via `defer`
    // before returning, while passing `out.items` by reference to the mutator.
    // Consumers that store the slice by reference (rather than duping it) saw
    // the bytes get poisoned/freed the instant applyRedact returned. This test
    // uses a mutator that stores by reference and inspects the bytes after the
    // call.
    const allocator = testing.allocator;

    const ByRefCtx = struct {
        stored: ?[]const u8 = null,
        fn valueFn(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
            _ = field;
            const self: *const @This() = @ptrCast(@alignCast(ctx));
            return self.stored;
        }
        fn setFn(ctx: *anyopaque, field: FieldRef, value: []const u8) void {
            _ = field;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.stored = value;
        }
        fn deleteFn(_: *anyopaque, _: FieldRef) bool {
            return false;
        }
        fn moveFn(_: *anyopaque, _: FieldRef, _: []const u8) void {}
        const accessor: LogAccessor = .{
            .value = valueFn,
            .set = setFn,
            .delete = deleteFn,
            .move = moveFn,
        };
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var ctx = ByRefCtx{ .stored = "?password=secret123&session=xyz" };

    var rule = LogRedact{
        .field = .{ .log_attribute = testAttrPath("body") },
        .replacement = "$1[REDACTED]$2",
        .regex = "([?&]password=)[^&\\s]+(&session=)",
    };

    var compiled = try redact_mod.Compiled.init(allocator, rule.regex.?, rule.replacement);
    defer compiled.deinit();

    const result = applyRedact(&rule, @ptrCast(&ctx), &ByRefCtx.accessor, .{
        .compiled = &compiled,
        .scratch = arena.allocator(),
    });
    try testing.expect(result);

    // After return, the slice handed to the mutator must still hold valid bytes.
    // Pre-fix this assertion saw 0xAA-poisoned memory from the freed ArrayList.
    try testing.expectEqualStrings("?password=[REDACTED]&session=xyz", ctx.stored.?);
}

test "applyRedact: regex on missing field is a no-op" {
    const allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogRedact{
        .field = .{ .log_attribute = testAttrPath("missing") },
        .replacement = "X",
        .regex = "\\d+",
    };

    var compiled = try redact_mod.Compiled.init(allocator, rule.regex.?, rule.replacement);
    defer compiled.deinit();

    const result = applyRedact(&rule, @ptrCast(&ctx), &TestContext.accessor, .{
        .compiled = &compiled,
        .scratch = arena.allocator(),
    });
    try testing.expect(!result);
}

test "applyRename: renames existing field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("old_name", "value123");

    var rule = LogRename{
        .from = .{ .from_log_attribute = testAttrPath("old_name") },
        .to = "new_name",
        .upsert = true,
    };

    const result = applyRename(&rule, @ptrCast(&ctx), &TestContext.accessor);
    try testing.expect(result);
    try testing.expect(ctx.fields.get("old_name") == null);
    try testing.expectEqualStrings("value123", ctx.fields.get("new_name").?);
}

test "applyRename: returns false for non-existent source" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogRename{
        .from = .{ .from_log_attribute = testAttrPath("nonexistent") },
        .to = "new_name",
        .upsert = true,
    };

    const result = applyRename(&rule, @ptrCast(&ctx), &TestContext.accessor);
    try testing.expect(!result);
}

test "applyAdd: adds new field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogAdd{
        .field = .{ .log_attribute = testAttrPath("new_field") },
        .value = "new_value",
        .upsert = true,
    };

    const result = applyAdd(&rule, @ptrCast(&ctx), &TestContext.accessor);
    try testing.expect(result);
    try testing.expectEqualStrings("new_value", ctx.fields.get("new_field").?);
}

test "applyAdd: upsert=false skips existing field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("existing", "original");

    var rule = LogAdd{
        .field = .{ .log_attribute = testAttrPath("existing") },
        .value = "new_value",
        .upsert = false,
    };

    const result = applyAdd(&rule, @ptrCast(&ctx), &TestContext.accessor);
    try testing.expect(!result);
    try testing.expectEqualStrings("original", ctx.fields.get("existing").?);
}

test "applyAdd: upsert=false adds non-existent field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    var rule = LogAdd{
        .field = .{ .log_attribute = testAttrPath("new_field") },
        .value = "hello",
        .upsert = false,
    };

    const result = applyAdd(&rule, @ptrCast(&ctx), &TestContext.accessor);
    try testing.expect(result);
    try testing.expectEqualStrings("hello", ctx.fields.get("new_field").?);
}

test "applyAdd: upsert=true overwrites existing field" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("existing", "original");

    var rule = LogAdd{
        .field = .{ .log_attribute = testAttrPath("existing") },
        .value = "new_value",
        .upsert = true,
    };

    const result = applyAdd(&rule, @ptrCast(&ctx), &TestContext.accessor);
    try testing.expect(result);
    try testing.expectEqualStrings("new_value", ctx.fields.get("existing").?);
}

test "applyTransforms: applies in correct order" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    // Setup initial state
    try ctx.set("to_remove", "value1");
    try ctx.set("to_redact", "sensitive");
    try ctx.set("to_rename", "rename_me");

    // Build transform with all operation types
    var transform = LogTransform{};

    // Remove
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("to_remove") },
    });

    // Redact
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("to_redact") },
        .replacement = "[HIDDEN]",
    });

    // Rename
    try transform.rename.append(allocator, .{
        .from = .{ .from_log_attribute = testAttrPath("to_rename") },
        .to = "renamed",
        .upsert = true,
    });

    // Add
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("added") },
        .value = "new_value",
        .upsert = true,
    });

    defer transform.remove.deinit(allocator);
    defer transform.redact.deinit(allocator);
    defer transform.rename.deinit(allocator);
    defer transform.add.deinit(allocator);

    const result = applyTransforms(
        &transform,
        @ptrCast(&ctx),
        &TestContext.accessor,
        .{},
    );

    // Verify attempted counts
    try testing.expectEqual(@as(usize, 1), result.removes_attempted);
    try testing.expectEqual(@as(usize, 1), result.redacts_attempted);
    try testing.expectEqual(@as(usize, 1), result.renames_attempted);
    try testing.expectEqual(@as(usize, 1), result.adds_attempted);
    try testing.expectEqual(@as(usize, 4), result.totalAttempted());

    // Verify applied counts
    try testing.expectEqual(@as(usize, 1), result.removes_applied);
    try testing.expectEqual(@as(usize, 1), result.redacts_applied);
    try testing.expectEqual(@as(usize, 1), result.renames_applied);
    try testing.expectEqual(@as(usize, 1), result.adds_applied);
    try testing.expectEqual(@as(usize, 4), result.totalApplied());

    // Verify final state
    try testing.expect(ctx.fields.get("to_remove") == null);
    try testing.expectEqualStrings("[HIDDEN]", ctx.fields.get("to_redact").?);
    try testing.expect(ctx.fields.get("to_rename") == null);
    try testing.expectEqualStrings("rename_me", ctx.fields.get("renamed").?);
    try testing.expectEqualStrings("new_value", ctx.fields.get("added").?);
}

test "applyTransforms: counts attempted vs applied when some operations fail" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    // Setup: only some fields exist
    try ctx.set("exists1", "value1");
    try ctx.set("exists2", "value2");
    try ctx.set("existing_field", "original");

    var transform = LogTransform{};

    // 3 removes: 2 exist, 1 doesn't
    try transform.remove.append(allocator, .{ .field = .{ .log_attribute = testAttrPath("exists1") } });
    try transform.remove.append(allocator, .{ .field = .{ .log_attribute = testAttrPath("missing1") } });
    try transform.remove.append(allocator, .{ .field = .{ .log_attribute = testAttrPath("exists2") } });

    // 2 redacts: 1 exists, 1 doesn't
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("missing2") },
        .replacement = "[REDACTED]",
    });
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("existing_field") },
        .replacement = "[REDACTED]",
    });

    // 2 renames: 1 source exists, 1 doesn't
    try transform.rename.append(allocator, .{
        .from = .{ .from_log_attribute = testAttrPath("existing_field") },
        .to = "renamed_field",
        .upsert = true,
    });
    try transform.rename.append(allocator, .{
        .from = .{ .from_log_attribute = testAttrPath("missing3") },
        .to = "wont_exist",
        .upsert = true,
    });

    // 3 adds: 2 with upsert=true succeed, 1 with upsert=false on existing field fails
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("new1") },
        .value = "added1",
        .upsert = true,
    });
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("renamed_field") }, // Will exist after rename
        .value = "should_not_overwrite",
        .upsert = false, // Won't overwrite existing
    });
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("new2") },
        .value = "added2",
        .upsert = true,
    });

    defer transform.remove.deinit(allocator);
    defer transform.redact.deinit(allocator);
    defer transform.rename.deinit(allocator);
    defer transform.add.deinit(allocator);

    const result = applyTransforms(
        &transform,
        @ptrCast(&ctx),
        &TestContext.accessor,
        .{},
    );

    // Verify attempted counts (total rules defined)
    try testing.expectEqual(@as(usize, 3), result.removes_attempted);
    try testing.expectEqual(@as(usize, 2), result.redacts_attempted);
    try testing.expectEqual(@as(usize, 2), result.renames_attempted);
    try testing.expectEqual(@as(usize, 3), result.adds_attempted);

    // Verify applied counts (only successful operations)
    try testing.expectEqual(@as(usize, 2), result.removes_applied); // exists1, exists2
    try testing.expectEqual(@as(usize, 1), result.redacts_applied); // existing_field
    try testing.expectEqual(@as(usize, 1), result.renames_applied); // existing_field -> renamed_field
    try testing.expectEqual(@as(usize, 2), result.adds_applied); // new1, new2 (not renamed_field due to upsert=false)

    // Verify misses can be computed
    try testing.expectEqual(@as(usize, 1), result.removes_attempted - result.removes_applied);
    try testing.expectEqual(@as(usize, 1), result.redacts_attempted - result.redacts_applied);
    try testing.expectEqual(@as(usize, 1), result.renames_attempted - result.renames_applied);
    try testing.expectEqual(@as(usize, 1), result.adds_attempted - result.adds_applied);
}

test "applyTransforms: empty transform returns zero counts" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    try ctx.set("field", "value");

    const transform = LogTransform{};

    const result = applyTransforms(
        &transform,
        @ptrCast(&ctx),
        &TestContext.accessor,
        .{},
    );

    try testing.expectEqual(@as(usize, 0), result.removes_attempted);
    try testing.expectEqual(@as(usize, 0), result.redacts_attempted);
    try testing.expectEqual(@as(usize, 0), result.renames_attempted);
    try testing.expectEqual(@as(usize, 0), result.adds_attempted);
    try testing.expectEqual(@as(usize, 0), result.totalAttempted());
    try testing.expectEqual(@as(usize, 0), result.totalApplied());

    // Field should be unchanged
    try testing.expectEqualStrings("value", ctx.fields.get("field").?);
}

test "applyTransforms: all operations fail returns zero applied" {
    const allocator = testing.allocator;
    var ctx = TestContext.init(allocator);
    defer ctx.deinit();

    // Don't set any fields - all operations will fail

    var transform = LogTransform{};

    // Remove non-existent field
    try transform.remove.append(allocator, .{ .field = .{ .log_attribute = testAttrPath("missing") } });

    // Redact non-existent field
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("missing") },
        .replacement = "[REDACTED]",
    });

    // Rename non-existent field
    try transform.rename.append(allocator, .{
        .from = .{ .from_log_attribute = testAttrPath("missing") },
        .to = "new_name",
        .upsert = true,
    });

    // Add with upsert=false to non-existent field (this actually succeeds - it's an insert)
    // So let's test add with upsert=false when field exists
    try ctx.set("blocker", "blocks_add");
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = testAttrPath("blocker") },
        .value = "wont_work",
        .upsert = false,
    });

    defer transform.remove.deinit(allocator);
    defer transform.redact.deinit(allocator);
    defer transform.rename.deinit(allocator);
    defer transform.add.deinit(allocator);

    const result = applyTransforms(
        &transform,
        &ctx,
        &TestContext.accessor,
        .{},
    );

    // All attempted
    try testing.expectEqual(@as(usize, 1), result.removes_attempted);
    try testing.expectEqual(@as(usize, 1), result.redacts_attempted);
    try testing.expectEqual(@as(usize, 1), result.renames_attempted);
    try testing.expectEqual(@as(usize, 1), result.adds_attempted);

    // None applied
    try testing.expectEqual(@as(usize, 0), result.removes_applied);
    try testing.expectEqual(@as(usize, 0), result.redacts_applied);
    try testing.expectEqual(@as(usize, 0), result.renames_applied);
    try testing.expectEqual(@as(usize, 0), result.adds_applied);
    try testing.expectEqual(@as(usize, 0), result.totalApplied());

    // Blocker field unchanged
    try testing.expectEqualStrings("blocks_add", ctx.fields.get("blocker").?);
}
