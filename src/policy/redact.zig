//! Redact regex + replacement template support.
//!
//! Wraps the third-party `regex` package (RE2-family Pike VM) and parses the
//! replacement-template syntax defined by tero.policy.v1.LogRedact.regex:
//!
//!   $0        full match
//!   $1..$99   numbered group
//!   ${N}      numbered group (braced)
//!   ${name}   named group
//!   $$        literal '$'
//!
//! Missing groups expand to the empty string. Unrecognized escapes after `$`
//! are left literal.

const std = @import("std");
const Regex = @import("regex");

// =============================================================================
// Pattern — thin wrapper around the third-party regex engine
// =============================================================================

pub const CompileError = error{InvalidRegex} || std.mem.Allocator.Error;

pub const Pattern = struct {
    re: Regex,

    pub fn compile(gpa: std.mem.Allocator, pattern: []const u8) CompileError!Pattern {
        const re = Regex.compile(gpa, pattern, .{}) catch return error.InvalidRegex;
        return .{ .re = re };
    }

    pub fn deinit(self: *Pattern) void {
        self.re.deinit();
    }
};

// =============================================================================
// Template — parsed replacement template
// =============================================================================

pub const Segment = union(enum) {
    literal: []const u8,
    numbered: u8,
    named: []const u8,
};

pub const Template = struct {
    segments: []Segment,
    gpa: std.mem.Allocator,

    pub fn parse(gpa: std.mem.Allocator, template: []const u8) !Template {
        var segs: std.ArrayListUnmanaged(Segment) = .empty;
        errdefer freeSegments(gpa, segs.items);
        errdefer segs.deinit(gpa);

        // Accumulator for the in-progress literal segment. Bytes go in here
        // until we hit a non-literal boundary (numbered/named group), at
        // which point we flush as a single owned segment. This avoids the
        // O(n²) cost of concat-merging adjacent literals after every byte.
        var lit_buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer lit_buf.deinit(gpa);

        var i: usize = 0;
        while (i < template.len) {
            if (template[i] != '$') {
                try lit_buf.append(gpa, template[i]);
                i += 1;
                continue;
            }

            // We're sitting on '$'. Look ahead.
            const next = i + 1;
            if (next >= template.len) {
                // Trailing '$' with nothing after: keep as literal '$'
                try lit_buf.append(gpa, '$');
                break;
            }

            const c = template[next];
            if (c == '$') {
                try lit_buf.append(gpa, '$');
                i = next + 1;
                continue;
            }

            if (c == '{') {
                // ${N} or ${name}
                const close = std.mem.indexOfScalarPos(u8, template, next + 1, '}') orelse {
                    // No closing brace — treat the whole thing as literal
                    try lit_buf.appendSlice(gpa, template[i .. next + 1]);
                    i = next + 1;
                    continue;
                };
                const inner = template[next + 1 .. close];
                if (inner.len == 0) {
                    // ${} — treat as literal
                    try lit_buf.appendSlice(gpa, template[i .. close + 1]);
                } else if (isAllDigits(inner)) {
                    if (parseGroupIndex(inner)) |idx| {
                        try flushLiteral(gpa, &segs, &lit_buf);
                        try segs.append(gpa, .{ .numbered = idx });
                    } else {
                        // out of range numeric — leave literal
                        try lit_buf.appendSlice(gpa, template[i .. close + 1]);
                    }
                } else {
                    try flushLiteral(gpa, &segs, &lit_buf);
                    const name_copy = try gpa.dupe(u8, inner);
                    errdefer gpa.free(name_copy);
                    try segs.append(gpa, .{ .named = name_copy });
                }
                i = close + 1;
                continue;
            }

            if (std.ascii.isDigit(c)) {
                // $N or $NN (greedy, up to two digits)
                var end = next + 1;
                if (end < template.len and std.ascii.isDigit(template[end])) {
                    end += 1;
                }
                if (parseGroupIndex(template[next..end])) |idx| {
                    try flushLiteral(gpa, &segs, &lit_buf);
                    try segs.append(gpa, .{ .numbered = idx });
                } else {
                    try lit_buf.appendSlice(gpa, template[i..end]);
                }
                i = end;
                continue;
            }

            // Unrecognized escape: keep the `$` literal and resume scanning
            // at `next` so the following byte gets normal treatment.
            try lit_buf.append(gpa, '$');
            i = next;
        }

        try flushLiteral(gpa, &segs, &lit_buf);
        lit_buf.deinit(gpa);

        const owned = try segs.toOwnedSlice(gpa);
        return .{ .segments = owned, .gpa = gpa };
    }

    pub fn deinit(self: *Template) void {
        freeSegments(self.gpa, self.segments);
        self.gpa.free(self.segments);
    }

    /// Expand the template into `out` using `captures` from a single match in `haystack`.
    pub fn expand(
        self: Template,
        haystack: []const u8,
        captures: Regex.Captures,
        out: *std.ArrayListUnmanaged(u8),
        gpa: std.mem.Allocator,
    ) !void {
        for (self.segments) |seg| {
            switch (seg) {
                .literal => |bytes| try out.appendSlice(gpa, bytes),
                .numbered => |idx| {
                    if (captures.get(idx)) |m| {
                        try out.appendSlice(gpa, m.bytes(haystack));
                    }
                },
                .named => |n| {
                    if (captures.name(n)) |m| {
                        try out.appendSlice(gpa, m.bytes(haystack));
                    }
                },
            }
        }
    }
};

/// Move the bytes accumulated in `buf` into a fresh `.literal` segment.
/// Resets `buf` to empty afterwards. No-ops when `buf` is empty.
fn flushLiteral(
    gpa: std.mem.Allocator,
    segs: *std.ArrayListUnmanaged(Segment),
    buf: *std.ArrayListUnmanaged(u8),
) !void {
    if (buf.items.len == 0) return;
    const owned = try buf.toOwnedSlice(gpa);
    errdefer gpa.free(owned);
    try segs.append(gpa, .{ .literal = owned });
}

fn freeSegments(gpa: std.mem.Allocator, segs: []Segment) void {
    for (segs) |seg| {
        switch (seg) {
            .literal => |b| gpa.free(b),
            .named => |n| gpa.free(n),
            .numbered => {},
        }
    }
}

fn isAllDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |b| if (!std.ascii.isDigit(b)) return false;
    return true;
}

fn parseGroupIndex(s: []const u8) ?u8 {
    const n = std.fmt.parseInt(u16, s, 10) catch return null;
    if (n > 99) return null;
    return @intCast(n);
}

// =============================================================================
// Compiled — paired pattern + template
// =============================================================================

/// `Compiled` holds a regex `Pattern` (mutable engine state internal to the
/// third-party `regex` package) and the parsed replacement template.
///
/// ## Thread safety
///
/// The underlying Pike VM mutates per-iteration state on the regex `Engine`,
/// so `replaceAll` is **not safe to call concurrently** on the same
/// `Compiled` without external synchronization. `replaceAll` therefore takes
/// its own mutex; multiple threads sharing a `Compiled` will serialize on the
/// lock while inside `replaceAll`. The lock is uncontended in the common
/// case (one evaluator thread per record), so the cost is ~20ns per call.
///
/// If you ever need higher parallelism on a single rule, build one
/// `Compiled` per evaluator thread rather than sharing.
///
/// ## Output lifetime
///
/// `replaceAll` appends to `out` using the caller-provided allocator. The
/// bytes are **not** freed by `Compiled` — ownership transfers to the
/// allocator. Use an arena that you reset at a record-lifetime boundary.
pub const Compiled = struct {
    pattern: Pattern,
    template: Template,
    /// Serializes access to the regex engine's per-iteration state.
    /// See the struct docstring for the threading model.
    mutex: std.Thread.Mutex = .{},

    pub fn init(
        gpa: std.mem.Allocator,
        regex_str: []const u8,
        template_str: []const u8,
    ) !Compiled {
        var pat = try Pattern.compile(gpa, regex_str);
        errdefer pat.deinit();
        const tpl = try Template.parse(gpa, template_str);
        return .{ .pattern = pat, .template = tpl };
    }

    pub fn deinit(self: *Compiled) void {
        self.pattern.deinit();
        self.template.deinit();
    }

    /// Replace all non-overlapping matches of `pattern` in `haystack` with the
    /// template-expanded replacement. Appends the result to `out`. Returns the
    /// number of matches replaced. If 0, `out` is left unchanged.
    ///
    /// Zero-width matches advance the cursor by one byte to guarantee
    /// termination (otherwise patterns like `^` would loop forever).
    ///
    /// See `Compiled`'s docstring for thread-safety and output-lifetime notes.
    pub fn replaceAll(
        self: *Compiled,
        haystack: []const u8,
        out: *std.ArrayListUnmanaged(u8),
        gpa: std.mem.Allocator,
    ) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var cursor: usize = 0;
        var count: usize = 0;
        var it = self.pattern.re.findAllCaptures(haystack);
        while (it.next()) |caps| {
            const span = caps.span();
            // Defensive: regex engines (correctly) return the leftmost match
            // at-or-after the previous match's end. If the engine ever yields
            // a match that starts before our cursor, we'd splice in the
            // wrong slice; skip it.
            if (span.start < cursor) continue;

            try out.appendSlice(gpa, haystack[cursor..span.start]);
            try self.template.expand(haystack, caps, out, gpa);
            count += 1;

            if (span.end > cursor) {
                cursor = span.end;
            } else {
                // Zero-width match: emit one byte literally and advance,
                // otherwise we loop forever on patterns like `^`, `\b`,
                // or pure lookaheads.
                if (span.start >= haystack.len) break;
                try out.append(gpa, haystack[span.start]);
                cursor = span.start + 1;
            }
        }
        if (count > 0) {
            try out.appendSlice(gpa, haystack[cursor..]);
        }
        return count;
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

fn templateExpectSingle(template_str: []const u8, regex_str: []const u8, haystack: []const u8, expected: []const u8) !void {
    var compiled = try Compiled.init(testing.allocator, regex_str, template_str);
    defer compiled.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);

    _ = try compiled.replaceAll(haystack, &out, testing.allocator);
    try testing.expectEqualStrings(expected, out.items);
}

test "Template: literal-only template" {
    var tpl = try Template.parse(testing.allocator, "hello world");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 1), tpl.segments.len);
    try testing.expect(tpl.segments[0] == .literal);
    try testing.expectEqualStrings("hello world", tpl.segments[0].literal);
}

test "Template: $$ becomes literal dollar" {
    var tpl = try Template.parse(testing.allocator, "price=$$5");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 1), tpl.segments.len);
    try testing.expectEqualStrings("price=$5", tpl.segments[0].literal);
}

test "Template: $0 references full match" {
    var tpl = try Template.parse(testing.allocator, "[$0]");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 3), tpl.segments.len);
    try testing.expectEqualStrings("[", tpl.segments[0].literal);
    try testing.expectEqual(@as(u8, 0), tpl.segments[1].numbered);
    try testing.expectEqualStrings("]", tpl.segments[2].literal);
}

test "Template: $1 and $99 numbered groups" {
    var tpl = try Template.parse(testing.allocator, "$1-$99");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 3), tpl.segments.len);
    try testing.expectEqual(@as(u8, 1), tpl.segments[0].numbered);
    try testing.expectEqualStrings("-", tpl.segments[1].literal);
    try testing.expectEqual(@as(u8, 99), tpl.segments[2].numbered);
}

test "Template: ${10} braced numbered group" {
    var tpl = try Template.parse(testing.allocator, "${10}x");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 2), tpl.segments.len);
    try testing.expectEqual(@as(u8, 10), tpl.segments[0].numbered);
    try testing.expectEqualStrings("x", tpl.segments[1].literal);
}

test "Template: ${name} named group" {
    var tpl = try Template.parse(testing.allocator, "<${user}>");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 3), tpl.segments.len);
    try testing.expectEqualStrings("<", tpl.segments[0].literal);
    try testing.expectEqualStrings("user", tpl.segments[1].named);
    try testing.expectEqualStrings(">", tpl.segments[2].literal);
}

test "Template: unrecognized $-escape stays literal" {
    var tpl = try Template.parse(testing.allocator, "$x");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 1), tpl.segments.len);
    try testing.expectEqualStrings("$x", tpl.segments[0].literal);
}

test "Template: trailing $ stays literal" {
    var tpl = try Template.parse(testing.allocator, "trailing$");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 1), tpl.segments.len);
    try testing.expectEqualStrings("trailing$", tpl.segments[0].literal);
}

test "Template: unclosed ${ stays literal" {
    var tpl = try Template.parse(testing.allocator, "${unterminated");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 1), tpl.segments.len);
    try testing.expectEqualStrings("${unterminated", tpl.segments[0].literal);
}

test "Compiled.replaceAll: single match with $0" {
    try templateExpectSingle("[$0]", "\\d+", "abc 123 xyz", "abc [123] xyz");
}

test "Compiled.replaceAll: multiple non-overlapping matches" {
    try templateExpectSingle("X", "\\d+", "a1b22c333", "aXbXcX");
}

test "Compiled.replaceAll: no match leaves output empty" {
    var compiled = try Compiled.init(testing.allocator, "zzz", "X");
    defer compiled.deinit();
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);
    const count = try compiled.replaceAll("abc 123", &out, testing.allocator);
    try testing.expectEqual(@as(usize, 0), count);
    try testing.expectEqual(@as(usize, 0), out.items.len);
}

test "Compiled.replaceAll: capture group reference" {
    // Pattern matches bearer + token; preserve scheme, redact token
    try templateExpectSingle("$1[REDACTED]", "(?i)(bearer\\s+)\\S+", "Authorization: Bearer abc123", "Authorization: Bearer [REDACTED]");
}

test "Compiled.replaceAll: named capture reference" {
    try templateExpectSingle("user=${name}", "user=(?<name>\\w+)", "user=alice;x=1", "user=alice;x=1");
}

test "Compiled.replaceAll: missing group expands to empty" {
    // Pattern has one group; template references $2 which doesn't exist
    try templateExpectSingle("[$1$2]", "(\\d+)", "value=42", "value=[42]");
}

test "Compiled.replaceAll: query param redaction (real-world example)" {
    try templateExpectSingle(
        "$1[REDACTED]$2",
        "([?&]password=)[^&\\s]+(&session_id=)",
        "?user=alice&password=secret123&session_id=xyz",
        "?user=alice&password=[REDACTED]&session_id=xyz",
    );
}

test "Compiled.replaceAll: no capture groups, full-match replacement" {
    // Regex matches `password=secret123&` with no capture groups. Replacement
    // is a literal string that reconstructs the surrounding structure so the
    // rest of the body stays intact.
    try templateExpectSingle(
        "password=[REDACTED]&",
        "password=[0-9a-zA-Z]+&",
        "?user=alice&password=secret123&session=xyz",
        "?user=alice&password=[REDACTED]&session=xyz",
    );
}

test "Compiled.replaceAll: zero-width match terminates and advances byte-by-byte" {
    // `^` matches the start of the haystack — width zero. Without the cursor
    // advance, the loop would either spin forever or never emit the rest of
    // the input. Verify we terminate and the output is a single insertion
    // of the template at offset 0 followed by the verbatim haystack.
    var compiled = try Compiled.init(testing.allocator, "^", "[START]");
    defer compiled.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);

    const count = try compiled.replaceAll("abc", &out, testing.allocator);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("[START]abc", out.items);
}

test "Compiled.replaceAll: zero-width match on empty haystack" {
    var compiled = try Compiled.init(testing.allocator, "^", "X");
    defer compiled.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);

    // Should terminate cleanly. Whether we emit "X" or 0 matches is a
    // policy decision — we tolerate either outcome here.
    _ = try compiled.replaceAll("", &out, testing.allocator);
}

test "Compiled.replaceAll: concurrent callers serialize on the Mutex" {
    // Spawns N threads that hammer the same Compiled. Without the Mutex
    // this races the regex engine's per-iteration state and produces
    // corrupted output / panics under TSan. With the Mutex, all threads
    // see identical, correct output.
    const allocator = testing.allocator;
    var compiled = try Compiled.init(allocator, "[0-9]+", "X");
    defer compiled.deinit();

    const Worker = struct {
        compiled_ref: *Compiled,
        gpa: std.mem.Allocator,
        ok: *std.atomic.Value(u32),

        fn run(self: @This()) void {
            var i: usize = 0;
            while (i < 50) : (i += 1) {
                var arena = std.heap.ArenaAllocator.init(self.gpa);
                defer arena.deinit();
                var out: std.ArrayListUnmanaged(u8) = .empty;
                const count = self.compiled_ref.replaceAll(
                    "user=42 token=99 session=7",
                    &out,
                    arena.allocator(),
                ) catch return;
                if (count != 3) return;
                if (!std.mem.eql(u8, out.items, "user=X token=X session=X")) return;
            }
            _ = self.ok.fetchAdd(1, .monotonic);
        }
    };

    var ok = std.atomic.Value(u32).init(0);
    const thread_count: u32 = 4;
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{Worker{
            .compiled_ref = &compiled,
            .gpa = allocator,
            .ok = &ok,
        }});
    }
    for (threads) |t| t.join();
    try testing.expectEqual(thread_count, ok.load(.monotonic));
}

test "Template: ${100} stays literal (numeric group out of range)" {
    var tpl = try Template.parse(testing.allocator, "${100}x");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 1), tpl.segments.len);
    try testing.expect(tpl.segments[0] == .literal);
    try testing.expectEqualStrings("${100}x", tpl.segments[0].literal);
}

test "Template: $999 only consumes two digits (greedy cap)" {
    // $99 is the largest valid numbered group; the trailing '9' stays literal.
    var tpl = try Template.parse(testing.allocator, "$999");
    defer tpl.deinit();
    try testing.expectEqual(@as(usize, 2), tpl.segments.len);
    try testing.expectEqual(@as(u8, 99), tpl.segments[0].numbered);
    try testing.expectEqualStrings("9", tpl.segments[1].literal);
}

test "compileRedactRules: cleans up on partial failure" {
    // First rule compiles, second rule has an invalid regex — the helper
    // must free the first rule's compiled state on the error path.
    const proto = @import("proto");
    const allocator = testing.allocator;

    var transform = proto.policy.LogTransform{};
    defer transform.redact.deinit(allocator);

    try transform.redact.append(allocator, .{
        .replacement = "X",
        .regex = "\\d+",
    });
    try transform.redact.append(allocator, .{
        .replacement = "Y",
        // Unclosed group — guaranteed compile failure.
        .regex = "(",
    });

    const result = @import("./log_transform.zig").compileRedactRules(allocator, &transform);
    try testing.expectError(error.InvalidRegex, result);
    // No leaks: the testing allocator panics on undeinited allocations,
    // so reaching the end of the test proves the cleanup succeeded.
}
