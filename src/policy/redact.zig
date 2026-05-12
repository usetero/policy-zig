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
    gpa: std.mem.Allocator,

    pub fn compile(gpa: std.mem.Allocator, pattern: []const u8) CompileError!Pattern {
        const re = Regex.compile(gpa, pattern, .{}) catch return error.InvalidRegex;
        return .{ .re = re, .gpa = gpa };
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

        var i: usize = 0;
        var lit_start: usize = 0;

        while (i < template.len) {
            if (template[i] != '$') {
                i += 1;
                continue;
            }

            // Flush any pending literal up to (but not including) the '$'
            if (i > lit_start) {
                try appendLiteral(gpa, &segs, template[lit_start..i]);
            }

            // We're sitting on '$'. Look ahead.
            const next = i + 1;
            if (next >= template.len) {
                // Trailing '$' with nothing after: keep as literal '$'
                try appendLiteral(gpa, &segs, "$");
                i = template.len;
                lit_start = i;
                break;
            }

            const c = template[next];
            if (c == '$') {
                try appendLiteral(gpa, &segs, "$");
                i = next + 1;
                lit_start = i;
                continue;
            }

            if (c == '{') {
                // ${N} or ${name}
                const close = std.mem.indexOfScalarPos(u8, template, next + 1, '}') orelse {
                    // No closing brace — treat the whole thing as literal
                    try appendLiteral(gpa, &segs, template[i .. next + 1]);
                    i = next + 1;
                    lit_start = i;
                    continue;
                };
                const inner = template[next + 1 .. close];
                if (inner.len == 0) {
                    // ${} — treat as literal
                    try appendLiteral(gpa, &segs, template[i .. close + 1]);
                } else if (isAllDigits(inner)) {
                    const idx = parseGroupIndex(inner) orelse {
                        // out of range numeric — leave literal
                        try appendLiteral(gpa, &segs, template[i .. close + 1]);
                        i = close + 1;
                        lit_start = i;
                        continue;
                    };
                    try segs.append(gpa, .{ .numbered = idx });
                } else {
                    const name_copy = try gpa.dupe(u8, inner);
                    try segs.append(gpa, .{ .named = name_copy });
                }
                i = close + 1;
                lit_start = i;
                continue;
            }

            if (std.ascii.isDigit(c)) {
                // $N or $NN (greedy, up to two digits)
                var end = next + 1;
                if (end < template.len and std.ascii.isDigit(template[end])) {
                    end += 1;
                }
                const idx = parseGroupIndex(template[next..end]) orelse {
                    try appendLiteral(gpa, &segs, template[i..end]);
                    i = end;
                    lit_start = i;
                    continue;
                };
                try segs.append(gpa, .{ .numbered = idx });
                i = end;
                lit_start = i;
                continue;
            }

            // Unrecognized escape: leave the `$` and continue scanning from `next`
            try appendLiteral(gpa, &segs, "$");
            i = next;
            lit_start = i;
        }

        // Flush trailing literal
        if (lit_start < template.len) {
            try appendLiteral(gpa, &segs, template[lit_start..]);
        }

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

fn appendLiteral(
    gpa: std.mem.Allocator,
    segs: *std.ArrayListUnmanaged(Segment),
    bytes: []const u8,
) !void {
    // Merge with the previous literal if possible to keep the segment list small.
    if (segs.items.len > 0) {
        const last = &segs.items[segs.items.len - 1];
        if (last.* == .literal) {
            const joined = try std.mem.concat(gpa, u8, &.{ last.literal, bytes });
            gpa.free(last.literal);
            last.* = .{ .literal = joined };
            return;
        }
    }
    const copy = try gpa.dupe(u8, bytes);
    try segs.append(gpa, .{ .literal = copy });
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

pub const Compiled = struct {
    pattern: Pattern,
    template: Template,

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
    pub fn replaceAll(
        self: *Compiled,
        haystack: []const u8,
        out: *std.ArrayListUnmanaged(u8),
        gpa: std.mem.Allocator,
    ) !usize {
        var cursor: usize = 0;
        var count: usize = 0;
        var it = self.pattern.re.findAllCaptures(haystack);
        while (it.next()) |caps| {
            const span = caps.span();
            try out.appendSlice(gpa, haystack[cursor..span.start]);
            try self.template.expand(haystack, caps, out, gpa);
            cursor = span.end;
            count += 1;
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
