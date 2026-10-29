//! Recursive-descent parser for BIND9 master files.
//!
//! Output is an AST (`ast.zig`); no names are resolved and no TTLs are
//! applied here.  $GENERATE is expanded into ordinary record nodes because it
//! is pure syntactic sugar, while $INCLUDE remains a node so that the
//! semantic analyser can control origin/TTL scope and file loading.

const std = @import("std");
const lexer = @import("lexer.zig");
const ast = @import("ast.zig");
const text = @import("../dns/text.zig");
const types = @import("../dns/types.zig");

pub const Error = error{
    ParseFailed,
    UnknownDirective,
    MissingToken,
    InvalidDirective,
    UnknownType,
    BadGenerateRange,
    BadGenerateSubstitution,
    TooManyGenerated,
    EmptyLine,
} || lexer.Error || std.mem.Allocator.Error;

pub const Parser = struct {
    allocator: std.mem.Allocator,
    lexer: lexer.Lexer,
    nodes: std.ArrayList(ast.Node) = .empty,
    err_line: u32 = 0,
    err_kind: ErrorKind = .none,
    saw_eof: bool = false,

    pub const ErrorKind = enum {
        none,
        lex,
        syntax,
        directive,
        generate,
        oom,
    };

    pub fn init(allocator: std.mem.Allocator, source: []const u8) Parser {
        return .{ .allocator = allocator, .lexer = lexer.Lexer.init(source) };
    }

    pub fn parse(allocator: std.mem.Allocator, source: []const u8, source_name: []const u8) Error!ast.Ast {
        var p = Parser.init(allocator, source);
        defer p.nodes.deinit(allocator);
        try p.parseAll();
        const name_copy = try allocator.dupe(u8, source_name);
        errdefer allocator.free(name_copy);
        return .{
            .nodes = try p.nodes.toOwnedSlice(allocator),
            .source_name = name_copy,
            .source = source,
        };
    }

    fn fail(p: *Parser, line: u32, kind: ErrorKind) Error {
        p.err_line = line;
        p.err_kind = kind;
        return error.ParseFailed;
    }

    fn parseAll(p: *Parser) Error!void {
        var line_tokens: std.ArrayList(lexer.Token) = .empty;
        defer line_tokens.deinit(p.allocator);
        while (!p.saw_eof) {
            line_tokens.clearRetainingCapacity();
            var first: ?lexer.Token = null;
            while (true) {
                const t = try p.lexer.next();
                if (t.kind == .eof) {
                    p.saw_eof = true;
                    break;
                }
                if (t.kind == .newline) {
                    if (first != null) break;
                    continue;
                }
                if (first == null) first = t;
                try line_tokens.append(p.allocator, t);
            }
            if (line_tokens.items.len == 0) continue;
            try p.parseLine(line_tokens.items);
        }
    }

    fn parseLine(p: *Parser, toks: []const lexer.Token) Error!void {
        if (toks.len == 0) return;
        const first = toks[0];
        if (first.kind == .word and first.text.len > 0 and first.text[0] == '$') {
            try p.parseDirective(toks);
            return;
        }
        var r = try p.parseRecord(toks);
        r.line = first.line;
        try p.nodes.append(p.allocator, .{ .record = r });
    }

    fn parseDirective(p: *Parser, toks: []const lexer.Token) Error!void {
        const d = toks[0].text;
        if (std.mem.eql(u8, d, "$ORIGIN")) {
            if (toks.len != 2) return p.fail(toks[0].line, .directive);
            try p.nodes.append(p.allocator, .{ .origin = .{
                .value = .{ .text = toks[1].text, .quoted = toks[1].kind == .quoted, .line = toks[1].line },
                .line = toks[0].line,
            } });
            return;
        }
        if (std.mem.eql(u8, d, "$TTL")) {
            if (toks.len != 2) return p.fail(toks[0].line, .directive);
            try p.nodes.append(p.allocator, .{ .ttl = .{
                .value = .{ .text = toks[1].text, .quoted = toks[1].kind == .quoted, .line = toks[1].line },
                .line = toks[0].line,
            } });
            return;
        }
        if (std.mem.eql(u8, d, "$INCLUDE")) {
            if (toks.len < 2 or toks.len > 3) return p.fail(toks[0].line, .directive);
            try p.nodes.append(p.allocator, .{ .include = .{
                .path = .{ .text = toks[1].text, .quoted = toks[1].kind == .quoted, .line = toks[1].line },
                .origin = if (toks.len == 3) .{ .text = toks[2].text, .quoted = toks[2].kind == .quoted, .line = toks[2].line } else null,
                .line = toks[0].line,
            } });
            return;
        }
        if (std.mem.eql(u8, d, "$GENERATE")) {
            try p.parseGenerate(toks);
            return;
        }
        return p.fail(toks[0].line, .directive);
    }

    fn parseRecord(p: *Parser, toks: []const lexer.Token) Error!ast.Record {
        var i: usize = 0;
        var owner: ?text.Token = null;
        if (!toks[0].leading_ws) {
            owner = tokenOf(toks[0]);
            i = 1;
        }
        var ttl: ?text.Token = null;
        var class: ?text.Token = null;
        while (i < toks.len) {
            const t = toks[i];
            if (class == null and types.classFromText(t.text) != null) {
                class = tokenOf(t);
                i += 1;
                continue;
            }
            if (ttl == null and looksLikeTtl(t.text)) {
                ttl = tokenOf(t);
                i += 1;
                continue;
            }
            break;
        }
        if (i >= toks.len) return p.fail(toks[0].line, .syntax);
        const rtype_tok = toks[i];
        const rtype = types.typeFromText(rtype_tok.text) orelse return p.fail(rtype_tok.line, .syntax);
        _ = rtype;
        i += 1;
        const rdata = try p.allocator.alloc(text.Token, toks.len - i);
        errdefer p.allocator.free(rdata);
        for (toks[i..], 0..) |t, j| {
            rdata[j] = tokenOf(t);
        }
        return .{
            .owner = owner,
            .ttl = ttl,
            .class = class,
            .rtype = tokenOf(rtype_tok),
            .rdata = rdata,
            .line = toks[0].line,
        };
    }

    fn parseGenerate(p: *Parser, toks: []const lexer.Token) Error!void {
        if (toks.len < 5) return p.fail(toks[0].line, .generate);
        const range = try parseRange(toks[1].text);
        const lhs = toks[2];
        var i: usize = 3;
        var ttl: ?text.Token = null;
        var class: ?text.Token = null;
        while (i < toks.len) {
            const t = toks[i];
            if (class == null and types.classFromText(t.text) != null) {
                class = tokenOf(t);
                i += 1;
                continue;
            }
            if (ttl == null and looksLikeTtl(t.text)) {
                ttl = tokenOf(t);
                i += 1;
                continue;
            }
            break;
        }
        if (i >= toks.len) return p.fail(toks[0].line, .generate);
        const rtype = toks[i];
        if (types.typeFromText(rtype.text) == null) return p.fail(rtype.line, .generate);
        i += 1;

        if (range.count > 65536) return p.fail(toks[0].line, .generate);
        var value = range.start;
        var n: usize = 0;
        while (n < range.count) : (n += 1) {
            const owner_text = try substitute(p.allocator, lhs.text, value);
            const rdata = try p.allocator.alloc(text.Token, toks.len - i);
            errdefer p.allocator.free(rdata);
            for (toks[i..], 0..) |t, j| {
                const s = try substitute(p.allocator, t.text, value);
                rdata[j] = .{ .text = s, .quoted = t.kind == .quoted, .line = t.line };
            }
            try p.nodes.append(p.allocator, .{ .record = .{
                .owner = .{ .text = owner_text, .quoted = false, .line = lhs.line },
                .ttl = ttl,
                .class = class,
                .rtype = tokenOf(rtype),
                .rdata = rdata,
                .line = toks[0].line,
            } });
            value = std.math.add(i64, value, range.step) catch break;
        }
    }
};

pub fn parse(allocator: std.mem.Allocator, source: []const u8, source_name: []const u8) Error!ast.Ast {
    return Parser.parse(allocator, source, source_name);
}

fn tokenOf(t: lexer.Token) text.Token {
    return .{ .text = t.text, .quoted = t.kind == .quoted, .line = t.line };
}

fn looksLikeTtl(s: []const u8) bool {
    if (s.len == 0) return false;
    if (!std.ascii.isDigit(s[0])) return false;
    _ = text.parseTtl(s) catch return false;
    return true;
}

const Range = struct {
    start: i64,
    count: usize,
    step: i64,
};

fn parseRange(s: []const u8) Error!Range {
    var rest = s;
    var step: i64 = 1;
    if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
        step = std.fmt.parseInt(i64, rest[slash + 1 ..], 10) catch return error.BadGenerateRange;
        rest = rest[0..slash];
    }
    const dash = std.mem.indexOfScalar(u8, rest, '-') orelse return error.BadGenerateRange;
    if (dash == 0) return error.BadGenerateRange;
    const start = std.fmt.parseInt(i64, rest[0..dash], 10) catch return error.BadGenerateRange;
    const stop = std.fmt.parseInt(i64, rest[dash + 1 ..], 10) catch return error.BadGenerateRange;
    if (step == 0) return error.BadGenerateRange;
    if (step > 0 and stop < start) return error.BadGenerateRange;
    if (step < 0 and stop > start) return error.BadGenerateRange;
    const span: i128 = if (step > 0)
        @as(i128, stop) - @as(i128, start)
    else
        @as(i128, start) - @as(i128, stop);
    const step_i: i128 = step;
    const abs_step: i128 = if (step_i < 0) -step_i else step_i;
    const count_i: i128 = @divFloor(span, abs_step) + 1;
    if (count_i < 0 or count_i > 65536) return error.BadGenerateRange;
    return .{ .start = start, .count = @intCast(count_i), .step = step };
}

/// Expands `$` and `${offset,width,base}` in $GENERATE fields (BIND ARM).
fn substitute(allocator: std.mem.Allocator, input: []const u8, value: i64) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];
        if (c == '\\') {
            try out.append(allocator, c);
            i += 1;
            if (i < input.len) {
                try out.append(allocator, input[i]);
                i += 1;
            }
            continue;
        }
        if (c != '$') {
            try out.append(allocator, c);
            i += 1;
            continue;
        }
        i += 1;
        var offset: i64 = 0;
        var width: usize = 0;
        var base: u8 = 'd';
        if (i < input.len and input[i] == '{') {
            const close = std.mem.indexOfScalarPos(u8, input, i + 1, '}') orelse
                return error.BadGenerateSubstitution;
            const spec = input[i + 1 .. close];
            var parts = std.mem.splitScalar(u8, spec, ',');
            const off_s = parts.next() orelse return error.BadGenerateSubstitution;
            offset = std.fmt.parseInt(i64, off_s, 10) catch return error.BadGenerateSubstitution;
            if (parts.next()) |w| {
                width = std.fmt.parseInt(usize, w, 10) catch return error.BadGenerateSubstitution;
                if (width > 255) return error.BadGenerateSubstitution;
            }
            if (parts.next()) |b| {
                if (b.len != 1) return error.BadGenerateSubstitution;
                base = b[0];
            }
            if (parts.next() != null) return error.BadGenerateSubstitution;
            i = close + 1;
        }
        const v = std.math.add(i64, value, offset) catch return error.BadGenerateSubstitution;
        if (v < 0) return error.BadGenerateSubstitution;
        try appendFormatted(&out, allocator, @intCast(v), width, base);
    }
    return out.toOwnedSlice(allocator);
}

fn appendFormatted(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u64, width: usize, base: u8) !void {
    var buf: [64]u8 = undefined;
    const s = switch (base) {
        'd' => std.fmt.bufPrint(&buf, "{d}", .{v}) catch return error.BadGenerateSubstitution,
        'o' => std.fmt.bufPrint(&buf, "{o}", .{v}) catch return error.BadGenerateSubstitution,
        'x' => std.fmt.bufPrint(&buf, "{x}", .{v}) catch return error.BadGenerateSubstitution,
        'X' => std.fmt.bufPrint(&buf, "{X}", .{v}) catch return error.BadGenerateSubstitution,
        else => return error.BadGenerateSubstitution,
    };
    if (s.len < width) {
        try out.appendNTimes(allocator, '0', width - s.len);
    }
    try out.appendSlice(allocator, s);
}

test "parse basic zone AST" {
    const src =
        \\$TTL 3600
        \\$ORIGIN example.com.
        \\@ IN SOA ns1 hostmaster 1 1h 15m 1w 5m
        \\  NS ns1
        \\www 300 IN A 192.0.2.1
        \\    AAAA 2001:db8::1
        \\txt TXT "hello world"
        \\
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = try Parser.parse(arena.allocator(), src, "test.zone");
    try std.testing.expectEqual(@as(usize, 7), a.nodes.len);
    try std.testing.expect(a.nodes[0] == .ttl);
    try std.testing.expect(a.nodes[1] == .origin);
    try std.testing.expect(a.nodes[2] == .record);
    const r = a.nodes[2].record;
    try std.testing.expectEqualStrings("@", r.owner.?.text);
    try std.testing.expectEqualStrings("SOA", r.rtype.text);
    try std.testing.expectEqual(@as(usize, 7), r.rdata.len);
    const www = a.nodes[4].record;
    try std.testing.expectEqualStrings("www", www.owner.?.text);
    try std.testing.expectEqualStrings("300", www.ttl.?.text);
    try std.testing.expectEqualStrings("IN", www.class.?.text);
    const inherited = a.nodes[5].record;
    try std.testing.expect(inherited.owner == null);
    try std.testing.expectEqualStrings("AAAA", inherited.rtype.text);
    const txt = a.nodes[6].record;
    try std.testing.expect(txt.rdata[0].quoted);
}

test "generate expands range and substitution" {
    const src = "$GENERATE 1-3 host${0,2,d} A 192.0.2.$\n";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = try Parser.parse(arena.allocator(), src, "gen.zone");
    try std.testing.expectEqual(@as(usize, 3), a.nodes.len);
    try std.testing.expectEqualStrings("host01", a.nodes[0].record.owner.?.text);
    try std.testing.expectEqualStrings("192.0.2.1", a.nodes[0].record.rdata[0].text);
    try std.testing.expectEqualStrings("host03", a.nodes[2].record.owner.?.text);
}

test "include remains an AST node" {
    const src = "$INCLUDE sub.zone other.example.\n";
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = try Parser.parse(arena.allocator(), src, "inc.zone");
    try std.testing.expectEqual(@as(usize, 1), a.nodes.len);
    try std.testing.expect(a.nodes[0] == .include);
    try std.testing.expectEqualStrings("sub.zone", a.nodes[0].include.path.text);
}

test "generate rejects overflow and huge width" {
    const bad_range = "$GENERATE -9223372036854775808-9223372036854775807 host A 192.0.2.1\n";
    try std.testing.expectError(error.BadGenerateRange, Parser.parse(std.testing.allocator, bad_range, "bad.zone"));
    const bad_width = "$GENERATE 1-1 host${0,999999999,d} A 192.0.2.1\n";
    try std.testing.expectError(error.BadGenerateSubstitution, Parser.parse(std.testing.allocator, bad_width, "bad.zone"));
}
