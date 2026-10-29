//! Master-file text helpers shared by the zone parser, AST and RDATA decoder.
//!
//! Tokens deliberately keep their original octets (including backslash
//! escapes).  Name parsing needs to distinguish `\.` from a label separator,
//! while TXT/HINFO/CAA decoding needs the escaped octets expanded.

const std = @import("std");

pub const Token = struct {
    text: []const u8,
    quoted: bool = false,
    line: u32 = 0,
};

pub const Error = error{
    InvalidTtl,
    TtlOverflow,
    InvalidNumber,
    InvalidTime,
    InvalidEscape,
    InvalidHex,
    InvalidBase64,
    ValueTooLong,
    OutOfMemory,
};

/// RFC 2181 section 8: TTL is an unsigned 31-bit value; the top bit must be
/// zero so that TTLs compare correctly when interpreted as signed.
pub const max_ttl: u32 = 0x7fffffff;

pub fn parseTtl(text: []const u8) Error!u32 {
    if (text.len == 0) return error.InvalidTtl;
    var total: u64 = 0;
    var i: usize = 0;
    while (i < text.len) {
        const start = i;
        while (i < text.len and std.ascii.isDigit(text[i])) i += 1;
        if (i == start) return error.InvalidTtl;
        const n = std.fmt.parseInt(u64, text[start..i], 10) catch return error.InvalidTtl;
        var mult: u64 = 1;
        if (i < text.len) {
            switch (text[i]) {
                's', 'S' => mult = 1,
                'm', 'M' => mult = 60,
                'h', 'H' => mult = 3600,
                'd', 'D' => mult = 86400,
                'w', 'W' => mult = 604800,
                else => return error.InvalidTtl,
            }
            i += 1;
        }
        const add = std.math.mul(u64, n, mult) catch return error.TtlOverflow;
        total = std.math.add(u64, total, add) catch return error.TtlOverflow;
    }
    if (total > max_ttl) return error.TtlOverflow;
    return @intCast(total);
}

pub fn parseU8(text: []const u8) Error!u8 {
    return std.fmt.parseInt(u8, text, 10) catch error.InvalidNumber;
}

pub fn parseU16(text: []const u8) Error!u16 {
    return std.fmt.parseInt(u16, text, 10) catch error.InvalidNumber;
}

pub fn parseU32(text: []const u8) Error!u32 {
    return std.fmt.parseInt(u32, text, 10) catch error.InvalidNumber;
}

/// DNSSEC timestamps are either seconds since the Unix epoch or the common
/// presentation form YYYYMMDDHHMMSS (RFC 4034 section 3.2).  The result is
/// truncated to 32 bits as required by the RRSIG wire format.
pub fn parseTime(text: []const u8) Error!u32 {
    if (text.len == 14 and std.ascii.isDigit(text[0])) {
        const year = std.fmt.parseInt(i64, text[0..4], 10) catch return error.InvalidTime;
        const month = std.fmt.parseInt(u8, text[4..6], 10) catch return error.InvalidTime;
        const day = std.fmt.parseInt(u8, text[6..8], 10) catch return error.InvalidTime;
        const hour = std.fmt.parseInt(u8, text[8..10], 10) catch return error.InvalidTime;
        const minute = std.fmt.parseInt(u8, text[10..12], 10) catch return error.InvalidTime;
        const second = std.fmt.parseInt(u8, text[12..14], 10) catch return error.InvalidTime;
        const secs = civilToUnix(year, month, day, hour, minute, second) catch return error.InvalidTime;
        return @truncate(@as(u64, @bitCast(secs)));
    }
    const n = std.fmt.parseInt(u64, text, 10) catch return error.InvalidTime;
    return @truncate(n);
}

fn civilToUnix(year_in: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8) !i64 {
    if (month < 1 or month > 12) return error.InvalidTime;
    if (hour > 23 or minute > 59 or second > 60) return error.InvalidTime;
    const mdays = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var max_day = mdays[month - 1];
    if (month == 2 and isLeap(year_in)) max_day = 29;
    if (day < 1 or day > max_day) return error.InvalidTime;

    var y = year_in;
    const m: i64 = month;
    if (m <= 2) y -= 1;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400; // [0, 399]
    const mp = if (m > 2) m - 3 else m + 9; // [0, 11]
    const doy = @divFloor(153 * mp + 2, 5) + @as(i64, day) - 1; // [0, 365]
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

fn isLeap(y: i64) bool {
    return (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
}

/// Expands RFC 1035 `\DDD` and `\X` escapes.  The output may be any octet,
/// including NUL; callers must treat it as a byte string.
pub fn decodeString(text: []const u8, out: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    var i: usize = 0;
    while (i < text.len) {
        const c = text[i];
        if (c != '\\') {
            try out.append(allocator, c);
            i += 1;
            continue;
        }
        if (i + 1 >= text.len) return error.InvalidEscape;
        const e = text[i + 1];
        if (e >= '0' and e <= '9') {
            if (i + 3 >= text.len) return error.InvalidEscape;
            if (text[i + 2] < '0' or text[i + 2] > '9' or
                text[i + 3] < '0' or text[i + 3] > '9') return error.InvalidEscape;
            const d0 = text[i + 1] - '0';
            const d1 = text[i + 2] - '0';
            const d2 = text[i + 3] - '0';
            const v: u16 = @as(u16, d0) * 100 + @as(u16, d1) * 10 + d2;
            if (v > 255) return error.InvalidEscape;
            try out.append(allocator, @intCast(v));
            i += 4;
        } else {
            try out.append(allocator, e);
            i += 2;
        }
    }
}

pub fn decodedAlloc(allocator: std.mem.Allocator, text: []const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try decodeString(text, &out, allocator);
    return out.toOwnedSlice(allocator);
}

/// Appends a wire-format RFC 1035 character-string (length octet + data).
/// Long input is split into 255-octet strings as BIND does for TXT.
pub fn appendCharString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) !void {
    if (data.len == 0) {
        try out.append(allocator, 0);
        return;
    }
    var rest = data;
    while (rest.len > 0) {
        const n = @min(rest.len, 255);
        try out.append(allocator, @intCast(n));
        try out.appendSlice(allocator, rest[0..n]);
        rest = rest[n..];
    }
}

pub fn appendU8(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u8) !void {
    try out.append(allocator, v);
}

pub fn appendU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u16) !void {
    try out.append(allocator, @intCast(v >> 8));
    try out.append(allocator, @intCast(v & 0xff));
}

pub fn appendU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u32) !void {
    try out.append(allocator, @intCast((v >> 24) & 0xff));
    try out.append(allocator, @intCast((v >> 16) & 0xff));
    try out.append(allocator, @intCast((v >> 8) & 0xff));
    try out.append(allocator, @intCast(v & 0xff));
}

pub fn appendHex(out: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) Error!void {
    if (text.len % 2 != 0) return error.InvalidHex;
    var i: usize = 0;
    while (i < text.len) : (i += 2) {
        const hi = hexVal(text[i]) orelse return error.InvalidHex;
        const lo = hexVal(text[i + 1]) orelse return error.InvalidHex;
        try out.append(allocator, (hi << 4) | lo);
    }
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Decodes standard base64, ignoring whitespace.  BIND permits the key or
/// signature to be split across tokens/lines in parentheses.
pub fn appendBase64(out: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) Error!void {
    var cleaned: std.ArrayList(u8) = .empty;
    defer cleaned.deinit(allocator);
    for (text) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        try cleaned.append(allocator, c);
    }
    const dec = &std.base64.standard.Decoder;
    const size = dec.calcSizeForSlice(cleaned.items) catch return error.InvalidBase64;
    const old_len = out.items.len;
    try out.resize(allocator, old_len + size);
    dec.decode(out.items[old_len..], cleaned.items) catch return error.InvalidBase64;
}

pub fn asciiLowerAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, text.len);
    for (text, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

test "TTL parsing" {
    try std.testing.expectEqual(@as(u32, 3600), try parseTtl("1h"));
    try std.testing.expectEqual(@as(u32, 5400), try parseTtl("1h30m"));
    try std.testing.expectEqual(@as(u32, 604800), try parseTtl("1w"));
    try std.testing.expectEqual(@as(u32, 42), try parseTtl("42"));
    try std.testing.expectError(error.TtlOverflow, parseTtl("2147483648"));
}

test "DNSSEC time parsing" {
    try std.testing.expectEqual(@as(u32, 0), try parseTime("19700101000000"));
    try std.testing.expectEqual(@as(u32, 1700000000), try parseTime("20231114221320"));
    try std.testing.expectEqual(@as(u32, 12345), try parseTime("12345"));
}

test "reject non-decimal escaped octet" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidEscape, decodeString("\\0/0", &out, std.testing.allocator));
}

test "escape decoding" {
    const allocator = std.testing.allocator;
    const got = try decodedAlloc(allocator, "a\\046b\\255");
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, "a.b\xff", got);
}

test "base64 decoding" {
    const allocator = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendBase64(&out, allocator, "aGVsbG8=");
    try std.testing.expectEqualStrings("hello", out.items);
}
