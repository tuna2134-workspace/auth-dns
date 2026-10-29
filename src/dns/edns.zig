//! EDNS(0), RFC 6891.
//!
//! The OPT pseudo-RR is carried in the additional section.  Its owner name is
//! the root, its CLASS is the requestor's UDP payload size, and its TTL packs
//! the extended RCODE, version and flags (including DO).

const std = @import("std");

pub const rr_type: u16 = 41;
pub const default_udp_size: u16 = 512;
pub const max_udp_size: u16 = 4096;
/// A conservative size that avoids IP fragmentation on typical paths and is
/// widely used by modern authoritative servers (DNS Flag Day 2020).
pub const recommended_udp_size: u16 = 1232;
pub const do_flag: u16 = 0x8000;
pub const version: u8 = 0;

pub const Error = error{
    BadOpt,
    Truncated,
    TooManyOptions,
};

pub const Opt = struct {
    udp_size: u16 = recommended_udp_size,
    ext_rcode: u8 = 0,
    version: u8 = 0,
    flags: u16 = 0,
    /// Raw option data (sequence of {code, length, data}).
    options: []const u8 = &.{},

    pub fn doBit(o: *const Opt) bool {
        return o.flags & do_flag != 0;
    }

    pub fn setDo(o: *Opt, on: bool) void {
        if (on) o.flags |= do_flag else o.flags &= ~do_flag;
    }

    /// The advertised requestor payload size, clamped to the minimum allowed
    /// by RFC 6891 section 6.2.5.
    pub fn effectiveUdpSize(o: *const Opt) u16 {
        return @max(o.udp_size, default_udp_size);
    }
};

pub fn parse(rdata: []const u8) Error!Opt {
    const o: Opt = .{ .options = rdata };
    var it = Iterator{ .data = rdata };
    while (it.next() catch return error.BadOpt) |_| {}
    return o;
}

pub fn encodeTtl(o: *const Opt) u32 {
    return (@as(u32, o.ext_rcode) << 24) |
        (@as(u32, o.version) << 16) |
        @as(u32, o.flags);
}

pub fn decodeTtl(ttl: u32) Opt {
    return .{
        .ext_rcode = @intCast(ttl >> 24),
        .version = @intCast((ttl >> 16) & 0xff),
        .flags = @intCast(ttl & 0xffff),
    };
}

pub const Option = struct {
    code: u16,
    data: []const u8,
};

pub const Iterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn next(it: *Iterator) Error!?Option {
        if (it.pos == it.data.len) return null;
        if (it.pos + 4 > it.data.len) return error.Truncated;
        const code = (@as(u16, it.data[it.pos]) << 8) | it.data[it.pos + 1];
        const len = (@as(u16, it.data[it.pos + 2]) << 8) | it.data[it.pos + 3];
        it.pos += 4;
        if (it.pos + len > it.data.len) return error.Truncated;
        const d = it.data[it.pos .. it.pos + len];
        it.pos += len;
        return .{ .code = code, .data = d };
    }
};

/// Builds an OPT RDATA containing the given options.  The caller owns the
/// returned buffer.
pub fn encodeOptions(allocator: std.mem.Allocator, options: []const Option) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (options) |o| {
        if (o.data.len > 65535) return error.BadOpt;
        try out.append(allocator, @intCast(o.code >> 8));
        try out.append(allocator, @intCast(o.code & 0xff));
        try out.append(allocator, @intCast(o.data.len >> 8));
        try out.append(allocator, @intCast(o.data.len & 0xff));
        try out.appendSlice(allocator, o.data);
    }
    return out.toOwnedSlice(allocator);
}

test "parse OPT rdata options" {
    const rdata = "\x00\x0a\x00\x08abcdefgh";
    const o = try parse(rdata);
    var it = Iterator{ .data = o.options };
    const opt = (try it.next()).?;
    try std.testing.expectEqual(@as(u16, 10), opt.code);
    try std.testing.expectEqualStrings("abcdefgh", opt.data);
    try std.testing.expect((try it.next()) == null);
}

test "TTL packing" {
    var o: Opt = .{ .udp_size = 1232, .ext_rcode = 1, .version = 0 };
    o.setDo(true);
    const ttl = encodeTtl(&o);
    const back = decodeTtl(ttl);
    try std.testing.expectEqual(@as(u8, 1), back.ext_rcode);
    try std.testing.expect(back.doBit());
}
