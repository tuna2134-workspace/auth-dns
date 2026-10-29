//! NSEC3 hashing and owner-name construction (RFC 5155).
//!
//! Hash algorithm 1 is SHA-1 with the RFC 5155 iteration:
//!   IH(salt, x, 0) = H(x || salt)
//!   IH(salt, x, k) = H(IH(salt, x, k-1) || salt)

const std = @import("std");
const name = @import("name.zig");
const openssl = @import("../dnssec/openssl.zig");

pub const Params = struct {
    algorithm: u8 = 1,
    flags: u8 = 0,
    iterations: u16 = 0,
    salt: []const u8 = &.{},
};

pub const hash_len = 20;
pub const owner_label_len = 32;

pub const Error = error{
    UnsupportedAlgorithm,
    NameTooLong,
} || openssl.Error;

pub fn hashName(name_wire: []const u8, params: Params, out: *[hash_len]u8) Error!void {
    if (params.algorithm != 1) return error.UnsupportedAlgorithm;
    var buf: [hash_len + 255 + 255]u8 = undefined;
    if (name_wire.len + params.salt.len > buf.len) return error.NameTooLong;
    @memcpy(buf[0..name_wire.len], name_wire);
    @memcpy(buf[name_wire.len..][0..params.salt.len], params.salt);
    try openssl.digestSha1(buf[0 .. name_wire.len + params.salt.len], out);
    var i: u16 = 0;
    while (i < params.iterations) : (i += 1) {
        @memcpy(buf[0..hash_len], out);
        @memcpy(buf[hash_len..][0..params.salt.len], params.salt);
        try openssl.digestSha1(buf[0 .. hash_len + params.salt.len], out);
    }
}

pub fn base32Encode(hash: *const [hash_len]u8, out: *[owner_label_len]u8) []const u8 {
    const alphabet = "0123456789abcdefghijklmnopqrstuv";
    var acc: u32 = 0;
    var bits: u4 = 0;
    var pos: usize = 0;
    for (hash) |b| {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[pos] = alphabet[(acc >> bits) & 0x1f];
            pos += 1;
        }
    }
    return out[0..pos];
}

/// Builds `<base32hash>.<origin>`.
pub fn makeOwner(hash: *const [hash_len]u8, origin: []const u8, out: *name.Name) Error![]const u8 {
    var label: [owner_label_len]u8 = undefined;
    const encoded = base32Encode(hash, &label);
    out.len = 0;
    if (1 + encoded.len + origin.len > name.max_name_len) return error.NameTooLong;
    out.buf[0] = @intCast(encoded.len);
    @memcpy(out.buf[1..][0..encoded.len], encoded);
    var pos = 1 + encoded.len;
    @memcpy(out.buf[pos..][0..origin.len], origin);
    pos += origin.len;
    out.len = @intCast(pos);
    return out.slice();
}

/// Parses the parameters from NSEC3PARAM or NSEC3 RDATA.
pub fn paramsFromRdata(rdata: []const u8) ?Params {
    if (rdata.len < 5) return null;
    const salt_len = rdata[4];
    if (5 + salt_len > rdata.len) return null;
    return .{
        .algorithm = rdata[0],
        .flags = rdata[1],
        .iterations = (@as(u16, rdata[2]) << 8) | rdata[3],
        .salt = rdata[5 .. 5 + salt_len],
    };
}

test "RFC 5155 hash vector" {
    var origin = try name.parseText("example.", null);
    const params = Params{ .iterations = 12, .salt = &.{ 0xaa, 0xbb, 0xcc, 0xdd } };
    var h: [hash_len]u8 = undefined;
    try hashName(origin.slice(), params, &h);
    var out: [owner_label_len]u8 = undefined;
    try std.testing.expectEqualStrings("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", base32Encode(&h, &out));
}
