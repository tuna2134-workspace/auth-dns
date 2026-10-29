//! TSIG transaction signatures (RFC 8945, obsoleting RFC 2845).
//!
//! Only libcrypto's HMAC is used.  The wire format and MAC input are
//! implemented directly from the RFC so that AXFR/IXFR multi-message signing
//! and BADTIME/BADSIG handling remain explicit.

const std = @import("std");
const name = @import("name.zig");
const types = @import("types.zig");
const message = @import("message.zig");
const openssl = @import("../dnssec/openssl.zig");

pub const Error = error{
    NotTsig,
    BadClass,
    BadTtl,
    BadRdata,
    BadMac,
    BadKey,
    BadTime,
    BadOriginalId,
    MacTooShort,
    MacTooLong,
    TsigNotLast,
    NoSpace,
} || name.Error || openssl.Error;

pub const Key = struct {
    /// Canonical lowercase wire name.
    name_wire: []const u8,
    /// Presentation form, used by ACL `key "name"` entries.
    name_text: []const u8,
    /// Canonical lowercase wire algorithm name, e.g. hmac-sha256.
    algorithm_wire: []const u8,
    algorithm_text: []const u8,
    secret: []const u8,

    pub fn deinit(k: *Key, allocator: std.mem.Allocator) void {
        allocator.free(k.name_wire);
        allocator.free(k.name_text);
        allocator.free(k.algorithm_wire);
        allocator.free(k.algorithm_text);
        allocator.free(k.secret);
    }
};

pub const Parsed = struct {
    key_name: name.Name,
    algorithm_name: name.Name,
    time_signed: u64,
    fudge: u16,
    mac: []const u8,
    original_id: u16,
    err_code: u16,
    other: []const u8,
};

pub const Request = struct {
    key: *const Key,
    mac: []u8,
    original_id: u16,
    time_signed: u64,
    fudge: u16,
};

pub fn parse(rr: message.Record) Error!Parsed {
    if (rr.rtype != types.TSIG) return error.NotTsig;
    if (rr.class != types.class_any) return error.BadClass;
    if (rr.ttl != 0) return error.BadTtl;
    var off: usize = 0;
    var alg: name.Name = undefined;
    off = try name.parseWire(rr.rdata, off, &alg);
    if (off + 10 > rr.rdata.len) return error.BadRdata;
    var ts: u64 = 0;
    for (0..6) |i| ts = (ts << 8) | rr.rdata[off + i];
    off += 6;
    const fudge = readU16(rr.rdata, off);
    const mac_len = readU16(rr.rdata, off + 2);
    off += 4;
    if (off + mac_len + 6 > rr.rdata.len) return error.BadRdata;
    const mac = rr.rdata[off .. off + mac_len];
    off += mac_len;
    const original_id = readU16(rr.rdata, off);
    const err = readU16(rr.rdata, off + 2);
    const other_len = readU16(rr.rdata, off + 4);
    off += 6;
    if (off + other_len != rr.rdata.len) return error.BadRdata;
    const other = rr.rdata[off .. off + other_len];
    return .{
        .key_name = rr.owner,
        .algorithm_name = alg,
        .time_signed = ts,
        .fudge = fudge,
        .mac = mac,
        .original_id = original_id,
        .err_code = err,
        .other = other,
    };
}

pub fn findKey(keys: []const Key, key_name: *const name.Name, algorithm: *const name.Name) ?*const Key {
    for (keys) |*k| {
        if (!wireEqlIgnoreCase(k.name_wire, key_name.slice())) continue;
        if (!wireEqlIgnoreCase(k.algorithm_wire, algorithm.slice())) continue;
        return k;
    }
    return null;
}

pub const VerifyContext = struct {
    parsed: ?Parsed = null,
    key: ?*const Key = null,
    mac_valid: bool = false,
};

/// Verifies a request TSIG.  The TSIG must be the final record of the message.
pub fn verifyRequest(
    allocator: std.mem.Allocator,
    raw: []const u8,
    rr: message.Record,
    keys: []const Key,
    ctx: ?*VerifyContext,
) Error!Request {
    const parsed = try parse(rr);
    if (ctx) |c| c.parsed = parsed;
    const key = findKey(keys, &parsed.key_name, &parsed.algorithm_name) orelse return error.BadKey;
    if (ctx) |c| c.key = key;
    if (parsed.err_code != 0) return error.BadRdata;
    const hdr = message.Header.parse(raw) catch return error.BadRdata;
    if (parsed.original_id != hdr.id) return error.BadOriginalId;
    const end = rr.rdata_offset + rr.rdata.len;
    if (end != raw.len) return error.TsigNotLast;

    // The MAC covers the message with the TSIG removed and ARCOUNT decremented.
    const unsigned = try allocator.dupe(u8, raw[0..rr.name_offset]);
    defer allocator.free(unsigned);
    const old_arc = readU16(unsigned, 10);
    if (old_arc == 0) return error.BadRdata;
    writeU16(unsigned, 10, old_arc - 1);

    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    try input.appendSlice(allocator, unsigned);
    const now = currentTime();
    try appendVariables(&input, allocator, key, parsed.time_signed, parsed.fudge, parsed.err_code, parsed.other);

    var mac: [64]u8 = undefined;
    const mac_len = try openssl.hmac(key.algorithm_text, key.secret, input.items, &mac);
    if (parsed.mac.len > mac_len) return error.BadMac;
    if (parsed.mac.len < @max(10, mac_len / 2)) return error.MacTooShort;
    var diff: u8 = 0;
    for (parsed.mac, 0..) |b, i| diff |= b ^ mac[i];
    if (diff != 0) return error.BadMac;
    if (ctx) |c| c.mac_valid = true;
    if (!withinFudge(now, parsed.time_signed, parsed.fudge)) return error.BadTime;
    const req_mac = try allocator.dupe(u8, parsed.mac);
    return .{
        .key = key,
        .mac = req_mac,
        .original_id = parsed.original_id,
        .time_signed = parsed.time_signed,
        .fudge = parsed.fudge,
    };
}

fn withinFudge(now: u64, signed: u64, fudge: u16) bool {
    const f: u64 = fudge;
    if (now >= signed) return now - signed <= f;
    return signed - now <= f;
}

/// Appends a TSIG RR to `buf[0..len]`.  `buf` must have room; the message
/// header's ARCOUNT is incremented.  Returns the new message length.
///
/// `prior_mac` is the request MAC for the first response message, or the
/// previous response message's MAC for subsequent AXFR/IXFR messages.
/// `timers_only` selects the reduced AXFR continuation variable set.
pub const Signed = struct {
    len: usize,
    mac: [64]u8 = undefined,
    mac_len: u8 = 0,
};

pub const ResponseOptions = struct {
    prior_mac: []const u8 = &.{},
    original_id: u16,
    timers_only: bool = false,
    /// Overrides the response time (used for BADTIME, where the client's time
    /// is echoed).
    time_signed: ?u64 = null,
    fudge: u16 = 300,
    error_code: u16 = 0,
    other: []const u8 = &.{},
    /// Emit a TSIG with MAC size 0 (unsigned BADSIG/BADKEY errors).
    omit_mac: bool = false,
};

pub fn appendResponse(
    allocator: std.mem.Allocator,
    buf: []u8,
    len: usize,
    key: *const Key,
    opts: ResponseOptions,
) Error!Signed {
    const now = opts.time_signed orelse currentTime();
    const fudge = opts.fudge;

    var rdata: std.ArrayList(u8) = .empty;
    defer rdata.deinit(allocator);
    try rdata.appendSlice(allocator, key.algorithm_wire);
    try appendU48(&rdata, allocator, now);
    try appendU16(&rdata, allocator, fudge);
    const mac_len_pos = rdata.items.len;
    try appendU16(&rdata, allocator, 0); // patched below

    var mac: [64]u8 = undefined;
    var mac_len: usize = 0;
    if (!opts.omit_mac) {
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(allocator);
        if (opts.prior_mac.len > 0) {
            try appendU16(&input, allocator, @intCast(opts.prior_mac.len));
            try input.appendSlice(allocator, opts.prior_mac);
        }
        try input.appendSlice(allocator, buf[0..len]);
        if (opts.timers_only) {
            try appendU48(&input, allocator, now);
            try appendU16(&input, allocator, fudge);
        } else {
            try appendVariables(&input, allocator, key, now, fudge, opts.error_code, opts.other);
        }
        mac_len = try openssl.hmac(key.algorithm_text, key.secret, input.items, &mac);
    }
    writeU16(rdata.items, mac_len_pos, @intCast(mac_len));
    try rdata.appendSlice(allocator, mac[0..mac_len]);
    try appendU16(&rdata, allocator, opts.original_id);
    try appendU16(&rdata, allocator, opts.error_code);
    try appendU16(&rdata, allocator, @intCast(opts.other.len));
    try rdata.appendSlice(allocator, opts.other);

    const rr_len = key.name_wire.len + 10 + rdata.items.len;
    if (len + rr_len > buf.len or len + rr_len > 65535) return error.NoSpace;
    @memcpy(buf[len..][0..key.name_wire.len], key.name_wire);
    var p = len + key.name_wire.len;
    writeU16(buf, p, types.TSIG);
    writeU16(buf, p + 2, types.class_any);
    writeU32(buf, p + 4, 0);
    writeU16(buf, p + 8, @intCast(rdata.items.len));
    p += 10;
    @memcpy(buf[p..][0..rdata.items.len], rdata.items);
    p += rdata.items.len;
    const arc = readU16(buf, 10);
    writeU16(buf, 10, arc + 1);
    var signed: Signed = .{ .len = p, .mac_len = @intCast(mac_len) };
    @memcpy(signed.mac[0..mac_len], mac[0..mac_len]);
    return signed;
}

fn appendVariables(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    key: *const Key,
    time_signed: u64,
    fudge: u16,
    err: u16,
    other: []const u8,
) !void {
    try out.appendSlice(allocator, key.name_wire);
    try appendU16(out, allocator, types.class_any);
    try appendU32(out, allocator, 0);
    try out.appendSlice(allocator, key.algorithm_wire);
    try appendU48(out, allocator, time_signed);
    try appendU16(out, allocator, fudge);
    try appendU16(out, allocator, err);
    try appendU16(out, allocator, @intCast(other.len));
    try out.appendSlice(allocator, other);
}

pub fn buildKey(
    allocator: std.mem.Allocator,
    name_text: []const u8,
    algorithm_text: []const u8,
    secret: []const u8,
) !Key {
    const root = name.Name.root();
    var kn = try name.parseText(name_text, &root);
    name.lowerInPlace(kn.buf[0..kn.len]);
    var alg_buf: [128]u8 = undefined;
    const alg_text = if (algorithm_text.len > 0 and algorithm_text[algorithm_text.len - 1] == '.')
        algorithm_text
    else
        try std.fmt.bufPrint(&alg_buf, "{s}.", .{algorithm_text});
    var an = try name.parseText(alg_text, &root);
    name.lowerInPlace(an.buf[0..an.len]);
    var nbuf: [name.max_name_len]u8 = undefined;
    const nt = try kn.toText(&nbuf);
    return .{
        .name_wire = try allocator.dupe(u8, kn.slice()),
        .name_text = try allocator.dupe(u8, nt),
        .algorithm_wire = try allocator.dupe(u8, an.slice()),
        .algorithm_text = try allocator.dupe(u8, algorithm_text),
        .secret = try allocator.dupe(u8, secret),
    };
}

extern fn time(t: ?*c_long) c_long;

fn currentTime() u64 {
    const secs = time(null);
    return if (secs < 0) 0 else @intCast(secs);
}

fn readU16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}
fn writeU16(buf: []u8, off: usize, v: u16) void {
    buf[off] = @intCast(v >> 8);
    buf[off + 1] = @intCast(v & 0xff);
}
fn writeU32(buf: []u8, off: usize, v: u32) void {
    buf[off] = @intCast(v >> 24);
    buf[off + 1] = @intCast((v >> 16) & 0xff);
    buf[off + 2] = @intCast((v >> 8) & 0xff);
    buf[off + 3] = @intCast(v & 0xff);
}
fn appendU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u16) !void {
    try out.append(allocator, @intCast(v >> 8));
    try out.append(allocator, @intCast(v & 0xff));
}
fn appendU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u32) !void {
    try out.append(allocator, @intCast(v >> 24));
    try out.append(allocator, @intCast((v >> 16) & 0xff));
    try out.append(allocator, @intCast((v >> 8) & 0xff));
    try out.append(allocator, @intCast(v & 0xff));
}
fn appendU48(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u64) !void {
    for (0..6) |i| try out.append(allocator, @intCast((v >> @intCast(40 - 8 * i)) & 0xff));
}

fn wireEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return name.eqlWireIgnoreCase(a, b);
}

pub const ReplayCache = struct {
    lock: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    times: std.StringHashMapUnmanaged(u64) = .{},

    pub fn deinit(c: *ReplayCache, allocator: std.mem.Allocator) void {
        c.times.deinit(allocator);
    }

    fn acquire(c: *ReplayCache) void {
        while (c.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn release(c: *ReplayCache) void {
        c.lock.store(false, .release);
    }

    /// Rejects timestamps older than the newest seen time minus fudge.
    /// Returns false when the request is a replay.
    pub fn checkAndUpdate(c: *ReplayCache, allocator: std.mem.Allocator, key_name: []const u8, time_signed: u64, fudge: u16) bool {
        c.acquire();
        defer c.release();
        const last = c.times.get(key_name) orelse 0;
        if (last != 0 and time_signed +% fudge < last) return false;
        if (time_signed > last) {
            c.times.put(allocator, key_name, time_signed) catch return true;
        }
        return true;
    }
};

/// 48-bit server time used in the Other Data field of BADTIME.
pub fn serverTime48() [6]u8 {
    const now = currentTime();
    var out: [6]u8 = undefined;
    for (0..6) |i| out[i] = @intCast((now >> @intCast(40 - 8 * i)) & 0xff);
    return out;
}

test "build TSIG key" {
    const allocator = std.testing.allocator;
    var k = try buildKey(allocator, "xfr.example.com", "hmac-sha256", "secret");
    defer k.deinit(allocator);
    try std.testing.expectEqualStrings("\x03xfr\x07example\x03com\x00", k.name_wire);
    try std.testing.expectEqualStrings("\x0bhmac-sha256\x00", k.algorithm_wire);
}
