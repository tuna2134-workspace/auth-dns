//! Offline DNSSEC signing: DNSKEY, RRSIG and NSEC generation.
//!
//! Signing happens at zone load time.  The resulting records are ordinary
//! zone records, so the query and transfer paths need no special casing other
//! than honouring the DO bit when deciding whether to return RRSIGs.
//!
//! References:
//!   * RFC 4034 sections 3, 4, 6 (DNSKEY, RRSIG, NSEC, canonical form)
//!   * RFC 4035 sections 2, 3 (authoritative DNSSEC behaviour)
//!   * RFC 6605 (ECDSA), RFC 8080 (Ed25519), RFC 5702 (RSA/SHA-256)

const std = @import("std");
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");
const text = @import("../dns/text.zig");
const rdata = @import("../dns/rdata.zig");
const zone = @import("../zone/zone.zig");
const openssl = @import("openssl.zig");

extern fn time(t: ?*c_long) c_long;

pub const Options = struct {
    key_flags: u16 = 257,
    /// Seconds of validity; default 30 days.
    validity: u32 = 30 * 24 * 3600,
    /// Signature inception is now - inception_skew.
    inception_skew: u32 = 3600,
    inception: ?u32 = null,
    expiration: ?u32 = null,
    /// TTL for DNSKEY and NSEC records; defaults to the SOA TTL and the
    /// negative-cache TTL respectively.
    dnskey_ttl: ?u32 = null,
    nsec_ttl: ?u32 = null,
};

/// Adds DNSKEY, NSEC and RRSIG records to `z` and returns the complete record
/// list.  Owner/RDATA slices of the original records reference `z`; the zone
/// must outlive the returned array (it is consumed by Zone.build, which
/// copies).
pub fn signZone(
    allocator: std.mem.Allocator,
    z: *const zone.Zone,
    key: *const openssl.Key,
    opts: Options,
) ![]zone.Record {
    const now: u32 = @truncate(@as(u64, @bitCast(time(null))));
    const inception = opts.inception orelse (now -% opts.inception_skew);
    const expiration = opts.expiration orelse (now +% opts.validity);
    const dnskey_ttl = opts.dnskey_ttl orelse z.soa.ttl;
    const nsec_ttl = opts.nsec_ttl orelse z.negative_ttl;

    const dnskey_rdata = try openssl.dnskeyRdata(allocator, opts.key_flags, key);
    const ksk_tag = openssl.keyTag(dnskey_rdata);
    // A zone needs a ZSK for ordinary data and (for conventional validators)
    // a self-signed KSK.  With a single private key we publish the same public
    // key under both flags, sign the DNSKEY RRset with the KSK and everything
    // else with the ZSK.
    const zsk_rdata = if (opts.key_flags != 256)
        try openssl.dnskeyRdata(allocator, 256, key)
    else
        dnskey_rdata;
    const zsk_tag = openssl.keyTag(zsk_rdata);

    var out: std.ArrayList(zone.Record) = .empty;
    errdefer out.deinit(allocator);

    // 1. Original records (excluding any pre-existing DNSSEC records, which a
    //    zone file should not normally contain when online/offline signing is
    //    enabled).
    for (z.allRRsets()) |*rs| {
        for (rs.rdata) |rd| {
            try out.append(allocator, .{
                .owner = rs.owner,
                .rtype = rs.rtype,
                .class = z.class,
                .ttl = rs.ttl,
                .rdata = rd,
            });
        }
    }

    // 2. DNSKEY(s) at the apex.
    try out.append(allocator, .{
        .owner = z.origin_wire,
        .rtype = types.DNSKEY,
        .class = z.class,
        .ttl = dnskey_ttl,
        .rdata = dnskey_rdata,
    });
    if (zsk_rdata.ptr != dnskey_rdata.ptr) {
        try out.append(allocator, .{
            .owner = z.origin_wire,
            .rtype = types.DNSKEY,
            .class = z.class,
            .ttl = dnskey_ttl,
            .rdata = zsk_rdata,
        });
    }

    // 3. NSEC chain over authoritative names.
    var nameset: std.StringHashMapUnmanaged(void) = .{};
    defer nameset.deinit(allocator);
    for (z.allRRsets()) |*rs| {
        if (isAuthoritativeRRset(z, rs.owner, rs.rtype)) {
            try nameset.put(allocator, rs.owner, {});
        }
    }
    try nameset.put(allocator, z.origin_wire, {});
    var sorted_list: std.ArrayList([]const u8) = .empty;
    defer sorted_list.deinit(allocator);
    var it = nameset.iterator();
    while (it.next()) |entry| try sorted_list.append(allocator, entry.key_ptr.*);
    const sorted = try sorted_list.toOwnedSlice(allocator);
    defer allocator.free(sorted);
    std.mem.sort([]const u8, sorted, {}, nameLess);

    var nsec_records: std.ArrayList(zone.Record) = .empty;
    defer nsec_records.deinit(allocator);
    for (sorted, 0..) |owner, i| {
        const next = sorted[(i + 1) % sorted.len];
        var rd: std.ArrayList(u8) = .empty;
        defer rd.deinit(allocator);
        try rd.appendSlice(allocator, next);
        var tlist: std.ArrayList(u16) = .empty;
        defer tlist.deinit(allocator);
        for (z.rrsetsAt(owner)) |idx| {
            const rs = &z.rrsets[idx];
            if (!isAuthoritativeRRset(z, owner, rs.rtype)) continue;
            if (isDelegationOwner(z, owner) and rs.rtype != types.NS and rs.rtype != types.DS) continue;
            try tlist.append(allocator, rs.rtype);
        }
        try tlist.append(allocator, types.RRSIG);
        try tlist.append(allocator, types.NSEC);
        if (std.mem.eql(u8, owner, z.origin_wire)) try tlist.append(allocator, types.DNSKEY);
        try rdata.encodeTypeBitmap(&rd, allocator, tlist.items);
        try nsec_records.append(allocator, .{
            .owner = owner,
            .rtype = types.NSEC,
            .class = z.class,
            .ttl = nsec_ttl,
            .rdata = try rd.toOwnedSlice(allocator),
        });
        try out.append(allocator, nsec_records.items[nsec_records.items.len - 1]);
    }

    // 4. Sign every authoritative RRset, including DNSKEY and NSEC.
    for (z.allRRsets()) |*rs| {
        if (!isSignableRRset(z, rs.owner, rs.rtype)) continue;
        const sig = try makeRrsig(allocator, z, rs.owner, rs.rtype, rs.ttl, rs.rdata, key, zsk_tag, inception, expiration);
        try out.append(allocator, sig);
    }
    // DNSKEY RRset, signed by the KSK.
    {
        var rdatas: [2][]const u8 = .{ dnskey_rdata, zsk_rdata };
        const n: usize = if (zsk_rdata.ptr != dnskey_rdata.ptr) 2 else 1;
        const sig = try makeRrsig(allocator, z, z.origin_wire, types.DNSKEY, dnskey_ttl, rdatas[0..n], key, ksk_tag, inception, expiration);
        try out.append(allocator, sig);
    }
    // NSEC RRsets.
    for (nsec_records.items) |*nr| {
        const rdatas = [_][]const u8{nr.rdata};
        const sig = try makeRrsig(allocator, z, nr.owner, types.NSEC, nr.ttl, &rdatas, key, zsk_tag, inception, expiration);
        try out.append(allocator, sig);
    }

    return out.toOwnedSlice(allocator);
}

fn nameLess(_: void, a: []const u8, b: []const u8) bool {
    return name.Name.canonicalCompareWire(a, b) == .lt;
}

fn isDelegationOwner(z: *const zone.Zone, owner: []const u8) bool {
    return z.isDelegation(owner);
}

/// True when an RRset is owned by the authoritative side of a zone (the apex,
/// an ordinary name, or the parent side of a delegation for NS/DS only).
fn isAuthoritativeRRset(z: *const zone.Zone, owner: []const u8, rtype: u16) bool {
    if (z.findDelegation(owner)) |deleg| {
        if (!std.mem.eql(u8, deleg, owner)) return false;
        return rtype == types.NS or rtype == types.DS or rtype == types.NSEC or rtype == types.RRSIG;
    }
    return true;
}

/// RFC 4035 section 3.1.4: the parent side of a delegation signs DS (and the
/// NSEC proving its absence), but not the delegation NS RRset, which belongs
/// to the child zone.
fn isSignableRRset(z: *const zone.Zone, owner: []const u8, rtype: u16) bool {
    if (z.findDelegation(owner)) |deleg| {
        if (!std.mem.eql(u8, deleg, owner)) return false;
        return rtype == types.DS or rtype == types.NSEC;
    }
    return true;
}

fn makeRrsig(
    allocator: std.mem.Allocator,
    z: *const zone.Zone,
    owner: []const u8,
    rtype: u16,
    ttl: u32,
    rdatas: []const []const u8,
    key: *const openssl.Key,
    key_tag: u16,
    inception: u32,
    expiration: u32,
) !zone.Record {
    const owner_name = try name.Name.init(owner);
    var labels: u8 = @intCast(owner_name.labelCount());
    if (owner_name.buf[0] == 1 and owner_name.buf[1] == '*') labels -%= 1;

    var signed: std.ArrayList(u8) = .empty;
    defer signed.deinit(allocator);
    try text.appendU16(&signed, allocator, rtype);
    try signed.append(allocator, key.algorithmNumber());
    try signed.append(allocator, labels);
    try text.appendU32(&signed, allocator, ttl);
    try text.appendU32(&signed, allocator, expiration);
    try text.appendU32(&signed, allocator, inception);
    try text.appendU16(&signed, allocator, key_tag);
    try signed.appendSlice(allocator, z.origin_wire);

    // RFC 4034 section 6.3 canonical RR form.  Our RDATA is already canonical
    // (uncompressed, lowercase names); the RRset is sorted by RDATA.
    var sorted: std.ArrayList([]const u8) = .empty;
    defer sorted.deinit(allocator);
    try sorted.appendSlice(allocator, rdatas);
    std.mem.sort([]const u8, sorted.items, {}, rdataLess);

    for (sorted.items) |rd| {
        try signed.appendSlice(allocator, owner);
        try text.appendU16(&signed, allocator, rtype);
        try text.appendU16(&signed, allocator, z.class);
        try text.appendU32(&signed, allocator, ttl);
        try text.appendU16(&signed, allocator, @intCast(rd.len));
        try signed.appendSlice(allocator, rd);
    }

    const signature = try key.sign(allocator, signed.items);
    defer allocator.free(signature);

    var rrsig: std.ArrayList(u8) = .empty;
    errdefer rrsig.deinit(allocator);
    try rrsig.appendSlice(allocator, signed.items[0 .. 18 + z.origin_wire.len]);
    try rrsig.appendSlice(allocator, signature);

    return .{
        .owner = owner,
        .rtype = types.RRSIG,
        .class = z.class,
        .ttl = ttl,
        .rdata = try rrsig.toOwnedSlice(allocator),
    };
}

fn rdataLess(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

test "sign a small zone" {
    const sema = @import("../zone/sema.zig");
    const allocator = std.testing.allocator;
    const src =
        \\$TTL 3600
        \\@ SOA ns. hostmaster. 1 1h 15m 1w 5m
        \\@ NS ns.
        \\ns A 192.0.2.1
        \\www A 192.0.2.2
        \\
    ;
    var z = try sema.loadSource(allocator, std.testing.io, src, "t.zone", .{
        .origin = try name.parseText("example.com.", null),
    });
    defer z.deinit();

    const pem = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "testdata/test-ecdsa.pem", allocator, .limited(1 << 20));
    defer allocator.free(pem);
    var key = try openssl.Key.loadPem(allocator, pem);
    defer key.deinit(allocator);

    const recs = try signZone(allocator, &z, &key, .{});
    defer {
        for (recs) |r| {
            if (r.rtype == types.DNSKEY or r.rtype == types.RRSIG or r.rtype == types.NSEC) {
                allocator.free(r.rdata);
            }
        }
        allocator.free(recs);
    }
    var count_dnskey: usize = 0;
    var count_rrsig: usize = 0;
    var count_nsec: usize = 0;
    for (recs) |r| switch (r.rtype) {
        types.DNSKEY => count_dnskey += 1,
        types.RRSIG => count_rrsig += 1,
        types.NSEC => count_nsec += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 2), count_dnskey);
    try std.testing.expect(count_rrsig >= 5);
    try std.testing.expect(count_nsec >= 3);
}
