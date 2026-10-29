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
const nsec3 = @import("../dns/nsec3.zig");

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
    /// When set, generate an NSEC3 chain instead of NSEC.
    nsec3: ?nsec3.Params = null,
};

/// Adds DNSKEY, NSEC and RRSIG records to `z` and returns the complete record
/// list.  Owner/RDATA slices of the original records reference `z`; the zone
/// must outlive the returned array (it is consumed by Zone.build, which
/// copies).
pub const SigningKey = struct {
    key: *const openssl.Key,
    flags: u16,
};

const KeyInfo = struct {
    key: *const openssl.Key,
    flags: u16,
    rdata: []const u8,
    tag: u16,
};

pub fn signZone(
    allocator: std.mem.Allocator,
    z: *const zone.Zone,
    keys: []const SigningKey,
    opts: Options,
) ![]zone.Record {
    if (keys.len == 0) return error.NoKeys;
    const now: u32 = @truncate(@as(u64, @bitCast(time(null))));
    const inception = opts.inception orelse (now -% opts.inception_skew);
    const expiration = opts.expiration orelse (now +% opts.validity);
    const dnskey_ttl = opts.dnskey_ttl orelse z.soa.ttl;
    const nsec_ttl = opts.nsec_ttl orelse z.negative_ttl;

    var infos = try allocator.alloc(KeyInfo, keys.len);
    defer allocator.free(infos);
    for (keys, 0..) |k, i| {
        const rd = try openssl.dnskeyRdata(allocator, k.flags, k.key);
        infos[i] = .{
            .key = k.key,
            .flags = k.flags,
            .rdata = rd,
            .tag = openssl.keyTag(rd),
        };
    }

    var ksk_idx: std.ArrayList(usize) = .empty;
    defer ksk_idx.deinit(allocator);
    var zsk_idx: std.ArrayList(usize) = .empty;
    defer zsk_idx.deinit(allocator);
    for (infos, 0..) |k, i| {
        if (k.flags & 0x8000 != 0) {
            try ksk_idx.append(allocator, i);
        } else {
            try zsk_idx.append(allocator, i);
        }
    }
    if (ksk_idx.items.len == 0) for (infos, 0..) |_, i| try ksk_idx.append(allocator, i);
    if (zsk_idx.items.len == 0) for (infos, 0..) |_, i| try zsk_idx.append(allocator, i);

    var out: std.ArrayList(zone.Record) = .empty;
    errdefer out.deinit(allocator);

    // 1. Original records.
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

    // 2. DNSKEY RRset (all published keys).
    for (infos) |k| {
        try out.append(allocator, .{
            .owner = z.origin_wire,
            .rtype = types.DNSKEY,
            .class = z.class,
            .ttl = dnskey_ttl,
            .rdata = k.rdata,
        });
    }
    var dnskeys = try allocator.alloc([]const u8, infos.len);
    defer allocator.free(dnskeys);
    for (infos, 0..) |k, i| dnskeys[i] = k.rdata;

    // 3. NSEC or NSEC3 denial chain.
    var nameset: std.StringHashMapUnmanaged(void) = .{};
    defer nameset.deinit(allocator);
    for (z.allRRsets()) |*rs| {
        if (isAuthoritativeRRset(z, rs.owner, rs.rtype)) try nameset.put(allocator, rs.owner, {});
    }
    try nameset.put(allocator, z.origin_wire, {});
    var sorted_list: std.ArrayList([]const u8) = .empty;
    defer sorted_list.deinit(allocator);
    var it = nameset.iterator();
    while (it.next()) |entry| try sorted_list.append(allocator, entry.key_ptr.*);
    const sorted = try sorted_list.toOwnedSlice(allocator);
    defer allocator.free(sorted);
    std.mem.sort([]const u8, sorted, {}, nameLess);

    var denial: std.ArrayList(zone.Record) = .empty;
    defer denial.deinit(allocator);

    if (opts.nsec3) |params| {
        var param_rdata: std.ArrayList(u8) = .empty;
        defer param_rdata.deinit(allocator);
        try param_rdata.append(allocator, 1);
        try param_rdata.append(allocator, params.flags);
        try appendU16(&param_rdata, allocator, params.iterations);
        if (params.salt.len > 255) return error.InvalidSoa;
        try param_rdata.append(allocator, @intCast(params.salt.len));
        try param_rdata.appendSlice(allocator, params.salt);
        try denial.append(allocator, .{
            .owner = z.origin_wire,
            .rtype = types.NSEC3PARAM,
            .class = z.class,
            .ttl = nsec_ttl,
            .rdata = try param_rdata.toOwnedSlice(allocator),
        });

        var n3owners: std.ArrayList([]const u8) = .empty;
        defer n3owners.deinit(allocator);
        var nit = z.names.iterator();
        while (nit.next()) |mentry| {
            const nm = mentry.key_ptr.*;
            if (z.findDelegation(nm)) |deleg| {
                if (!std.mem.eql(u8, nm, deleg)) continue;
                // RFC 5155 Opt-Out: omit insecure delegations from the chain.
                if (params.opt_out and z.rrsetAt(nm, types.DS) == null) continue;
            }
            try n3owners.append(allocator, nm);
        }
        const n3sorted = try n3owners.toOwnedSlice(allocator);
        defer allocator.free(n3sorted);
        std.mem.sort([]const u8, n3sorted, {}, nameLess);

        var entries: std.ArrayList(Nsec3Entry) = .empty;
        defer entries.deinit(allocator);
        for (n3sorted) |owner| {
            var h: [nsec3.hash_len]u8 = undefined;
            try nsec3.hashName(owner, params, &h);
            var hname: name.Name = undefined;
            const ho = try nsec3.makeOwner(&h, z.origin_wire, &hname);
            try entries.append(allocator, .{
                .original = owner,
                .hashed_owner = try allocator.dupe(u8, ho),
                .hash = h,
            });
        }
        std.mem.sort(Nsec3Entry, entries.items, {}, nsec3EntryLess);

        for (entries.items, 0..) |*e, i| {
            const next = entries.items[(i + 1) % entries.items.len].hash;
            var rd: std.ArrayList(u8) = .empty;
            defer rd.deinit(allocator);
            try rd.append(allocator, 1);
            // BIND-compatible: every NSEC3 in an opt-out chain carries the
            // Opt-Out flag.  This is conservative and lets validators handle
            // any omitted delegation.
            try rd.append(allocator, if (params.opt_out) 1 else params.flags);
            try appendU16(&rd, allocator, params.iterations);
            try rd.append(allocator, @intCast(params.salt.len));
            try rd.appendSlice(allocator, params.salt);
            try rd.append(allocator, nsec3.hash_len);
            try rd.appendSlice(allocator, &next);
            var tlist: std.ArrayList(u16) = .empty;
            defer tlist.deinit(allocator);
            try nsec3Types(z, e.original, &tlist, allocator);
            try rdata.encodeTypeBitmap(&rd, allocator, tlist.items);
            try denial.append(allocator, .{
                .owner = e.hashed_owner,
                .rtype = types.NSEC3,
                .class = z.class,
                .ttl = nsec_ttl,
                .rdata = try rd.toOwnedSlice(allocator),
            });
        }
    } else {
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
            try denial.append(allocator, .{
                .owner = owner,
                .rtype = types.NSEC,
                .class = z.class,
                .ttl = nsec_ttl,
                .rdata = try rd.toOwnedSlice(allocator),
            });
        }
    }
    for (denial.items) |r| try out.append(allocator, r);

    // 4. Sign ordinary RRsets with every ZSK.
    for (z.allRRsets()) |*rs| {
        if (!isSignableRRset(z, rs.owner, rs.rtype)) continue;
        for (zsk_idx.items) |ki| {
            const k = infos[ki];
            const sig = try makeRrsig(allocator, z, rs.owner, rs.rtype, rs.ttl, rs.rdata, k.key, k.tag, inception, expiration);
            try out.append(allocator, sig);
        }
    }

    // 5. Sign the DNSKEY RRset with every KSK.
    for (ksk_idx.items) |ki| {
        const k = infos[ki];
        const sig = try makeRrsig(allocator, z, z.origin_wire, types.DNSKEY, dnskey_ttl, dnskeys, k.key, k.tag, inception, expiration);
        try out.append(allocator, sig);
    }

    // 6. Sign the denial records with every ZSK.
    for (denial.items) |*nr| {
        const rdatas = [_][]const u8{nr.rdata};
        for (zsk_idx.items) |ki| {
            const k = infos[ki];
            const sig = try makeRrsig(allocator, z, nr.owner, nr.rtype, nr.ttl, &rdatas, k.key, k.tag, inception, expiration);
            try out.append(allocator, sig);
        }
    }

    return out.toOwnedSlice(allocator);
}

const Nsec3Entry = struct {
    original: []const u8,
    hashed_owner: []const u8,
    hash: [nsec3.hash_len]u8,
};

fn nsec3EntryLess(_: void, a: Nsec3Entry, b: Nsec3Entry) bool {
    return std.mem.order(u8, &a.hash, &b.hash) == .lt;
}

fn nsec3Types(z: *const zone.Zone, owner: []const u8, tlist: *std.ArrayList(u16), allocator: std.mem.Allocator) !void {
    const deleg = isDelegationOwner(z, owner);
    var any = false;
    var has_ds = false;
    for (z.rrsetsAt(owner)) |idx| {
        const rs = &z.rrsets[idx];
        if (!isAuthoritativeRRset(z, owner, rs.rtype)) continue;
        if (deleg and rs.rtype != types.NS and rs.rtype != types.DS) continue;
        try tlist.append(allocator, rs.rtype);
        any = true;
        if (rs.rtype == types.DS) has_ds = true;
    }
    if (!any) return;
    if (deleg) {
        if (has_ds) try tlist.append(allocator, types.RRSIG);
        return;
    }
    try tlist.append(allocator, types.RRSIG);
    if (std.mem.eql(u8, owner, z.origin_wire)) {
        try tlist.append(allocator, types.DNSKEY);
        try tlist.append(allocator, types.NSEC3PARAM);
    }
}

fn appendU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u16) !void {
    try out.append(allocator, @intCast(v >> 8));
    try out.append(allocator, @intCast(v & 0xff));
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

    const keys = [_]SigningKey{
        .{ .key = &key, .flags = 257 },
        .{ .key = &key, .flags = 256 },
    };
    const recs = try signZone(allocator, &z, &keys, .{});
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
