//! RFC 2136 Dynamic Update, applied to an immutable zone snapshot.
//!
//! The caller writes the resulting record set to a temporary master file and
//! reloads it through the normal semantic analyser, so all SOA/NS/CNAME and
//! DNSSEC checks run exactly as they do for a hand-edited zone.

const std = @import("std");
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");
const message = @import("../dns/message.zig");
const zone = @import("../zone/zone.zig");
const secondary = @import("secondary.zig");

pub const Outcome = union(enum) {
    ok: []zone.Record,
    rcode: types.Rcode,
};

pub fn apply(
    allocator: std.mem.Allocator,
    z: *const zone.Zone,
    msg: *const message.Message,
    strip_dnssec: bool,
) !Outcome {
    var recs: std.ArrayList(zone.Record) = .empty;
    errdefer recs.deinit(allocator);

    const flat = try zone.flatten(z, allocator);
    defer allocator.free(flat);
    for (flat) |r| {
        if (strip_dnssec and isDnssecType(r.rtype)) continue;
        try recs.append(allocator, .{
            .owner = try allocator.dupe(u8, r.owner),
            .rtype = r.rtype,
            .class = r.class,
            .ttl = r.ttl,
            .rdata = try allocator.dupe(u8, r.rdata),
        });
    }

    // Prerequisites (answer section).
    for (msg.answers) |rr| {
        var owner = rr.owner;
        name.lowerInPlace(owner.buf[0..owner.len]);
        const owner_wire = owner.slice();
        if (rr.class == types.class_any) {
            if (rr.ttl != 0 or rr.rdata.len != 0) return .{ .rcode = .formerr };
            if (rr.rtype == types.ANY) {
                if (!z.hasName(owner_wire)) return .{ .rcode = .nxdomain };
            } else if (z.rrsetAt(owner_wire, rr.rtype) == null) {
                return .{ .rcode = .nxrrset };
            }
        } else if (rr.class == types.class_none) {
            if (rr.ttl != 0 or rr.rdata.len != 0) return .{ .rcode = .formerr };
            if (rr.rtype == types.ANY) {
                if (z.hasName(owner_wire)) return .{ .rcode = .yxdomain };
            } else if (z.rrsetAt(owner_wire, rr.rtype) != null) {
                return .{ .rcode = .yxrrset };
            }
        } else {
            if (rr.ttl != 0 or rr.rdata.len == 0) return .{ .rcode = .formerr };
            const raw = try secondary.normalizeRecord(allocator, msg.raw, rr);
            defer allocator.free(raw.rdata);
            defer allocator.free(raw.owner);
            const set = z.rrsetAt(owner_wire, rr.rtype) orelse return .{ .rcode = .nxrrset };
            var found = false;
            for (set.rdata) |rd| {
                if (std.mem.eql(u8, rd, raw.rdata)) {
                    found = true;
                    break;
                }
            }
            if (!found) return .{ .rcode = .nxrrset };
        }
    }

    // Update section (authority).
    for (msg.authority) |rr| {
        var owner = rr.owner;
        name.lowerInPlace(owner.buf[0..owner.len]);
        const owner_wire = owner.slice();
        if (!owner.isSubdomainOf(&z.origin)) return .{ .rcode = .notzone };
        if (rr.class == types.class_in) {
            if (rr.rdata.len == 0) return .{ .rcode = .formerr };
            if (isDnssecType(rr.rtype)) return .{ .rcode = .refused };
            const raw = try secondary.normalizeRecord(allocator, msg.raw, rr);
            defer allocator.free(raw.owner);
            defer allocator.free(raw.rdata);
            try addRecord(&recs, allocator, owner_wire, rr.rtype, rr.ttl, raw.rdata);
        } else if (rr.class == types.class_any) {
            if (rr.ttl != 0 or rr.rdata.len != 0) return .{ .rcode = .formerr };
            if (rr.rtype == types.ANY) {
                removeName(&recs, owner_wire);
            } else {
                removeRRset(&recs, owner_wire, rr.rtype);
            }
        } else if (rr.class == types.class_none) {
            if (rr.ttl != 0 or rr.rdata.len == 0) return .{ .rcode = .formerr };
            const raw = try secondary.normalizeRecord(allocator, msg.raw, rr);
            defer allocator.free(raw.owner);
            defer allocator.free(raw.rdata);
            removeRR(&recs, owner_wire, rr.rtype, raw.rdata);
        } else {
            return .{ .rcode = .formerr };
        }
    }

    // Bump the SOA serial.
    var soa_index: ?usize = null;
    for (recs.items, 0..) |r, i| {
        if (r.rtype == types.SOA and std.mem.eql(u8, r.owner, z.origin_wire)) {
            soa_index = i;
            break;
        }
    }
    const si = soa_index orelse return .{ .rcode = .formerr };
    const new_serial = zone.appendSerial(zone.soaSerial(recs.items[si].rdata) orelse z.serial);
    recs.items[si].rdata = try zone.soaWithSerial(allocator, recs.items[si].rdata, new_serial);

    return .{ .ok = try recs.toOwnedSlice(allocator) };
}

fn isDnssecType(t: u16) bool {
    return t == types.RRSIG or t == types.NSEC or t == types.NSEC3 or
        t == types.NSEC3PARAM or t == types.DNSKEY;
}

fn addRecord(out: *std.ArrayList(zone.Record), allocator: std.mem.Allocator, owner: []const u8, rtype: u16, ttl: u32, rd: []const u8) !void {
    var i: usize = 0;
    while (i < out.items.len) : (i += 1) {
        const r = out.items[i];
        if (r.rtype == rtype and std.mem.eql(u8, r.owner, owner) and std.mem.eql(u8, r.rdata, rd)) return;
    }
    try out.append(allocator, .{
        .owner = try allocator.dupe(u8, owner),
        .rtype = rtype,
        .class = types.class_in,
        .ttl = ttl,
        .rdata = try allocator.dupe(u8, rd),
    });
}

fn removeName(out: *std.ArrayList(zone.Record), owner: []const u8) void {
    var i: usize = 0;
    while (i < out.items.len) {
        if (std.mem.eql(u8, out.items[i].owner, owner)) {
            _ = out.orderedRemove(i);
        } else {
            i += 1;
        }
    }
}

fn removeRRset(out: *std.ArrayList(zone.Record), owner: []const u8, rtype: u16) void {
    var i: usize = 0;
    while (i < out.items.len) {
        const r = out.items[i];
        if (r.rtype == rtype and std.mem.eql(u8, r.owner, owner)) {
            _ = out.orderedRemove(i);
        } else {
            i += 1;
        }
    }
}

fn removeRR(out: *std.ArrayList(zone.Record), owner: []const u8, rtype: u16, rd: []const u8) void {
    var i: usize = 0;
    while (i < out.items.len) {
        const r = out.items[i];
        if (r.rtype == rtype and std.mem.eql(u8, r.owner, owner) and std.mem.eql(u8, r.rdata, rd)) {
            _ = out.orderedRemove(i);
            return;
        }
        i += 1;
    }
}
