//! Immutable, indexed zone database.
//!
//! Records are sorted in RFC 4034 canonical order and grouped into RRsets.
//! Lookups are O(1) in the number of names.  The zone owns an arena; after
//! construction all state is immutable and safe for concurrent readers.

const std = @import("std");
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");
const nsec3 = @import("../dns/nsec3.zig");

pub const Record = struct {
    owner: []const u8,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: []const u8,
    line: u32 = 0,
};

pub const RRset = struct {
    owner: []const u8,
    rtype: u16,
    ttl: u32,
    rdata: []const []const u8,
    /// For RRSIG RRsets, the covered type.  RRSIGs are not a conventional
    /// RRset (RFC 4035 section 2.2), so signatures for different covered
    /// types must retain their own TTL and be selectable independently.
    covered: ?u16 = null,

    pub fn count(rs: *const RRset) usize {
        return rs.rdata.len;
    }
};

pub const BuildError = error{
    MissingSoa,
    MultipleSoa,
    MissingNs,
    InvalidSoa,
    OutOfZone,
    BadWildcard,
    TooManyRecords,
    BadTtl,
    RdataTooLong,
    WrongClass,
    MetaType,
} || std.mem.Allocator.Error;

pub const Zone = struct {
    arena: std.heap.ArenaAllocator,
    origin: name.Name,
    origin_wire: []const u8,
    class: u16,
    rrsets: []RRset,
    index: std.StringHashMapUnmanaged([]const u32),
    names: std.StringHashMapUnmanaged(void),
    delegations: std.StringHashMapUnmanaged(void),
    soa: RRset,
    serial: u32,
    minimum: u32,
    refresh: u32,
    retry: u32,
    negative_ttl: u32,
    signed: bool,
    warnings: []const []const u8,
    record_count: usize,
    nsec_names: []const []const u8,
    nsec3_names: []const []const u8,
    nsec3_params: ?nsec3.Params,

    pub fn deinit(z: *Zone) void {
        z.arena.deinit();
    }

    /// Builds a zone from raw records.  All record data is copied into the
    /// zone's arena, so the input may be freed afterwards.
    pub fn build(
        backing: std.mem.Allocator,
        origin_in: name.Name,
        class: u16,
        raw: []const Record,
        warnings_in: []const []const u8,
    ) BuildError!Zone {
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();

        var origin = origin_in;
        name.lowerInPlace(origin.buf[0..origin.len]);
        const origin_wire = try a.dupe(u8, origin.slice());

        const recs = try a.alloc(Record, raw.len);
        for (raw, 0..) |r, i| {
            if (r.ttl > 0x7fffffff) return error.BadTtl;
            if (r.rdata.len > 65535) return error.RdataTooLong;
            if (r.class != class) return error.WrongClass;
            if (types.isMetaType(r.rtype)) return error.MetaType;
            const owner_name = name.Name.init(r.owner) catch return error.OutOfZone;
            if (!owner_name.isSubdomainOf(&origin)) return error.OutOfZone;
            recs[i] = .{
                .owner = try a.dupe(u8, r.owner),
                .rtype = r.rtype,
                .class = r.class,
                .ttl = r.ttl,
                .rdata = try a.dupe(u8, r.rdata),
                .line = r.line,
            };
        }
        std.mem.sort(Record, recs, {}, recordLess);

        var warnings: std.ArrayList([]const u8) = .empty;
        for (warnings_in) |w| try warnings.append(a, try a.dupe(u8, w));

        var rrlist: std.ArrayList(RRset) = .empty;
        var i: usize = 0;
        while (i < recs.len) {
            const owner = recs[i].owner;
            const rtype = recs[i].rtype;
            const ttl = recs[i].ttl;
            const covered = if (rtype == types.RRSIG) rrsigCoveredOrZero(recs[i].rdata) else null;
            var j = i + 1;
            var rd: std.ArrayList([]const u8) = .empty;
            try rd.append(a, recs[i].rdata);
            var ttl_warned = false;
            while (j < recs.len and std.mem.eql(u8, recs[j].owner, owner) and recs[j].rtype == rtype and
                (if (rtype == types.RRSIG)
                    rrsigCoveredOrZero(recs[j].rdata) == (covered orelse 0)
                else
                    true))
            {
                if (recs[j].ttl != ttl and !ttl_warned) {
                    ttl_warned = true;
                    try warnings.append(a, try std.fmt.allocPrint(a, "line {d}: RRset TTL {d} differs from first TTL {d}; using {d}", .{ recs[j].line, recs[j].ttl, ttl, ttl }));
                }
                // Sorted by RDATA, so duplicates are adjacent.  RFC 2181
                // section 5: an RRset is a set; duplicates are dropped.
                if (!std.mem.eql(u8, recs[j].rdata, recs[j - 1].rdata)) {
                    try rd.append(a, recs[j].rdata);
                }
                j += 1;
            }
            try rrlist.append(a, .{
                .owner = owner,
                .rtype = rtype,
                .ttl = ttl,
                .rdata = try rd.toOwnedSlice(a),
                .covered = covered,
            });
            i = j;
        }
        const rrsets = try rrlist.toOwnedSlice(a);

        var soa_set: ?RRset = null;
        var has_ns_apex = false;
        for (rrsets) |*rs| {
            if (rs.rtype == types.SOA and std.mem.eql(u8, rs.owner, origin_wire)) {
                if (soa_set != null) return error.MultipleSoa;
                if (rs.rdata.len != 1) return error.MultipleSoa;
                soa_set = rs.*;
            }
            if (rs.rtype == types.NS and std.mem.eql(u8, rs.owner, origin_wire)) has_ns_apex = true;
        }
        const soa = soa_set orelse return error.MissingSoa;
        if (!has_ns_apex) return error.MissingNs;
        const serial = soaSerial(soa.rdata[0]) orelse return error.InvalidSoa;
        const minimum = soaMinimum(soa.rdata[0]) orelse return error.InvalidSoa;
        const refresh = soaRefresh(soa.rdata[0]) orelse 3600;
        const retry = soaRetry(soa.rdata[0]) orelse 600;
        const negative_ttl = @min(soa.ttl, minimum);

        var names: std.StringHashMapUnmanaged(void) = .{};
        var delegations: std.StringHashMapUnmanaged(void) = .{};
        for (rrsets) |*rs| {
            try names.put(a, rs.owner, {});
            if (rs.rtype == types.NS and !std.mem.eql(u8, rs.owner, origin_wire)) {
                try delegations.put(a, rs.owner, {});
            }
            var cur = name.Name.init(rs.owner) catch continue;
            while (cur.parent()) |p| {
                if (!p.isSubdomainOf(&origin)) break;
                const key = try a.dupe(u8, p.slice());
                try names.put(a, key, {});
                if (p.eql(&origin)) break;
                cur = p;
            }
        }

        var tmp: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(u32)) = .{};
        for (rrsets, 0..) |*rs, idx| {
            const gop = try tmp.getOrPut(a, rs.owner);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(a, @intCast(idx));
        }
        var index: std.StringHashMapUnmanaged([]const u32) = .{};
        var it = tmp.iterator();
        while (it.next()) |entry| {
            try index.put(a, entry.key_ptr.*, try a.dupe(u32, entry.value_ptr.items));
        }

        var record_count: usize = 0;
        var signed = false;
        var nsec_list: std.ArrayList([]const u8) = .empty;
        var nsec3_list: std.ArrayList([]const u8) = .empty;
        var nsec3_params: ?nsec3.Params = null;
        for (rrsets) |*rs| {
            record_count += rs.rdata.len;
            if (rs.rtype == types.DNSKEY and std.mem.eql(u8, rs.owner, origin_wire)) signed = true;
            if (rs.rtype == types.NSEC) try nsec_list.append(a, rs.owner);
            if (rs.rtype == types.NSEC3) {
                try nsec3_list.append(a, rs.owner);
                if (rs.rdata.len > 0) {
                    if (nsec3.paramsFromRdata(rs.rdata[0])) |p| {
                        if (nsec3_params) |*cur| {
                            cur.opt_out = cur.opt_out or p.opt_out;
                        } else {
                            nsec3_params = p;
                        }
                    }
                }
            }
            if (rs.rtype == types.NSEC3PARAM and std.mem.eql(u8, rs.owner, origin_wire) and rs.rdata.len > 0) {
                if (nsec3.paramsFromRdata(rs.rdata[0])) |p| {
                    if (nsec3_params) |*cur| {
                        cur.flags = p.flags;
                        cur.iterations = p.iterations;
                        cur.salt = p.salt;
                        cur.opt_out = cur.opt_out or p.opt_out;
                    } else {
                        nsec3_params = p;
                    }
                }
            }
        }
        const nsec_names = try nsec_list.toOwnedSlice(a);
        std.mem.sort([]const u8, nsec_names, {}, nsecLess);
        const nsec3_names = try nsec3_list.toOwnedSlice(a);
        std.mem.sort([]const u8, nsec3_names, {}, nsecLess);

        return .{
            .arena = arena,
            .origin = origin,
            .origin_wire = origin_wire,
            .class = class,
            .rrsets = rrsets,
            .index = index,
            .names = names,
            .delegations = delegations,
            .soa = soa,
            .serial = serial,
            .minimum = minimum,
            .refresh = refresh,
            .retry = retry,
            .negative_ttl = negative_ttl,
            .signed = signed,
            .warnings = try warnings.toOwnedSlice(a),
            .record_count = record_count,
            .nsec_names = nsec_names,
            .nsec3_names = nsec3_names,
            .nsec3_params = nsec3_params,
        };
    }

    pub fn isSigned(z: *const Zone) bool {
        return z.signed;
    }

    pub fn setSigned(z: *Zone, v: bool) void {
        z.signed = v;
    }

    pub fn normalize(qname: []const u8, buf: *[name.max_name_len]u8) []const u8 {
        @memcpy(buf[0..qname.len], qname);
        name.lowerInPlace(buf[0..qname.len]);
        return buf[0..qname.len];
    }

    pub fn hasName(z: *const Zone, qname_lower: []const u8) bool {
        return z.names.contains(qname_lower);
    }

    pub fn isDelegation(z: *const Zone, qname_lower: []const u8) bool {
        return z.delegations.contains(qname_lower);
    }

    pub fn rrsetAt(z: *const Zone, qname_lower: []const u8, rtype: u16) ?*const RRset {
        const list = z.index.get(qname_lower) orelse return null;
        for (list) |idx| {
            const rs = &z.rrsets[idx];
            if (rs.rtype == rtype) return rs;
        }
        return null;
    }

    pub fn rrsetsAt(z: *const Zone, qname_lower: []const u8) []const u32 {
        return z.index.get(qname_lower) orelse &.{};
    }

    /// Finds the closest delegation at or above `qname_lower`, stopping at the
    /// zone apex.  Returns the delegation name (arena-owned).
    pub fn findDelegation(z: *const Zone, qname_lower: []const u8) ?[]const u8 {
        var cur = name.Name.init(qname_lower) catch return null;
        while (true) {
            const s = cur.slice();
            if (!std.mem.eql(u8, s, z.origin_wire) and z.delegations.contains(s)) {
                return z.delegations.getKey(s);
            }
            if (std.mem.eql(u8, s, z.origin_wire)) return null;
            cur = cur.parent() orelse return null;
        }
    }

    /// RFC 4592 closest encloser: the longest existing ancestor of qname,
    /// including empty non-terminals.  The zone apex always exists.
    pub fn closestEncloser(z: *const Zone, qname_lower: []const u8) ?[]const u8 {
        var cur = name.Name.init(qname_lower) catch return null;
        while (true) {
            const s = cur.slice();
            if (z.names.contains(s)) return z.names.getKey(s);
            if (std.mem.eql(u8, s, z.origin_wire)) return z.origin_wire;
            cur = cur.parent() orelse return null;
        }
    }

    pub fn makeWildcard(closest: []const u8, buf: *[name.max_name_len]u8) ?[]const u8 {
        if (closest.len + 2 > name.max_name_len) return null;
        buf[0] = 1;
        buf[1] = '*';
        @memcpy(buf[2..][0..closest.len], closest);
        return buf[0 .. 2 + closest.len];
    }

    pub fn sigRRsetFor(z: *const Zone, qname_lower: []const u8, covered: u16) ?*const RRset {
        const list = z.index.get(qname_lower) orelse return null;
        for (list) |idx| {
            const rs = &z.rrsets[idx];
            if (rs.rtype == types.RRSIG and rs.covered == covered) return rs;
        }
        return null;
    }

    pub fn nsec3At(z: *const Zone, owner: []const u8) ?*const RRset {
        return z.rrsetAt(owner, types.NSEC3);
    }

    pub fn nsec3Covering(z: *const Zone, owner: []const u8) ?*const RRset {
        if (z.nsec3_names.len == 0) return null;
        var lo: usize = 0;
        var hi: usize = z.nsec3_names.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (name.Name.canonicalCompareWire(z.nsec3_names[mid], owner) != .gt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        const idx = if (lo == 0) z.nsec3_names.len - 1 else lo - 1;
        return z.rrsetAt(z.nsec3_names[idx], types.NSEC3);
    }

    pub fn nsec3Params(z: *const Zone) ?nsec3.Params {
        return z.nsec3_params;
    }

    pub fn allRRsets(z: *const Zone) []const RRset {
        return z.rrsets;
    }

    pub fn nsecAt(z: *const Zone, qname_lower: []const u8) ?*const RRset {
        return z.rrsetAt(qname_lower, types.NSEC);
    }

    /// Returns the NSEC RRset whose owner canonically precedes `qname_lower`
    /// (wrapping from the last name to the apex).
    pub fn nsecCovering(z: *const Zone, qname_lower: []const u8) ?*const RRset {
        if (z.nsec_names.len == 0) return null;
        var lo: usize = 0;
        var hi: usize = z.nsec_names.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (name.Name.canonicalCompareWire(z.nsec_names[mid], qname_lower) != .gt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        const idx = if (lo == 0) z.nsec_names.len - 1 else lo - 1;
        return z.rrsetAt(z.nsec_names[idx], types.NSEC);
    }

    pub fn soaRdata(z: *const Zone) []const u8 {
        return z.soa.rdata[0];
    }

    pub fn negativeTtl(z: *const Zone) u32 {
        return z.negative_ttl;
    }

    pub fn serialNumber(z: *const Zone) u32 {
        return z.serial;
    }

    pub fn recordCount(z: *const Zone) usize {
        return z.record_count;
    }
};

fn rrsigCoveredOrZero(rdata: []const u8) u16 {
    if (rdata.len < 2) return 0;
    return (@as(u16, rdata[0]) << 8) | rdata[1];
}

fn nsecLess(_: void, a: []const u8, b: []const u8) bool {
    return name.Name.canonicalCompareWire(a, b) == .lt;
}

fn recordLess(_: void, a: Record, b: Record) bool {
    const ord = name.Name.canonicalCompareWire(a.owner, b.owner);
    if (ord != .eq) return ord == .lt;
    if (a.rtype != b.rtype) return a.rtype < b.rtype;
    return std.mem.order(u8, a.rdata, b.rdata) == .lt;
}

pub fn soaSerial(rdata: []const u8) ?u32 {
    var n: name.Name = undefined;
    var off = name.parseWire(rdata, 0, &n) catch return null;
    off = name.parseWire(rdata, off, &n) catch return null;
    if (off + 20 > rdata.len) return null;
    return readU32(rdata, off);
}

pub fn soaMinimum(rdata: []const u8) ?u32 {
    var n: name.Name = undefined;
    var off = name.parseWire(rdata, 0, &n) catch return null;
    off = name.parseWire(rdata, off, &n) catch return null;
    if (off + 20 > rdata.len) return null;
    return readU32(rdata, off + 16);
}

pub fn soaRefresh(rdata: []const u8) ?u32 {
    var n: name.Name = undefined;
    var off = name.parseWire(rdata, 0, &n) catch return null;
    off = name.parseWire(rdata, off, &n) catch return null;
    if (off + 8 > rdata.len) return null;
    return readU32(rdata, off + 4);
}

pub fn soaRetry(rdata: []const u8) ?u32 {
    var n: name.Name = undefined;
    var off = name.parseWire(rdata, 0, &n) catch return null;
    off = name.parseWire(rdata, off, &n) catch return null;
    if (off + 12 > rdata.len) return null;
    return readU32(rdata, off + 8);
}

/// Flattens all RRsets into individual records.  Owner/RDATA slices point
/// into the zone arena.
pub fn flatten(z: *const Zone, allocator: std.mem.Allocator) ![]Record {
    var out: std.ArrayList(Record) = .empty;
    errdefer out.deinit(allocator);
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
    return out.toOwnedSlice(allocator);
}

pub fn soaWithSerial(allocator: std.mem.Allocator, soa_rdata: []const u8, serial: u32) ![]u8 {
    var n: name.Name = undefined;
    var off = try name.parseWire(soa_rdata, 0, &n);
    off = try name.parseWire(soa_rdata, off, &n);
    if (off + 20 > soa_rdata.len) return error.InvalidSoa;
    const out = try allocator.dupe(u8, soa_rdata);
    std.mem.writeInt(u32, out[off..][0..4], serial, .big);
    return out;
}

pub fn appendSerial(serial: u32) u32 {
    if (serial == 0x7fffffff) return 1;
    return serial + 1;
}

pub fn writeRecords(records: []const Record, allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const w = &aw.writer;
    for (records) |r| {
        var owner_name = name.Name.init(r.owner) catch continue;
        try owner_name.writeText(w);
        var tbuf: [12]u8 = undefined;
        try w.print("\t{d}\tIN\t{s}\t", .{ r.ttl, types.typeToTextBuf(r.rtype, &tbuf) });
        try @import("../dns/rdata.zig").toText(allocator, r.rtype, r.rdata, w);
        try w.writeByte('\n');
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = aw.written() });
}

/// Writes the zone in BIND master-file form.  Complex/unknown RDATA is
/// emitted with the RFC 3597 \# representation, so the output reloads
/// losslessly even for types without a presentation formatter.
pub fn writeFile(z: *const Zone, allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    const w = &aw.writer;
    for (z.allRRsets()) |*rs| {
        var owner_name = name.Name.init(rs.owner) catch continue;
        for (rs.rdata) |rd| {
            try owner_name.writeText(w);
            var tbuf: [12]u8 = undefined;
            try w.print("\t{d}\tIN\t{s}\t", .{ rs.ttl, types.typeToTextBuf(rs.rtype, &tbuf) });
            try @import("../dns/rdata.zig").toText(allocator, rs.rtype, rd, w);
            try w.writeByte('\n');
        }
    }
    const tmp = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp);
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = aw.written() }) catch |e| {
        std.Io.Dir.cwd().deleteFile(io, tmp) catch {};
        return e;
    };
    std.Io.Dir.cwd().rename(tmp, std.Io.Dir.cwd(), path, io) catch |e| {
        std.Io.Dir.cwd().deleteFile(io, tmp) catch {};
        return e;
    };
}

pub fn rrsigTypeCovered(rdata: []const u8) u16 {
    if (rdata.len < 2) return 0;
    return (@as(u16, rdata[0]) << 8) | rdata[1];
}

fn readU32(data: []const u8, off: usize) u32 {
    return (@as(u32, data[off]) << 24) | (@as(u32, data[off + 1]) << 16) |
        (@as(u32, data[off + 2]) << 8) | data[off + 3];
}

/// RFC 1982 serial comparison.  Returns true when `a` is newer than `b`.
pub fn serialGreater(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}

test "serial arithmetic" {
    try std.testing.expect(serialGreater(2, 1));
    try std.testing.expect(serialGreater(0, 0xffffffff));
    try std.testing.expect(!serialGreater(1, 2));
    try std.testing.expect(!serialGreater(5, 5));
}

test "wildcard name length" {
    var buf: [name.max_name_len]u8 = undefined;
    var too_long: [name.max_name_len - 1]u8 = undefined;
    @memset(&too_long, 0);
    try std.testing.expect(Zone.makeWildcard(&too_long, &buf) == null);
    var ok: [name.max_name_len - 2]u8 = undefined;
    @memset(&ok, 0);
    try std.testing.expect(Zone.makeWildcard(&ok, &buf) != null);
}
