//! IXFR journal (RFC 1995).
//!
//! Each journal entry is a pair of record lists between two SOA serials.  The
//! journal is kept in memory and may be persisted to a small append-style file
//! so that IXFR survives a restart.  Serial comparisons use RFC 1982
//! arithmetic.

const std = @import("std");
const zone = @import("zone.zig");
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");

pub const Delta = struct {
    from_serial: u32,
    to_serial: u32,
    removed: []zone.Record,
    added: []zone.Record,

    pub fn deinit(d: *Delta, allocator: std.mem.Allocator) void {
        for (d.removed) |r| freeRecord(allocator, r);
        for (d.added) |r| freeRecord(allocator, r);
        if (d.removed.len > 0) allocator.free(d.removed);
        if (d.added.len > 0) allocator.free(d.added);
        d.* = undefined;
    }

    pub fn byteSize(d: *const Delta) usize {
        var n: usize = 32;
        for (d.removed) |r| n += 16 + r.owner.len + r.rdata.len;
        for (d.added) |r| n += 16 + r.owner.len + r.rdata.len;
        return n;
    }
};

pub const Journal = struct {
    allocator: std.mem.Allocator,
    deltas: std.ArrayList(Delta) = .empty,
    max_deltas: usize = 1024,
    max_bytes: usize = 64 * 1024 * 1024,
    total_bytes: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Journal {
        return .{ .allocator = allocator };
    }

    pub fn deinit(j: *Journal) void {
        for (j.deltas.items) |*d| d.deinit(j.allocator);
        j.deltas.deinit(j.allocator);
        j.* = undefined;
    }

    pub fn append(j: *Journal, delta: Delta) !void {
        if (j.deltas.items.len > 0) {
            const last = &j.deltas.items[j.deltas.items.len - 1];
            if (last.to_serial != delta.from_serial) {
                // A serial reset or a gap means old deltas can no longer form a
                // contiguous IXFR chain.  Start a new journal epoch.
                j.clear();
            }
        }
        j.total_bytes += delta.byteSize();
        try j.deltas.append(j.allocator, delta);
        while (j.deltas.items.len > j.max_deltas or j.total_bytes > j.max_bytes) {
            if (j.deltas.items.len <= 1) break;
            var old = j.deltas.orderedRemove(0);
            j.total_bytes -= old.byteSize();
            old.deinit(j.allocator);
        }
    }

    pub fn clear(j: *Journal) void {
        for (j.deltas.items) |*d| d.deinit(j.allocator);
        j.deltas.clearRetainingCapacity();
        j.total_bytes = 0;
    }

    /// Returns a contiguous delta chain from `from_serial` to `current_serial`.
    /// An empty slice means the client is already current.
    pub fn findChain(j: *const Journal, from_serial: u32, current_serial: u32) ?[]const Delta {
        if (from_serial == current_serial) return &.{};
        if (!serialOlder(from_serial, current_serial)) return &.{};
        var start: ?usize = null;
        for (j.deltas.items, 0..) |d, i| {
            if (d.from_serial == from_serial) {
                start = i;
                break;
            }
        }
        const s = start orelse return null;
        var end = s;
        var expected = from_serial;
        while (end < j.deltas.items.len) {
            const d = j.deltas.items[end];
            if (d.from_serial != expected) break;
            expected = d.to_serial;
            end += 1;
            if (expected == current_serial) return j.deltas.items[s..end];
        }
        return null;
    }

    pub fn save(j: *const Journal, io: std.Io, path: []const u8) !void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(j.allocator);
        try out.appendSlice(j.allocator, "ADNSJ1\n");
        for (j.deltas.items) |*d| {
            try appendU32(&out, j.allocator, d.from_serial);
            try appendU32(&out, j.allocator, d.to_serial);
            try appendU32(&out, j.allocator, @intCast(d.removed.len));
            try appendU32(&out, j.allocator, @intCast(d.added.len));
            for (d.removed) |r| try appendRecord(&out, j.allocator, r);
            for (d.added) |r| try appendRecord(&out, j.allocator, r);
        }
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = out.items });
    }

    pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Journal {
        var j = Journal.init(allocator);
        errdefer j.deinit();
        const data = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(128 * 1024 * 1024)) catch |e| switch (e) {
            error.FileNotFound => return j,
            else => return e,
        };
        defer allocator.free(data);
        if (data.len < 7 or !std.mem.eql(u8, data[0..7], "ADNSJ1\n")) return j;
        var pos: usize = 7;
        while (pos < data.len) {
            if (pos + 16 > data.len) break;
            const from = readU32(data, pos);
            const to = readU32(data, pos + 4);
            const nr = readU32(data, pos + 8);
            const na = readU32(data, pos + 12);
            pos += 16;
            if (nr > 1_000_000 or na > 1_000_000) break;
            var delta: Delta = .{ .from_serial = from, .to_serial = to, .removed = &.{}, .added = &.{} };
            delta.removed = allocator.alloc(zone.Record, nr) catch break;
            delta.added = allocator.alloc(zone.Record, na) catch break;
            var ok = true;
            for (0..nr) |i| {
                delta.removed[i] = readRecord(allocator, data, &pos) catch {
                    ok = false;
                    break;
                };
            }
            if (ok) for (0..na) |i| {
                delta.added[i] = readRecord(allocator, data, &pos) catch {
                    ok = false;
                    break;
                };
            };
            if (!ok) {
                // Truncated tail: drop this delta and stop.
                allocator.free(delta.removed);
                allocator.free(delta.added);
                break;
            }
            j.append(delta) catch break;
        }
        return j;
    }
};

pub fn serialOlder(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}

pub fn serialNewer(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}

/// Computes the IXFR delta between two zone versions.  Records are compared by
/// (owner, type, RDATA, TTL); RFC 1995 treats a TTL change as a delete+add.
pub fn diff(allocator: std.mem.Allocator, old: *const zone.Zone, new: *const zone.Zone) !Delta {
    const old_recs = try flatten(allocator, old);
    defer freeRecords(allocator, old_recs);
    const new_recs = try flatten(allocator, new);
    defer freeRecords(allocator, new_recs);

    var removed: std.ArrayList(zone.Record) = .empty;
    defer removed.deinit(allocator);
    var added: std.ArrayList(zone.Record) = .empty;
    defer added.deinit(allocator);

    var i: usize = 0;
    var k: usize = 0;
    while (i < old_recs.len or k < new_recs.len) {
        if (i >= old_recs.len) {
            try added.append(allocator, try copyRecord(allocator, new_recs[k]));
            k += 1;
            continue;
        }
        if (k >= new_recs.len) {
            try removed.append(allocator, try copyRecord(allocator, old_recs[i]));
            i += 1;
            continue;
        }
        const ord = compareRecord(old_recs[i], new_recs[k]);
        switch (ord) {
            .lt => {
                try removed.append(allocator, try copyRecord(allocator, old_recs[i]));
                i += 1;
            },
            .gt => {
                try added.append(allocator, try copyRecord(allocator, new_recs[k]));
                k += 1;
            },
            .eq => {
                if (old_recs[i].ttl != new_recs[k].ttl) {
                    try removed.append(allocator, try copyRecord(allocator, old_recs[i]));
                    try added.append(allocator, try copyRecord(allocator, new_recs[k]));
                }
                i += 1;
                k += 1;
            },
        }
    }
    return .{
        .from_serial = old.serial,
        .to_serial = new.serial,
        .removed = try removed.toOwnedSlice(allocator),
        .added = try added.toOwnedSlice(allocator),
    };
}

fn flatten(allocator: std.mem.Allocator, z: *const zone.Zone) ![]zone.Record {
    var out: std.ArrayList(zone.Record) = .empty;
    errdefer out.deinit(allocator);
    for (z.allRRsets()) |*rs| {
        // The SOA serial is represented by the IXFR framing itself, not as a
        // deleted/added RR in the delta.
        if (rs.rtype == types.SOA) continue;
        for (rs.rdata) |rd| {
            try out.append(allocator, .{
                .owner = try allocator.dupe(u8, rs.owner),
                .rtype = rs.rtype,
                .class = z.class,
                .ttl = rs.ttl,
                .rdata = try allocator.dupe(u8, rd),
            });
        }
    }
    std.mem.sort(zone.Record, out.items, {}, recordLess);
    return out.toOwnedSlice(allocator);
}

fn compareRecord(a: zone.Record, b: zone.Record) std.math.Order {
    const ord = name.Name.canonicalCompareWire(a.owner, b.owner);
    if (ord != .eq) return ord;
    if (a.rtype != b.rtype) return if (a.rtype < b.rtype) .lt else .gt;
    return std.mem.order(u8, a.rdata, b.rdata);
}

fn recordLess(_: void, a: zone.Record, b: zone.Record) bool {
    return compareRecord(a, b) == .lt;
}

fn copyRecord(allocator: std.mem.Allocator, r: zone.Record) !zone.Record {
    return .{
        .owner = try allocator.dupe(u8, r.owner),
        .rtype = r.rtype,
        .class = r.class,
        .ttl = r.ttl,
        .rdata = try allocator.dupe(u8, r.rdata),
        .line = r.line,
    };
}

fn freeRecord(allocator: std.mem.Allocator, r: zone.Record) void {
    allocator.free(r.owner);
    allocator.free(r.rdata);
}

fn freeRecords(allocator: std.mem.Allocator, recs: []zone.Record) void {
    for (recs) |r| freeRecord(allocator, r);
    allocator.free(recs);
}

fn appendU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u32) !void {
    try out.append(allocator, @intCast(v >> 24));
    try out.append(allocator, @intCast((v >> 16) & 0xff));
    try out.append(allocator, @intCast((v >> 8) & 0xff));
    try out.append(allocator, @intCast(v & 0xff));
}

fn appendRecord(out: *std.ArrayList(u8), allocator: std.mem.Allocator, r: zone.Record) !void {
    if (r.owner.len > 255 or r.rdata.len > 65535) return error.InvalidRecord;
    try out.append(allocator, @intCast(r.owner.len));
    try out.appendSlice(allocator, r.owner);
    try out.append(allocator, @intCast(r.rtype >> 8));
    try out.append(allocator, @intCast(r.rtype & 0xff));
    try out.append(allocator, @intCast(r.class >> 8));
    try out.append(allocator, @intCast(r.class & 0xff));
    try appendU32(out, allocator, r.ttl);
    try out.append(allocator, @intCast(r.rdata.len >> 8));
    try out.append(allocator, @intCast(r.rdata.len & 0xff));
    try out.appendSlice(allocator, r.rdata);
}

fn readU32(data: []const u8, off: usize) u32 {
    return (@as(u32, data[off]) << 24) | (@as(u32, data[off + 1]) << 16) |
        (@as(u32, data[off + 2]) << 8) | data[off + 3];
}

fn readRecord(allocator: std.mem.Allocator, data: []const u8, pos: *usize) !zone.Record {
    if (pos.* + 1 > data.len) return error.Truncated;
    const owner_len = data[pos.*];
    pos.* += 1;
    if (pos.* + owner_len + 10 > data.len) return error.Truncated;
    const owner = try allocator.dupe(u8, data[pos.* .. pos.* + owner_len]);
    pos.* += owner_len;
    const rtype = (@as(u16, data[pos.*]) << 8) | data[pos.* + 1];
    const class = (@as(u16, data[pos.* + 2]) << 8) | data[pos.* + 3];
    const ttl = readU32(data, pos.* + 4);
    const rdlen = (@as(u16, data[pos.* + 8]) << 8) | data[pos.* + 9];
    pos.* += 10;
    if (pos.* + rdlen > data.len) {
        allocator.free(owner);
        return error.Truncated;
    }
    const rdata = try allocator.dupe(u8, data[pos.* .. pos.* + rdlen]);
    pos.* += rdlen;
    return .{ .owner = owner, .rtype = rtype, .class = class, .ttl = ttl, .rdata = rdata };
}

test "journal serial chain" {
    var j = Journal.init(std.testing.allocator);
    defer j.deinit();
    try j.append(.{ .from_serial = 1, .to_serial = 2, .removed = &.{}, .added = &.{} });
    try j.append(.{ .from_serial = 2, .to_serial = 3, .removed = &.{}, .added = &.{} });
    try std.testing.expectEqual(@as(usize, 2), j.findChain(1, 3).?.len);
    try std.testing.expectEqual(@as(usize, 1), j.findChain(2, 3).?.len);
    try std.testing.expectEqual(@as(usize, 0), j.findChain(3, 3).?.len);
    try std.testing.expect(j.findChain(0, 3) == null);
}
