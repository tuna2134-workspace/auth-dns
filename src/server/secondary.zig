//! Secondary-side zone transfer client (AXFR/IXFR over TCP).
//!
//! The client requests IXFR when it already has a zone, and accepts AXFR
//! fallback from the primary.  RDATA names are decompressed into the
//! canonical uncompressed form used by the rest of the server.

const std = @import("std");
const Io = std.Io;
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");
const message = @import("../dns/message.zig");
const rdata = @import("../dns/rdata.zig");
const zone = @import("../zone/zone.zig");

pub const Primary = struct {
    addr: Io.net.IpAddress,
    /// TSIG key name.  Not yet used for outgoing requests.
    key_name: ?[]const u8 = null,
};

pub const Result = union(enum) {
    up_to_date,
    zone: zone.Zone,
};

const Raw = struct {
    owner: []const u8,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: []const u8,
};

pub fn fetch(
    backing: std.mem.Allocator,
    io: Io,
    origin: name.Name,
    class: u16,
    primary: Primary,
    current: ?*const zone.Zone,
) !Result {
    var tmp = std.heap.ArenaAllocator.init(backing);
    defer tmp.deinit();
    const a = tmp.allocator();

    // std.Io's connect timeout is unimplemented in Zig 0.17; use the OS
    // default TCP connect timeout and the read timeout below.
    var stream = primary.addr.connect(io, .{ .mode = .stream }) catch |e| return e;
    defer stream.close(io);

    var qbuf: [1024]u8 = undefined;
    var random_id: u16 = 0;
    io.random(std.mem.asBytes(&random_id));
    var h: message.Header = .{ .id = random_id };
    h.setRd(false);
    var b = try message.Builder.init(&qbuf, h, qbuf.len);
    try b.addQuestion(origin.slice(), if (current == null) types.AXFR else types.IXFR, class);
    if (current) |z| {
        const soa = try soaWithSerial(a, z.soaRdata(), z.serial);
        try b.addRecord(.authority, origin.slice(), types.SOA, class, z.soa.ttl, soa);
    }
    const query = b.finish();
    try writeAll(&stream, io, query);

    var records: std.ArrayList(Raw) = .empty;
    defer records.deinit(a);

    var msg_buf: [65535]u8 = undefined;
    var msg_count: usize = 0;
    var last_was_soa = false;
    while (true) {
        var lenbuf: [2]u8 = undefined;
        readExact(stream.socket.handle, &lenbuf, 5000) catch |e| {
            if (msg_count == 0) return e;
            break;
        };
        const len = (@as(usize, lenbuf[0]) << 8) | lenbuf[1];
        if (len < 12 or len > msg_buf.len) return error.BadTransfer;
        readExact(stream.socket.handle, msg_buf[0..len], 5000) catch |e| {
            if (msg_count == 0) return e;
            break;
        };
        var m = try message.parse(a, msg_buf[0..len]);
        defer m.deinit(a);
        if (m.header.id != h.id) return error.BadTransfer;
        if (!m.header.qr()) return error.BadTransfer;
        if (m.header.rcode() != 0) return error.TransferRefused;
        for (m.answers) |rr| {
            const raw = try normalizeRecord(a, m.raw, rr);
            try records.append(a, raw);
        }
        msg_count += 1;
        last_was_soa = m.answers.len > 0 and m.answers[m.answers.len - 1].rtype == types.SOA;
        if (last_was_soa) {
            // The transfer is complete when no further message arrives shortly.
            var next_len: [2]u8 = undefined;
            readExact(stream.socket.handle, &next_len, 300) catch break;
            const nlen = (@as(usize, next_len[0]) << 8) | next_len[1];
            if (nlen < 12 or nlen > msg_buf.len) return error.BadTransfer;
            readExact(stream.socket.handle, msg_buf[0..nlen], 5000) catch break;
            var nm = try message.parse(a, msg_buf[0..nlen]);
            defer nm.deinit(a);
            for (nm.answers) |rr| {
                const raw = try normalizeRecord(a, nm.raw, rr);
                try records.append(a, raw);
            }
            msg_count += 1;
            last_was_soa = nm.answers.len > 0 and nm.answers[nm.answers.len - 1].rtype == types.SOA;
            if (!last_was_soa) {
                // Continue reading in the outer loop; the next iteration will
                // start from the length prefix again.
                continue;
            }
            // Another SOA-terminated message: keep reading until timeout.
            continue;
        }
    }
    if (records.items.len == 0 or !last_was_soa) return error.BadTransfer;

    if (records.items.len == 1 and records.items[0].rtype == types.SOA) {
        if (current) |z| {
            if (serialOf(records.items[0].rdata) == z.serial) return .up_to_date;
        }
    }

    const is_axfr = records.items.len >= 2 and records.items[0].rtype == types.SOA and
        records.items[1].rtype != types.SOA;
    if (is_axfr) {
        return .{ .zone = try buildZone(backing, origin, class, records.items) };
    }
    if (current) |z| {
        const merged = try applyIxfr(a, z, records.items);
        defer a.free(merged);
        return .{ .zone = try buildZone(backing, origin, class, merged) };
    }
    return .{ .zone = try buildZone(backing, origin, class, records.items) };
}

fn buildZone(backing: std.mem.Allocator, origin: name.Name, class: u16, raws: []const Raw) !zone.Zone {
    var recs = try backing.alloc(zone.Record, raws.len);
    defer backing.free(recs);
    for (raws, 0..) |r, i| {
        recs[i] = .{
            .owner = r.owner,
            .rtype = r.rtype,
            .class = r.class,
            .ttl = r.ttl,
            .rdata = r.rdata,
        };
    }
    return zone.Zone.build(backing, origin, class, recs, &.{});
}

fn applyIxfr(a: std.mem.Allocator, z: *const zone.Zone, raws: []const Raw) ![]Raw {
    var out: std.ArrayList(Raw) = .empty;
    // Copy current records except SOA; deletions/additions are applied below.
    for (z.allRRsets()) |*rs| {
        if (rs.rtype == types.SOA) continue;
        for (rs.rdata) |rd| {
            try out.append(a, .{
                .owner = try a.dupe(u8, rs.owner),
                .rtype = rs.rtype,
                .class = z.class,
                .ttl = rs.ttl,
                .rdata = try a.dupe(u8, rd),
            });
        }
    }
    var i: usize = 0;
    // Start with the current SOA.
    if (raws.len == 0 or raws[0].rtype != types.SOA) return error.BadTransfer;
    i = 1;
    var expected = z.serial;
    var final_soa: ?Raw = null;
    while (i < raws.len) {
        if (raws[i].rtype != types.SOA) return error.BadTransfer;
        const old_serial = serialOf(raws[i].rdata);
        if (old_serial != expected) return error.BadTransfer;
        i += 1;
        // Deleted RRs.
        while (i < raws.len and raws[i].rtype != types.SOA) : (i += 1) {
            removeRecord(&out, raws[i]);
        }
        if (i >= raws.len or raws[i].rtype != types.SOA) return error.BadTransfer;
        const new_serial = serialOf(raws[i].rdata);
        const new_soa = raws[i];
        final_soa = new_soa;
        i += 1;
        // Added RRs.
        while (i < raws.len and raws[i].rtype != types.SOA) : (i += 1) {
            try out.append(a, raws[i]);
        }
        expected = new_serial;
        if (i >= raws.len) break;
        // A final SOA equal to the new serial is the transfer suffix.
        if (raws[i].rtype == types.SOA and serialOf(raws[i].rdata) == new_serial) {
            i += 1;
            if (i == raws.len) break;
        }
    }
    if (final_soa) |fs| try out.append(a, new_soaRecord(fs));
    return out.toOwnedSlice(a);
}

fn new_soaRecord(r: Raw) Raw {
    return r;
}

fn removeRecord(out: *std.ArrayList(Raw), r: Raw) void {
    var i: usize = 0;
    while (i < out.items.len) {
        const x = out.items[i];
        if (x.rtype == r.rtype and std.mem.eql(u8, x.owner, r.owner) and std.mem.eql(u8, x.rdata, r.rdata)) {
            _ = out.orderedRemove(i);
            return;
        }
        i += 1;
    }
}

pub fn normalizeRecord(a: std.mem.Allocator, msg: []const u8, rr: message.Record) !Raw {
    var owner = rr.owner;
    name.lowerInPlace(owner.buf[0..owner.len]);
    const owner_wire = try a.dupe(u8, owner.slice());
    const rd = try normalizeRdata(a, msg, rr);
    return .{ .owner = owner_wire, .rtype = rr.rtype, .class = rr.class, .ttl = rr.ttl, .rdata = rd };
}

fn normalizeRdata(a: std.mem.Allocator, msg: []const u8, rr: message.Record) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    const rd = rr.rdata;
    const base = rr.rdata_offset;
    switch (rr.rtype) {
        types.NS, types.CNAME, types.PTR, types.DNAME, types.MB, types.MD, types.MF, types.MG, types.MR => {
            _ = try appendWireName(&out, a, msg, base);
        },
        types.MX, types.KX, types.RT, types.AFSDB => {
            if (rd.len < 3) return error.BadTransfer;
            try out.appendSlice(a, rd[0..2]);
            _ = try appendWireName(&out, a, msg, base + 2);
        },
        types.SRV => {
            if (rd.len < 7) return error.BadTransfer;
            try out.appendSlice(a, rd[0..6]);
            _ = try appendWireName(&out, a, msg, base + 6);
        },
        types.SOA => {
            const mname = try appendWireName(&out, a, msg, base);
            _ = try appendWireName(&out, a, msg, base + mname);
            try out.appendSlice(a, rd[rd.len - 20 ..]);
        },
        types.NAPTR => {
            if (rd.len < 5) return error.BadTransfer;
            try out.appendSlice(a, rd[0..4]);
            var off: usize = 4;
            for (0..3) |_| {
                if (off >= rd.len) return error.BadTransfer;
                const l = rd[off];
                try out.appendSlice(a, rd[off .. off + 1 + l]);
                off += 1 + l;
            }
            _ = try appendWireName(&out, a, msg, base + off);
        },
        types.RP, types.MINFO => {
            const first = try appendWireName(&out, a, msg, base);
            _ = try appendWireName(&out, a, msg, base + first);
        },
        types.PX => {
            if (rd.len < 3) return error.BadTransfer;
            try out.appendSlice(a, rd[0..2]);
            const first = try appendWireName(&out, a, msg, base + 2);
            _ = try appendWireName(&out, a, msg, base + 2 + first);
        },
        types.RRSIG, types.SIG => {
            if (rd.len < 19) return error.BadTransfer;
            try out.appendSlice(a, rd[0..18]);
            const first = try appendWireName(&out, a, msg, base + 18);
            try out.appendSlice(a, rd[18 + first ..]);
        },
        types.NSEC => {
            const first = try appendWireName(&out, a, msg, base);
            try out.appendSlice(a, rd[first..]);
        },
        types.SVCB, types.HTTPS => {
            if (rd.len < 3) return error.BadTransfer;
            try out.appendSlice(a, rd[0..2]);
            const first = try appendWireName(&out, a, msg, base + 2);
            try out.appendSlice(a, rd[2 + first ..]);
        },
        else => try out.appendSlice(a, rd),
    }
    return out.toOwnedSlice(a);
}

fn appendWireName(out: *std.ArrayList(u8), a: std.mem.Allocator, msg: []const u8, off: usize) !usize {
    var n: name.Name = undefined;
    const next = try name.parseWire(msg, off, &n);
    try out.appendSlice(a, n.slice());
    return next - off; // encoded length in the original message
}

fn soaWithSerial(a: std.mem.Allocator, rdata_in: []const u8, serial: u32) ![]u8 {
    var n: name.Name = undefined;
    var off = try name.parseWire(rdata_in, 0, &n);
    off = try name.parseWire(rdata_in, off, &n);
    if (off + 20 > rdata_in.len) return error.BadSoa;
    const out = try a.dupe(u8, rdata_in);
    std.mem.writeInt(u32, out[off..][0..4], serial, .big);
    return out;
}

fn serialOf(soa_rdata: []const u8) u32 {
    return zone.soaSerial(soa_rdata) orelse 0;
}

fn writeAll(stream: *Io.net.Stream, io: Io, data: []const u8) !void {
    var buf: [8192]u8 = undefined;
    var w = stream.writer(io, &buf);
    var prefix: [2]u8 = .{ @intCast(data.len >> 8), @intCast(data.len & 0xff) };
    try w.interface.writeAll(&prefix);
    try w.interface.writeAll(data);
    try w.interface.flush();
}

fn readExact(fd: std.posix.fd_t, buf: []u8, timeout_ms: i32) !void {
    var off: usize = 0;
    while (off < buf.len) {
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const n = std.posix.poll(&fds, timeout_ms) catch return error.ReadFailed;
        if (n == 0) return error.Timeout;
        const rev = fds[0].revents;
        if (rev & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) return error.EndOfStream;
        const r = std.c.recv(fd, @ptrCast(buf.ptr + off), buf.len - off, 0);
        if (r == 0) return error.EndOfStream;
        if (r < 0) return error.ReadFailed;
        off += @intCast(r);
    }
}
