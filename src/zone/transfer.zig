//! AXFR (RFC 5936) and IXFR (RFC 1995) response construction.
//!
//! Both transfers are TCP-only in this server.  The caller checks ACLs and
//! TSIG before invoking these builders; each returned message is a complete
//! DNS message with the request ID, AA=1 and TC=0.  The first message carries
//! the question; continuation messages have QDCOUNT=0, as permitted by
//! RFC 5936 section 2.2.1.

const std = @import("std");
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");
const message = @import("../dns/message.zig");
const zone = @import("zone.zig");
const journal_mod = @import("journal.zig");

pub const Options = struct {
    max_message_size: usize = 65535,
    max_records_per_message: usize = 4096,
};

pub fn buildAxfr(
    allocator: std.mem.Allocator,
    z: *const zone.Zone,
    query: *const message.Message,
    opts: Options,
) ![][]u8 {
    var p = try Packer.init(allocator, query, opts.max_message_size, opts.max_records_per_message);
    errdefer p.deinit();

    for (z.soa.rdata) |rd| {
        try p.add(z.origin_wire, types.SOA, z.class, z.soa.ttl, rd);
    }
    for (z.allRRsets()) |*rs| {
        if (rs.rtype == types.SOA and std.mem.eql(u8, rs.owner, z.origin_wire)) continue;
        for (rs.rdata) |rd| {
            try p.add(rs.owner, rs.rtype, z.class, rs.ttl, rd);
        }
    }
    for (z.soa.rdata) |rd| {
        try p.add(z.origin_wire, types.SOA, z.class, z.soa.ttl, rd);
    }
    try p.finish();
    return p.takeMessages();
}

pub fn buildIxfr(
    allocator: std.mem.Allocator,
    z: *const zone.Zone,
    j: ?*const journal_mod.Journal,
    query: *const message.Message,
    opts: Options,
) ![][]u8 {
    const client_serial = clientSerial(query) orelse return buildAxfr(allocator, z, query, opts);
    // Same or newer client version: a single copy of the current SOA.
    if (!journal_mod.serialOlder(client_serial, z.serial)) {
        return buildUpToDate(allocator, z, query, opts);
    }
    const journal = j orelse return buildAxfr(allocator, z, query, opts);
    const chain = journal.findChain(client_serial, z.serial) orelse
        return buildAxfr(allocator, z, query, opts);
    if (chain.len == 0) return buildUpToDate(allocator, z, query, opts);

    var p = try Packer.init(allocator, query, opts.max_message_size, opts.max_records_per_message);
    errdefer p.deinit();
    // Prefix: the server's current SOA.
    for (z.soa.rdata) |rd| try p.add(z.origin_wire, types.SOA, z.class, z.soa.ttl, rd);

    for (chain) |*d| {
        const old_rdata = try soaWithSerial(allocator, z.soa.rdata[0], d.from_serial);
        defer allocator.free(old_rdata);
        try p.add(z.origin_wire, types.SOA, z.class, z.soa.ttl, old_rdata);

        for (d.removed) |r| try p.add(r.owner, r.rtype, r.class, r.ttl, r.rdata);

        const new_rdata = try soaWithSerial(allocator, z.soa.rdata[0], d.to_serial);
        defer allocator.free(new_rdata);
        try p.add(z.origin_wire, types.SOA, z.class, z.soa.ttl, new_rdata);

        for (d.added) |r| try p.add(r.owner, r.rtype, r.class, r.ttl, r.rdata);
    }
    // Suffix: the current SOA again (RFC 1995 section 4).
    for (z.soa.rdata) |rd| try p.add(z.origin_wire, types.SOA, z.class, z.soa.ttl, rd);

    try p.finish();
    return p.takeMessages();
}

fn buildUpToDate(
    allocator: std.mem.Allocator,
    z: *const zone.Zone,
    query: *const message.Message,
    opts: Options,
) ![][]u8 {
    var p = try Packer.init(allocator, query, opts.max_message_size, opts.max_records_per_message);
    errdefer p.deinit();
    for (z.soa.rdata) |rd| try p.add(z.origin_wire, types.SOA, z.class, z.soa.ttl, rd);
    try p.finish();
    return p.takeMessages();
}

/// Returns the serial from the first SOA in the IXFR request's authority
/// section, decompressing names relative to the whole message.
pub fn clientSerial(query: *const message.Message) ?u32 {
    for (query.authority) |rr| {
        if (rr.rtype != types.SOA) continue;
        var n: name.Name = undefined;
        var off = name.parseWire(query.raw, rr.rdata_offset, &n) catch return null;
        off = name.parseWire(query.raw, off, &n) catch return null;
        if (off + 20 > query.raw.len) return null;
        return (@as(u32, query.raw[off]) << 24) | (@as(u32, query.raw[off + 1]) << 16) |
            (@as(u32, query.raw[off + 2]) << 8) | query.raw[off + 3];
    }
    return null;
}

fn soaWithSerial(allocator: std.mem.Allocator, rdata: []const u8, serial: u32) ![]u8 {
    var n: name.Name = undefined;
    var off = try name.parseWire(rdata, 0, &n);
    off = try name.parseWire(rdata, off, &n);
    if (off + 20 > rdata.len) return error.InvalidSoa;
    const out = try allocator.dupe(u8, rdata);
    out[off] = @intCast(serial >> 24);
    out[off + 1] = @intCast((serial >> 16) & 0xff);
    out[off + 2] = @intCast((serial >> 8) & 0xff);
    out[off + 3] = @intCast(serial & 0xff);
    return out;
}

const Packer = struct {
    allocator: std.mem.Allocator,
    scratch: []u8,
    b: message.Builder,
    messages: std.ArrayList([]u8) = .empty,
    header: message.Header,
    include_question: bool = true,
    question_wire_len: usize = 0,
    max_records: usize,
    has_records: bool = false,
    record_count: usize = 0,

    fn init(
        allocator: std.mem.Allocator,
        query: *const message.Message,
        max_size: usize,
        max_records: usize,
    ) !Packer {
        const q = query.question() orelse return error.NoQuestion;
        const size = @min(max_size, 65535);
        const scratch = try allocator.alloc(u8, size);
        errdefer allocator.free(scratch);
        var h: message.Header = .{ .id = query.header.id };
        h.setQr(true);
        h.setOpcode(query.header.opcode());
        h.setAa(true);
        h.setRd(query.header.rd());
        var p: Packer = .{
            .allocator = allocator,
            .scratch = scratch,
            .b = try message.Builder.init(scratch, h, size),
            .header = h,
            .max_records = max_records,
        };
        try p.b.addQuestion(q.qname.slice(), q.qtype, q.qclass);
        p.question_wire_len = p.b.pos - message.header_len;
        return p;
    }

    fn deinit(p: *Packer) void {
        for (p.messages.items) |m| p.allocator.free(m);
        p.messages.deinit(p.allocator);
        p.allocator.free(p.scratch);
    }

    fn add(p: *Packer, owner: []const u8, rtype: u16, class: u16, ttl: u32, rdata: []const u8) !void {
        if (p.has_records and p.record_count >= p.max_records) {
            try p.flush();
            try p.resetBuilder();
        }
        p.b.addRecord(.answer, owner, rtype, class, ttl, rdata) catch |e| switch (e) {
            error.NoSpace => {
                if (!p.has_records) return error.RecordTooLarge;
                try p.flush();
                try p.resetBuilder();
                try p.b.addRecord(.answer, owner, rtype, class, ttl, rdata);
            },
            else => return e,
        };
        p.has_records = true;
        p.record_count += 1;
    }

    fn flush(p: *Packer) !void {
        if (!p.has_records) return;
        const wire = p.b.finish();
        const copy = try p.allocator.dupe(u8, wire);
        errdefer p.allocator.free(copy);
        try p.messages.append(p.allocator, copy);
        p.has_records = false;
        p.record_count = 0;
    }

    fn resetBuilder(p: *Packer) !void {
        p.include_question = false;
        p.b = try message.Builder.init(p.scratch, p.header, p.scratch.len);
    }

    fn finish(p: *Packer) !void {
        try p.flush();
    }

    fn takeMessages(p: *Packer) ![][]u8 {
        const out = try p.messages.toOwnedSlice(p.allocator);
        p.allocator.free(p.scratch);
        p.scratch = &.{};
        p.messages = .empty;
        return out;
    }
};

test "AXFR starts and ends with SOA" {
    const sema = @import("sema.zig");
    const src =
        \\$TTL 60
        \\@ SOA ns. hostmaster. 7 1 1 1 1
        \\@ NS ns.
        \\ns A 192.0.2.1
        \\www A 192.0.2.2
        \\
    ;
    var z = try sema.loadSource(std.testing.allocator, std.testing.io, src, "t.zone", .{
        .origin = try name.parseText("example.com.", null),
    });
    defer z.deinit();

    var qbuf: [512]u8 = undefined;
    const h: message.Header = .{ .id = 0x4242 };
    var qb = try message.Builder.init(&qbuf, h, qbuf.len);
    try qb.addQuestion("\x07example\x03com\x00", types.AXFR, types.class_in);
    var q = try message.parse(std.testing.allocator, qb.finish());
    defer q.deinit(std.testing.allocator);

    const msgs = try buildAxfr(std.testing.allocator, &z, &q, .{});
    defer {
        for (msgs) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(msgs);
    }
    var total: usize = 0;
    var soa_count: usize = 0;
    for (msgs, 0..) |m, idx| {
        var rm = try message.parse(std.testing.allocator, m);
        defer rm.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u16, 0x4242), rm.header.id);
        try std.testing.expect(rm.header.aa());
        if (idx == 0) try std.testing.expectEqual(@as(u16, 1), rm.header.qdcount);
        total += rm.answers.len;
        for (rm.answers) |rr| if (rr.rtype == types.SOA) {
            soa_count += 1;
        };
    }
    try std.testing.expectEqual(@as(usize, 2), soa_count);
    try std.testing.expectEqual(@as(usize, 5), total);
}

test "IXFR up-to-date is one SOA" {
    const sema = @import("sema.zig");
    const src =
        \\$TTL 60
        \\@ SOA ns. hostmaster. 7 1 1 1 1
        \\@ NS ns.
        \\ns A 192.0.2.1
        \\
    ;
    var z = try sema.loadSource(std.testing.allocator, std.testing.io, src, "t.zone", .{
        .origin = try name.parseText("example.com.", null),
    });
    defer z.deinit();
    var qbuf: [512]u8 = undefined;
    const h: message.Header = .{ .id = 1 };
    var qb = try message.Builder.init(&qbuf, h, qbuf.len);
    try qb.addQuestion("\x07example\x03com\x00", types.IXFR, types.class_in);
    var soa_rdata: [64]u8 = undefined;
    const mname = "\x02ns\x00";
    const rname = "\x0ahostmaster\x00";
    @memcpy(soa_rdata[0..mname.len], mname);
    @memcpy(soa_rdata[mname.len..][0..rname.len], rname);
    var pos = mname.len + rname.len;
    for ([_]u32{ 7, 1, 1, 1, 1 }) |v| {
        soa_rdata[pos] = @intCast(v >> 24);
        soa_rdata[pos + 1] = @intCast((v >> 16) & 0xff);
        soa_rdata[pos + 2] = @intCast((v >> 8) & 0xff);
        soa_rdata[pos + 3] = @intCast(v & 0xff);
        pos += 4;
    }
    try qb.addRecord(.authority, "\x07example\x03com\x00", types.SOA, types.class_in, 60, soa_rdata[0..pos]);
    var q = try message.parse(std.testing.allocator, qb.finish());
    defer q.deinit(std.testing.allocator);
    const msgs = try buildIxfr(std.testing.allocator, &z, null, &q, .{});
    defer {
        for (msgs) |m| std.testing.allocator.free(m);
        std.testing.allocator.free(msgs);
    }
    try std.testing.expectEqual(@as(usize, 1), msgs.len);
    var rm = try message.parse(std.testing.allocator, msgs[0]);
    defer rm.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), rm.answers.len);
    try std.testing.expectEqual(types.SOA, rm.answers[0].rtype);
}
