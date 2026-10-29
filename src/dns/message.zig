//! RFC 1035 section 4 message format, parsing and construction.
//!
//! Parsing accepts compression pointers in every name (including RDATA names,
//! which is why each record retains its RDATA offset into the original
//! message).  Construction always emits a correct message even if compression
//! is disabled for a particular field; RDATA is stored uncompressed.

const std = @import("std");
const name = @import("name.zig");
const types = @import("types.zig");

pub const header_len: usize = 12;

pub const Header = struct {
    id: u16 = 0,
    flags: u16 = 0,
    qdcount: u16 = 0,
    ancount: u16 = 0,
    nscount: u16 = 0,
    arcount: u16 = 0,

    pub fn parse(buf: []const u8) !Header {
        if (buf.len < header_len) return error.Truncated;
        return .{
            .id = readU16(buf, 0),
            .flags = readU16(buf, 2),
            .qdcount = readU16(buf, 4),
            .ancount = readU16(buf, 6),
            .nscount = readU16(buf, 8),
            .arcount = readU16(buf, 10),
        };
    }

    pub fn write(h: Header, buf: []u8) void {
        writeU16(buf, 0, h.id);
        writeU16(buf, 2, h.flags);
        writeU16(buf, 4, h.qdcount);
        writeU16(buf, 6, h.ancount);
        writeU16(buf, 8, h.nscount);
        writeU16(buf, 10, h.arcount);
    }

    pub fn qr(h: Header) bool {
        return h.flags & 0x8000 != 0;
    }
    pub fn opcode(h: Header) u4 {
        return @intCast((h.flags >> 11) & 0xf);
    }
    pub fn aa(h: Header) bool {
        return h.flags & 0x0400 != 0;
    }
    pub fn tc(h: Header) bool {
        return h.flags & 0x0200 != 0;
    }
    pub fn rd(h: Header) bool {
        return h.flags & 0x0100 != 0;
    }
    pub fn ra(h: Header) bool {
        return h.flags & 0x0080 != 0;
    }
    pub fn ad(h: Header) bool {
        return h.flags & 0x0020 != 0;
    }
    pub fn cd(h: Header) bool {
        return h.flags & 0x0010 != 0;
    }
    pub fn rcode(h: Header) u4 {
        return @intCast(h.flags & 0xf);
    }

    pub fn setQr(h: *Header, v: bool) void {
        setBit(&h.flags, 0x8000, v);
    }
    pub fn setOpcode(h: *Header, v: u4) void {
        h.flags = (h.flags & ~@as(u16, 0x7800)) | (@as(u16, v) << 11);
    }
    pub fn setAa(h: *Header, v: bool) void {
        setBit(&h.flags, 0x0400, v);
    }
    pub fn setTc(h: *Header, v: bool) void {
        setBit(&h.flags, 0x0200, v);
    }
    pub fn setRd(h: *Header, v: bool) void {
        setBit(&h.flags, 0x0100, v);
    }
    pub fn setRa(h: *Header, v: bool) void {
        setBit(&h.flags, 0x0080, v);
    }
    pub fn setAd(h: *Header, v: bool) void {
        setBit(&h.flags, 0x0020, v);
    }
    pub fn setCd(h: *Header, v: bool) void {
        setBit(&h.flags, 0x0010, v);
    }
    pub fn setRcode(h: *Header, v: u4) void {
        h.flags = (h.flags & ~@as(u16, 0x000f)) | v;
    }
};

fn setBit(v: *u16, mask: u16, on: bool) void {
    if (on) v.* |= mask else v.* &= ~mask;
}

pub const Question = struct {
    qname: name.Name,
    qtype: u16,
    qclass: u16,
};

pub const Record = struct {
    owner: name.Name,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: []const u8,
    /// Offset of the owner name and RDATA in the original message.  Needed to
    /// decompress names inside RDATA and to verify TSIG signatures.
    name_offset: usize,
    rdata_offset: usize,
};

pub const Message = struct {
    header: Header,
    questions: []Question,
    answers: []Record,
    authority: []Record,
    additional: []Record,
    raw: []const u8,

    pub fn deinit(m: *Message, allocator: std.mem.Allocator) void {
        allocator.free(m.questions);
        allocator.free(m.answers);
        allocator.free(m.authority);
        allocator.free(m.additional);
    }

    pub fn question(m: *const Message) ?Question {
        if (m.questions.len == 0) return null;
        return m.questions[0];
    }

    pub fn opt(m: *const Message) ?Record {
        for (m.additional) |rr| {
            if (rr.rtype == types.OPT) return rr;
        }
        return null;
    }

    pub fn tsig(m: *const Message) ?Record {
        for (m.additional) |rr| {
            if (rr.rtype == types.TSIG) return rr;
        }
        return null;
    }
};

pub const ParseError = error{
    Truncated,
    TooManyRecords,
    BadPointer,
    BadLabelType,
    NameTooLong,
    LabelTooLong,
    EmptyLabel,
    InvalidText,
    BadOpt,
};

pub fn parse(allocator: std.mem.Allocator, buf: []const u8) !Message {
    const h = try Header.parse(buf);
    const total: usize = @as(usize, h.qdcount) + h.ancount + h.nscount + h.arcount;
    if (total > 8192) return error.TooManyRecords;
    if (h.qdcount > 1024) return error.TooManyRecords;

    const questions = try allocator.alloc(Question, h.qdcount);
    errdefer allocator.free(questions);
    const answers = try allocator.alloc(Record, h.ancount);
    errdefer allocator.free(answers);
    const authority = try allocator.alloc(Record, h.nscount);
    errdefer allocator.free(authority);
    const additional = try allocator.alloc(Record, h.arcount);
    errdefer allocator.free(additional);

    var off: usize = header_len;
    for (questions) |*q| {
        const next = try name.parseWire(buf, off, &q.qname);
        off = next;
        if (off + 4 > buf.len) return error.Truncated;
        q.qtype = readU16(buf, off);
        q.qclass = readU16(buf, off + 2);
        off += 4;
    }
    try parseSection(buf, &off, answers);
    try parseSection(buf, &off, authority);
    try parseSection(buf, &off, additional);

    return .{
        .header = h,
        .questions = questions,
        .answers = answers,
        .authority = authority,
        .additional = additional,
        .raw = buf,
    };
}

fn parseSection(buf: []const u8, off: *usize, out: []Record) !void {
    for (out) |*rr| {
        const name_off = off.*;
        const next = try name.parseWire(buf, name_off, &rr.owner);
        off.* = next;
        if (off.* + 10 > buf.len) return error.Truncated;
        rr.rtype = readU16(buf, off.*);
        rr.class = readU16(buf, off.* + 2);
        rr.ttl = readU32(buf, off.* + 4);
        const rdlen = readU16(buf, off.* + 8);
        off.* += 10;
        if (off.* + rdlen > buf.len) return error.Truncated;
        rr.rdata = buf[off.* .. off.* + rdlen];
        rr.name_offset = name_off;
        rr.rdata_offset = off.*;
        off.* += rdlen;
    }
}

pub const Section = enum { answer, authority, additional };

pub const Builder = struct {
    buf: []u8,
    pos: usize = header_len,
    limit: usize,
    header: Header = .{},
    compressor: name.Compressor = .{},
    counts: [3]u16 = .{ 0, 0, 0 },
    qdcount: u16 = 0,

    pub fn init(buf: []u8, h: Header, limit: usize) !Builder {
        if (buf.len < header_len or limit < header_len or limit > buf.len) return error.NoSpace;
        var b: Builder = .{ .buf = buf, .limit = limit, .header = h };
        @memset(b.buf[0..header_len], 0);
        return b;
    }

    pub fn addQuestion(b: *Builder, qname: []const u8, qtype: u16, qclass: u16) !void {
        try b.writeName(qname);
        try b.ensure(4);
        writeU16(b.buf, b.pos, qtype);
        writeU16(b.buf, b.pos + 2, qclass);
        b.pos += 4;
        b.qdcount += 1;
    }

    pub fn addRecord(b: *Builder, section: Section, owner: []const u8, rtype: u16, class: u16, ttl: u32, rdata: []const u8) !void {
        if (rdata.len > 65535) return error.RdataTooLong;
        const saved_pos = b.pos;
        const saved_compressor = b.compressor.count;
        errdefer {
            b.pos = saved_pos;
            b.compressor.count = saved_compressor;
        }
        try b.writeName(owner);
        try b.ensure(10);
        writeU16(b.buf, b.pos, rtype);
        writeU16(b.buf, b.pos + 2, class);
        writeU32(b.buf, b.pos + 4, ttl);
        writeU16(b.buf, b.pos + 8, @intCast(rdata.len));
        b.pos += 10;
        try b.ensure(rdata.len);
        @memcpy(b.buf[b.pos..][0..rdata.len], rdata);
        b.pos += rdata.len;
        const idx = @backingInt(section);
        if (b.counts[idx] == 65535) return error.TooManyRecords;
        b.counts[idx] += 1;
    }

    pub fn addOpt(b: *Builder, udp_size: u16, ext_rcode: u8, ver: u8, flags: u16, options: []const u8) !void {
        const ttl = (@as(u32, ext_rcode) << 24) | (@as(u32, ver) << 16) | flags;
        try b.addRecord(.additional, "\x00", types.OPT, udp_size, ttl, options);
    }

    fn writeName(b: *Builder, owner: []const u8) !void {
        try b.compressor.write(b.buf[0..b.limit], &b.pos, owner);
        if (b.pos > b.limit) return error.NoSpace;
    }

    fn ensure(b: *Builder, n: usize) !void {
        if (b.pos + n > b.limit) return error.NoSpace;
    }

    pub fn setRcode(b: *Builder, rcode: u4) void {
        b.header.setRcode(rcode);
    }

    pub fn setTc(b: *Builder, on: bool) void {
        b.header.setTc(on);
    }

    pub fn finish(b: *Builder) []u8 {
        b.header.qdcount = b.qdcount;
        b.header.ancount = b.counts[0];
        b.header.nscount = b.counts[1];
        b.header.arcount = b.counts[2];
        b.header.write(b.buf[0..header_len]);
        return b.buf[0..b.pos];
    }

    pub fn recordCount(b: *const Builder, section: Section) u16 {
        return b.counts[@backingInt(section)];
    }
};

pub const BuildError = error{
    NoSpace,
    RdataTooLong,
    TooManyRecords,
    NameTooLong,
    LabelTooLong,
    EmptyLabel,
    Truncated,
    BadPointer,
    PointerLoop,
    BadLabelType,
};

fn readU16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}
fn readU32(buf: []const u8, off: usize) u32 {
    return (@as(u32, buf[off]) << 24) | (@as(u32, buf[off + 1]) << 16) |
        (@as(u32, buf[off + 2]) << 8) | buf[off + 3];
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

/// Patches the ARCOUNT field after appending a TSIG or OPT record in place.
pub fn setArcount(buf: []u8, count: u16) void {
    writeU16(buf, 10, count);
}

/// Extracts a domain name that starts at `rdata_offset + relative` inside the
/// original message, decompressing as needed.  Used for SOA/MX/SRV targets.
pub fn nameInRdata(msg: []const u8, rr: Record, relative: usize, out: *name.Name) !usize {
    return name.parseWire(msg, rr.rdata_offset + relative, out);
}

test "build and parse a response" {
    const allocator = std.testing.allocator;
    var buf: [512]u8 = undefined;
    var h: Header = .{ .id = 0x1234 };
    h.setQr(true);
    h.setAa(true);
    h.setRd(true);
    var b = try Builder.init(&buf, h, buf.len);
    var origin = try name.parseText("example.com.", null);
    try b.addQuestion(origin.slice(), types.SOA, types.class_in);

    var rdata: [128]u8 = undefined;
    var pos: usize = 0;
    const mname = "\x02ns\x07example\x03com\x00";
    @memcpy(rdata[0..mname.len], mname);
    pos = mname.len;
    const rname = "\x05admin\x07example\x03com\x00";
    @memcpy(rdata[pos..][0..rname.len], rname);
    pos += rname.len;
    writeU32(&rdata, pos, 1);
    writeU32(&rdata, pos + 4, 3600);
    writeU32(&rdata, pos + 8, 600);
    writeU32(&rdata, pos + 12, 604800);
    writeU32(&rdata, pos + 16, 300);
    pos += 20;

    try b.addRecord(.answer, origin.slice(), types.SOA, types.class_in, 3600, rdata[0..pos]);
    const wire = b.finish();

    var m = try parse(allocator, wire);
    defer m.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 0x1234), m.header.id);
    try std.testing.expect(m.header.aa());
    try std.testing.expectEqual(@as(u16, 1), m.header.qdcount);
    try std.testing.expectEqual(@as(usize, 1), m.answers.len);
    try std.testing.expect(m.questions[0].qname.eqlIgnoreCase(&origin));
    try std.testing.expectEqual(types.SOA, m.answers[0].rtype);
    try std.testing.expectEqual(@as(u32, 3600), m.answers[0].ttl);
}

test "compression in answer owner points at question" {
    const allocator = std.testing.allocator;
    var buf: [512]u8 = undefined;
    var h: Header = .{ .id = 1 };
    h.setQr(true);
    var b = try Builder.init(&buf, h, buf.len);
    var origin = try name.parseText("www.example.com.", null);
    try b.addQuestion(origin.slice(), types.A, types.class_in);
    const a = [_]u8{ 192, 0, 2, 1 };
    try b.addRecord(.answer, origin.slice(), types.A, types.class_in, 60, &a);
    const wire = b.finish();
    var m = try parse(allocator, wire);
    defer m.deinit(allocator);
    try std.testing.expect(m.answers[0].owner.eqlIgnoreCase(&origin));
}
