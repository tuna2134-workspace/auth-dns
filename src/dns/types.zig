//! DNS RR TYPE, CLASS, OPCODE and RCODE registry helpers.
//!
//! RFC 1035 section 3.2 defines the original TYPE/CLASS values; later RFCs
//! add many more.  Unknown types are represented as their 16-bit value and
//! rendered in the RFC 3597 `TYPE123` notation so that a server never needs a
//! table update to transfer or serve them.

const std = @import("std");

pub const A: u16 = 1;
pub const NS: u16 = 2;
pub const MD: u16 = 3;
pub const MF: u16 = 4;
pub const CNAME: u16 = 5;
pub const SOA: u16 = 6;
pub const MB: u16 = 7;
pub const MG: u16 = 8;
pub const MR: u16 = 9;
pub const NULL: u16 = 10;
pub const WKS: u16 = 11;
pub const PTR: u16 = 12;
pub const HINFO: u16 = 13;
pub const MINFO: u16 = 14;
pub const MX: u16 = 15;
pub const TXT: u16 = 16;
pub const RP: u16 = 17;
pub const AFSDB: u16 = 18;
pub const X25: u16 = 19;
pub const ISDN: u16 = 20;
pub const RT: u16 = 21;
pub const NSAP: u16 = 22;
pub const NSAP_PTR: u16 = 23;
pub const SIG: u16 = 24;
pub const KEY: u16 = 25;
pub const PX: u16 = 26;
pub const GPOS: u16 = 27;
pub const AAAA: u16 = 28;
pub const LOC: u16 = 29;
pub const NXT: u16 = 30;
pub const EID: u16 = 31;
pub const NIMLOC: u16 = 32;
pub const SRV: u16 = 33;
pub const ATMA: u16 = 34;
pub const NAPTR: u16 = 35;
pub const KX: u16 = 36;
pub const CERT: u16 = 37;
pub const A6: u16 = 38;
pub const DNAME: u16 = 39;
pub const SINK: u16 = 40;
pub const OPT: u16 = 41;
pub const APL: u16 = 42;
pub const DS: u16 = 43;
pub const SSHFP: u16 = 44;
pub const IPSECKEY: u16 = 45;
pub const RRSIG: u16 = 46;
pub const NSEC: u16 = 47;
pub const DNSKEY: u16 = 48;
pub const DHCID: u16 = 49;
pub const NSEC3: u16 = 50;
pub const NSEC3PARAM: u16 = 51;
pub const TLSA: u16 = 52;
pub const SMIMEA: u16 = 53;
pub const HIP: u16 = 55;
pub const NINFO: u16 = 56;
pub const RKEY: u16 = 57;
pub const TALINK: u16 = 58;
pub const CDS: u16 = 59;
pub const CDNSKEY: u16 = 60;
pub const OPENPGPKEY: u16 = 61;
pub const CSYNC: u16 = 62;
pub const ZONEMD: u16 = 63;
pub const SVCB: u16 = 64;
pub const HTTPS: u16 = 65;
pub const SPF: u16 = 99;
pub const EUI48: u16 = 108;
pub const EUI64: u16 = 109;
pub const TKEY: u16 = 249;
pub const TSIG: u16 = 250;
pub const IXFR: u16 = 251;
pub const AXFR: u16 = 252;
pub const MAILB: u16 = 253;
pub const MAILA: u16 = 254;
pub const ANY: u16 = 255;
pub const URI: u16 = 256;
pub const CAA: u16 = 257;
pub const AVC: u16 = 258;
pub const DOA: u16 = 259;
pub const AMTRELAY: u16 = 260;
pub const TA: u16 = 32768;
pub const DLV: u16 = 32769;

pub const class_in: u16 = 1;
pub const class_ch: u16 = 3;
pub const class_hs: u16 = 4;
pub const class_none: u16 = 254;
pub const class_any: u16 = 255;

pub const Opcode = enum(u4) {
    query = 0,
    iquery = 1,
    status = 2,
    notify = 4,
    update = 5,
    _,
};

pub const Rcode = enum(u4) {
    noerror = 0,
    formerr = 1,
    servfail = 2,
    nxdomain = 3,
    notimp = 4,
    refused = 5,
    yxdomain = 6,
    yxrrset = 7,
    nxrrset = 8,
    notauth = 9,
    notzone = 10,
    _,
};

/// Extended RCODEs are only valid with EDNS(0); they occupy the high 8 bits of
/// the combined 12-bit RCODE (RFC 6891 section 6.1.3).
pub const extended_rcode_badvers: u16 = 16;
pub const extended_rcode_badkey: u16 = 17;
pub const extended_rcode_badtime: u16 = 18;
pub const extended_rcode_badmode: u16 = 19;
pub const extended_rcode_badname: u16 = 20;
pub const extended_rcode_badalg: u16 = 21;
pub const extended_rcode_badtrunc: u16 = 22;
pub const extended_rcode_badcookie: u16 = 23;

const type_names = [_]struct { value: u16, name: []const u8 }{
    .{ .value = A, .name = "A" },
    .{ .value = NS, .name = "NS" },
    .{ .value = MD, .name = "MD" },
    .{ .value = MF, .name = "MF" },
    .{ .value = CNAME, .name = "CNAME" },
    .{ .value = SOA, .name = "SOA" },
    .{ .value = MB, .name = "MB" },
    .{ .value = MG, .name = "MG" },
    .{ .value = MR, .name = "MR" },
    .{ .value = NULL, .name = "NULL" },
    .{ .value = WKS, .name = "WKS" },
    .{ .value = PTR, .name = "PTR" },
    .{ .value = HINFO, .name = "HINFO" },
    .{ .value = MINFO, .name = "MINFO" },
    .{ .value = MX, .name = "MX" },
    .{ .value = TXT, .name = "TXT" },
    .{ .value = RP, .name = "RP" },
    .{ .value = AFSDB, .name = "AFSDB" },
    .{ .value = X25, .name = "X25" },
    .{ .value = ISDN, .name = "ISDN" },
    .{ .value = RT, .name = "RT" },
    .{ .value = NSAP, .name = "NSAP" },
    .{ .value = NSAP_PTR, .name = "NSAP-PTR" },
    .{ .value = SIG, .name = "SIG" },
    .{ .value = KEY, .name = "KEY" },
    .{ .value = PX, .name = "PX" },
    .{ .value = GPOS, .name = "GPOS" },
    .{ .value = AAAA, .name = "AAAA" },
    .{ .value = LOC, .name = "LOC" },
    .{ .value = NXT, .name = "NXT" },
    .{ .value = EID, .name = "EID" },
    .{ .value = NIMLOC, .name = "NIMLOC" },
    .{ .value = SRV, .name = "SRV" },
    .{ .value = ATMA, .name = "ATMA" },
    .{ .value = NAPTR, .name = "NAPTR" },
    .{ .value = KX, .name = "KX" },
    .{ .value = CERT, .name = "CERT" },
    .{ .value = A6, .name = "A6" },
    .{ .value = DNAME, .name = "DNAME" },
    .{ .value = SINK, .name = "SINK" },
    .{ .value = OPT, .name = "OPT" },
    .{ .value = APL, .name = "APL" },
    .{ .value = DS, .name = "DS" },
    .{ .value = SSHFP, .name = "SSHFP" },
    .{ .value = IPSECKEY, .name = "IPSECKEY" },
    .{ .value = RRSIG, .name = "RRSIG" },
    .{ .value = NSEC, .name = "NSEC" },
    .{ .value = DNSKEY, .name = "DNSKEY" },
    .{ .value = DHCID, .name = "DHCID" },
    .{ .value = NSEC3, .name = "NSEC3" },
    .{ .value = NSEC3PARAM, .name = "NSEC3PARAM" },
    .{ .value = TLSA, .name = "TLSA" },
    .{ .value = SMIMEA, .name = "SMIMEA" },
    .{ .value = HIP, .name = "HIP" },
    .{ .value = NINFO, .name = "NINFO" },
    .{ .value = RKEY, .name = "RKEY" },
    .{ .value = TALINK, .name = "TALINK" },
    .{ .value = CDS, .name = "CDS" },
    .{ .value = CDNSKEY, .name = "CDNSKEY" },
    .{ .value = OPENPGPKEY, .name = "OPENPGPKEY" },
    .{ .value = CSYNC, .name = "CSYNC" },
    .{ .value = ZONEMD, .name = "ZONEMD" },
    .{ .value = SVCB, .name = "SVCB" },
    .{ .value = HTTPS, .name = "HTTPS" },
    .{ .value = SPF, .name = "SPF" },
    .{ .value = EUI48, .name = "EUI48" },
    .{ .value = EUI64, .name = "EUI64" },
    .{ .value = TKEY, .name = "TKEY" },
    .{ .value = TSIG, .name = "TSIG" },
    .{ .value = IXFR, .name = "IXFR" },
    .{ .value = AXFR, .name = "AXFR" },
    .{ .value = MAILB, .name = "MAILB" },
    .{ .value = MAILA, .name = "MAILA" },
    .{ .value = ANY, .name = "ANY" },
    .{ .value = URI, .name = "URI" },
    .{ .value = CAA, .name = "CAA" },
    .{ .value = AVC, .name = "AVC" },
    .{ .value = DOA, .name = "DOA" },
    .{ .value = AMTRELAY, .name = "AMTRELAY" },
    .{ .value = TA, .name = "TA" },
    .{ .value = DLV, .name = "DLV" },
};

pub fn typeFromText(text: []const u8) ?u16 {
    var upper: [16]u8 = undefined;
    if (text.len > upper.len) {
        if (std.ascii.startsWithIgnoreCase(text, "TYPE")) {
            return std.fmt.parseInt(u16, text[4..], 10) catch null;
        }
        return null;
    }
    for (text, 0..) |c, i| upper[i] = std.ascii.toUpper(c);
    const s = upper[0..text.len];
    for (type_names) |t| {
        if (std.mem.eql(u8, t.name, s)) return t.value;
    }
    if (std.ascii.startsWithIgnoreCase(text, "TYPE")) {
        return std.fmt.parseInt(u16, text[4..], 10) catch null;
    }
    return null;
}

pub fn typeToText(value: u16) []const u8 {
    for (type_names) |t| {
        if (t.value == value) return t.name;
    }
    return "UNKNOWN";
}

pub fn typeToTextBuf(value: u16, buf: *[12]u8) []const u8 {
    for (type_names) |t| {
        if (t.value == value) return t.name;
    }
    return std.fmt.bufPrint(buf, "TYPE{d}", .{value}) catch "TYPE?";
}

pub fn classFromText(text: []const u8) ?u16 {
    var upper: [8]u8 = undefined;
    if (text.len > upper.len) {
        if (std.ascii.startsWithIgnoreCase(text, "CLASS")) {
            return std.fmt.parseInt(u16, text[5..], 10) catch null;
        }
        return null;
    }
    for (text, 0..) |c, i| upper[i] = std.ascii.toUpper(c);
    const s = upper[0..text.len];
    if (std.mem.eql(u8, s, "IN")) return class_in;
    if (std.mem.eql(u8, s, "CH")) return class_ch;
    if (std.mem.eql(u8, s, "HS")) return class_hs;
    if (std.mem.eql(u8, s, "NONE")) return class_none;
    if (std.mem.eql(u8, s, "ANY")) return class_any;
    if (std.ascii.startsWithIgnoreCase(text, "CLASS")) {
        return std.fmt.parseInt(u16, text[5..], 10) catch null;
    }
    return null;
}

pub fn classToText(value: u16) []const u8 {
    return switch (value) {
        class_in => "IN",
        class_ch => "CH",
        class_hs => "HS",
        class_none => "NONE",
        class_any => "ANY",
        else => "CLASS?",
    };
}

pub fn opcodeToText(value: u4) []const u8 {
    return switch (value) {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        4 => "NOTIFY",
        5 => "UPDATE",
        else => "OPCODE?",
    };
}

pub fn rcodeToText(value: u4) []const u8 {
    return switch (value) {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        else => "RCODE?",
    };
}

/// Types that are only meaningful in the question section.
pub fn isMetaType(t: u16) bool {
    return t == OPT or t == TKEY or t == TSIG or t == IXFR or t == AXFR or t == MAILB or t == MAILA or t == ANY;
}

test "type names round trip" {
    try std.testing.expectEqual(A, typeFromText("a").?);
    try std.testing.expectEqual(HTTPS, typeFromText("HTTPS").?);
    try std.testing.expectEqual(@as(u16, 655), typeFromText("TYPE655").?);
    try std.testing.expect(typeFromText("NOTATYPE") == null);
    var buf: [12]u8 = undefined;
    try std.testing.expectEqualStrings("TYPE655", typeToTextBuf(655, &buf));
}

test "class names" {
    try std.testing.expectEqual(class_in, classFromText("IN").?);
    try std.testing.expectEqual(class_ch, classFromText("ch").?);
    try std.testing.expect(classFromText("XX") == null);
}
