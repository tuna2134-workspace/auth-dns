//! Conversion of master-file RDATA tokens into wire-format RDATA.
//!
//! The zone semantic analyser calls `parse` once per record.  Names embedded
//! in RDATA are resolved against the current $ORIGIN and lowercased here so
//! that the stored bytes are already in the canonical form needed by RFC 4034
//! section 6.2 (DNSSEC signing) and by AXFR/IXFR comparisons.

const std = @import("std");
const name = @import("name.zig");
const types = @import("types.zig");
const text = @import("text.zig");

pub const Error = error{
    WrongTokenCount,
    UnknownType,
    InvalidAddress,
    InvalidRdata,
    RdataTooLong,
    InvalidTypeBitmap,
    UnsupportedType,
} || text.Error || name.Error || std.mem.Allocator.Error;

pub const Context = struct {
    origin: *const name.Name,
};

const Builder = struct {
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    ctx: Context,

    fn u8_(b: *Builder, v: u8) !void {
        try b.out.append(b.allocator, v);
    }
    fn u16_(b: *Builder, v: u16) !void {
        try text.appendU16(b.out, b.allocator, v);
    }
    fn u32_(b: *Builder, v: u32) !void {
        try text.appendU32(b.out, b.allocator, v);
    }
    fn name_(b: *Builder, tok: text.Token) !void {
        var n = try name.parseText(tok.text, b.ctx.origin);
        name.lowerInPlace(n.buf[0..n.len]);
        try b.out.appendSlice(b.allocator, n.slice());
    }
    fn charString(b: *Builder, data: []const u8) !void {
        try text.appendCharString(b.out, b.allocator, data);
    }
};

pub fn parse(
    allocator: std.mem.Allocator,
    rtype: u16,
    tokens: []const text.Token,
    ctx: Context,
    out: *std.ArrayList(u8),
) Error!void {
    errdefer out.clearRetainingCapacity();
    if (tokens.len == 0) return error.WrongTokenCount;

    // RFC 3597 section 5: generic \# <length> <hex> representation.  This is
    // accepted for every type, including known ones, and is the only way to
    // add a type this build does not understand.
    if (std.mem.eql(u8, tokens[0].text, "\\#")) {
        return parseGeneric(allocator, tokens, out);
    }

    var b: Builder = .{ .allocator = allocator, .out = out, .ctx = ctx };
    switch (rtype) {
        types.A => {
            try expect(tokens, 1);
            const ip = std.Io.net.Ip4Address.parse(tokens[0].text, 0) catch return error.InvalidAddress;
            try out.appendSlice(allocator, &ip.bytes);
        },
        types.AAAA => {
            try expect(tokens, 1);
            const ip = std.Io.net.Ip6Address.parse(tokens[0].text, 0) catch return error.InvalidAddress;
            try out.appendSlice(allocator, &ip.bytes);
        },
        types.NS, types.CNAME, types.PTR, types.DNAME, types.MB, types.MD, types.MF, types.MG, types.MR => {
            try expect(tokens, 1);
            try b.name_(tokens[0]);
        },
        types.SOA => {
            try expect(tokens, 7);
            try b.name_(tokens[0]);
            try b.name_(tokens[1]);
            try b.u32_(try text.parseU32(tokens[2].text));
            // BIND accepts TTL units (1h, 15m, ...) for these four SOA
            // timers even though RFC 1035 prints them as integers.
            try b.u32_(try text.parseTtl(tokens[3].text));
            try b.u32_(try text.parseTtl(tokens[4].text));
            try b.u32_(try text.parseTtl(tokens[5].text));
            try b.u32_(try text.parseTtl(tokens[6].text));
        },
        types.MX => {
            try expect(tokens, 2);
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.name_(tokens[1]);
        },
        types.AFSDB, types.RT, types.KX => {
            try expect(tokens, 2);
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.name_(tokens[1]);
        },
        types.MINFO => {
            try expect(tokens, 2);
            try b.name_(tokens[0]);
            try b.name_(tokens[1]);
        },
        types.RP => {
            try expect(tokens, 2);
            try b.name_(tokens[0]);
            try b.name_(tokens[1]);
        },
        types.PX => {
            try expect(tokens, 3);
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.name_(tokens[1]);
            try b.name_(tokens[2]);
        },
        types.TXT, types.SPF => {
            if (tokens.len == 0) return error.WrongTokenCount;
            for (tokens) |tok| {
                const s = try text.decodedAlloc(allocator, tok.text);
                defer allocator.free(s);
                try b.charString(s);
            }
        },
        types.HINFO => {
            try expect(tokens, 2);
            const a = try text.decodedAlloc(allocator, tokens[0].text);
            defer allocator.free(a);
            const c = try text.decodedAlloc(allocator, tokens[1].text);
            defer allocator.free(c);
            try b.charString(a);
            try b.charString(c);
        },
        types.SRV => {
            try expect(tokens, 4);
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.u16_(try text.parseU16(tokens[1].text));
            try b.u16_(try text.parseU16(tokens[2].text));
            try b.name_(tokens[3]);
        },
        types.NAPTR => {
            try expect(tokens, 6);
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.u16_(try text.parseU16(tokens[1].text));
            inline for (0..3) |i| {
                const s = try text.decodedAlloc(allocator, tokens[2 + i].text);
                defer allocator.free(s);
                try b.charString(s);
            }
            try b.name_(tokens[5]);
        },
        types.CAA => {
            if (tokens.len < 3) return error.WrongTokenCount;
            try b.u8_(try text.parseU8(tokens[0].text));
            const tag = try text.decodedAlloc(allocator, tokens[1].text);
            defer allocator.free(tag);
            if (tag.len > 255) return error.RdataTooLong;
            try b.u8_(@intCast(tag.len));
            try out.appendSlice(allocator, tag);
            var value: std.ArrayList(u8) = .empty;
            defer value.deinit(allocator);
            for (tokens[2..], 0..) |tok, vi| {
                if (vi != 0) try value.append(allocator, ' ');
                const decoded = try text.decodedAlloc(allocator, tok.text);
                defer allocator.free(decoded);
                try value.appendSlice(allocator, decoded);
            }
            try out.appendSlice(allocator, value.items);
        },
        types.SSHFP => {
            try expect(tokens, 3);
            try b.u8_(try text.parseU8(tokens[0].text));
            try b.u8_(try text.parseU8(tokens[1].text));
            try text.appendHex(out, allocator, tokens[2].text);
        },
        types.TLSA, types.SMIMEA => {
            if (tokens.len < 4) return error.WrongTokenCount;
            try b.u8_(try text.parseU8(tokens[0].text));
            try b.u8_(try text.parseU8(tokens[1].text));
            try b.u8_(try text.parseU8(tokens[2].text));
            const hex = try joinTokens(allocator, tokens[3..]);
            defer allocator.free(hex);
            try text.appendHex(out, allocator, hex);
        },
        types.DS, types.CDS => {
            if (tokens.len < 4) return error.WrongTokenCount;
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.u8_(try text.parseU8(tokens[1].text));
            try b.u8_(try text.parseU8(tokens[2].text));
            const hex = try joinTokens(allocator, tokens[3..]);
            defer allocator.free(hex);
            try text.appendHex(out, allocator, hex);
        },
        types.DNSKEY, types.CDNSKEY => {
            if (tokens.len < 4) return error.WrongTokenCount;
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.u8_(try text.parseU8(tokens[1].text));
            try b.u8_(try text.parseU8(tokens[2].text));
            const b64 = try joinTokens(allocator, tokens[3..]);
            defer allocator.free(b64);
            try text.appendBase64(out, allocator, b64);
        },
        types.RRSIG, types.SIG => {
            if (tokens.len < 9) return error.WrongTokenCount;
            const covered = types.typeFromText(tokens[0].text) orelse return error.UnknownType;
            try b.u16_(covered);
            try b.u8_(try text.parseU8(tokens[1].text));
            try b.u8_(try text.parseU8(tokens[2].text));
            try b.u32_(try text.parseU32(tokens[3].text));
            try b.u32_(try text.parseTime(tokens[4].text));
            try b.u32_(try text.parseTime(tokens[5].text));
            try b.u16_(try text.parseU16(tokens[6].text));
            try b.name_(tokens[7]);
            const b64 = try joinTokens(allocator, tokens[8..]);
            defer allocator.free(b64);
            try text.appendBase64(out, allocator, b64);
        },
        types.NSEC => {
            if (tokens.len < 2) return error.WrongTokenCount;
            try b.name_(tokens[0]);
            var tlist: std.ArrayList(u16) = .empty;
            defer tlist.deinit(allocator);
            for (tokens[1..]) |tok| {
                const t = types.typeFromText(tok.text) orelse return error.UnknownType;
                try tlist.append(allocator, t);
            }
            try encodeTypeBitmap(out, allocator, tlist.items);
        },
        types.NSEC3 => {
            if (tokens.len < 6) return error.WrongTokenCount;
            try b.u8_(try text.parseU8(tokens[0].text));
            try b.u8_(try text.parseU8(tokens[1].text));
            try b.u16_(try text.parseU16(tokens[2].text));
            try appendSalt(&b, tokens[3].text);
            const next = try base32hexDecode(allocator, tokens[4].text);
            defer allocator.free(next);
            try b.u8_(@intCast(next.len));
            try out.appendSlice(allocator, next);
            var tlist: std.ArrayList(u16) = .empty;
            defer tlist.deinit(allocator);
            for (tokens[5..]) |tok| {
                const t = types.typeFromText(tok.text) orelse return error.UnknownType;
                try tlist.append(allocator, t);
            }
            try encodeTypeBitmap(out, allocator, tlist.items);
        },
        types.NSEC3PARAM => {
            try expect(tokens, 4);
            try b.u8_(try text.parseU8(tokens[0].text));
            try b.u8_(try text.parseU8(tokens[1].text));
            try b.u16_(try text.parseU16(tokens[2].text));
            try appendSalt(&b, tokens[3].text);
        },
        types.CERT => {
            if (tokens.len < 4) return error.WrongTokenCount;
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.u16_(try text.parseU16(tokens[1].text));
            try b.u8_(try text.parseU8(tokens[2].text));
            const b64 = try joinTokens(allocator, tokens[3..]);
            defer allocator.free(b64);
            try text.appendBase64(out, allocator, b64);
        },
        types.URI => {
            try expect(tokens, 3);
            try b.u16_(try text.parseU16(tokens[0].text));
            try b.u16_(try text.parseU16(tokens[1].text));
            const s = try text.decodedAlloc(allocator, tokens[2].text);
            defer allocator.free(s);
            try out.appendSlice(allocator, s);
        },
        types.LOC => {
            try parseLoc(&b, tokens);
        },
        types.WKS => {
            if (tokens.len < 2) return error.WrongTokenCount;
            const ip = std.Io.net.Ip4Address.parse(tokens[0].text, 0) catch return error.InvalidAddress;
            try out.appendSlice(allocator, &ip.bytes);
            const proto = protocolNumber(tokens[1].text) orelse return error.InvalidRdata;
            try b.u8_(proto);
            var bitmap = std.mem.zeroes([8192]u8);
            var max_port: usize = 0;
            for (tokens[2..]) |tok| {
                const p = try text.parseU16(tok.text);
                if (p > 65535) return error.InvalidRdata;
                bitmap[p / 8] |= @as(u8, 0x80) >> @intCast(p % 8);
                max_port = @max(max_port, p / 8 + 1);
            }
            try out.appendSlice(allocator, bitmap[0..max_port]);
        },
        types.EUI48 => {
            try expect(tokens, 1);
            try appendDashHex(out, allocator, tokens[0].text, 6);
        },
        types.EUI64 => {
            try expect(tokens, 1);
            try appendDashHex(out, allocator, tokens[0].text, 8);
        },
        types.ZONEMD => {
            if (tokens.len < 4) return error.WrongTokenCount;
            try b.u32_(try text.parseU32(tokens[0].text));
            try b.u8_(try text.parseU8(tokens[1].text));
            try b.u8_(try text.parseU8(tokens[2].text));
            const hex = try joinTokens(allocator, tokens[3..]);
            defer allocator.free(hex);
            try text.appendHex(out, allocator, hex);
        },
        types.SVCB, types.HTTPS => {
            try parseSvc(&b, tokens);
        },
        types.CSYNC => {
            if (tokens.len < 3) return error.WrongTokenCount;
            try b.u32_(try text.parseU32(tokens[0].text));
            try b.u16_(try text.parseU16(tokens[1].text));
            var tlist: std.ArrayList(u16) = .empty;
            defer tlist.deinit(allocator);
            for (tokens[2..]) |tok| {
                const t = types.typeFromText(tok.text) orelse return error.UnknownType;
                try tlist.append(allocator, t);
            }
            try encodeTypeBitmap(out, allocator, tlist.items);
        },
        else => {
            return error.UnsupportedType;
        },
    }
    if (out.items.len > 65535) return error.RdataTooLong;
}

const SvcParam = struct {
    key: u16,
    value: []u8,
};

fn parseSvc(b: *Builder, tokens: []const text.Token) !void {
    if (tokens.len < 2) return error.WrongTokenCount;
    try b.u16_(try text.parseU16(tokens[0].text));
    try b.name_(tokens[1]);

    var params: std.ArrayList(SvcParam) = .empty;
    defer {
        for (params.items) |p| b.allocator.free(p.value);
        params.deinit(b.allocator);
    }

    var i: usize = 2;
    while (i < tokens.len) : (i += 1) {
        const tok = tokens[i];
        var key_text: []const u8 = tok.text;
        var raw_value: []const u8 = "";
        var has_value = false;
        if (std.mem.indexOfScalar(u8, tok.text, '=')) |eq| {
            key_text = tok.text[0..eq];
            raw_value = tok.text[eq + 1 ..];
            has_value = true;
            if (raw_value.len == 0 and i + 1 < tokens.len and tokens[i + 1].quoted) {
                i += 1;
                raw_value = tokens[i].text;
            }
        }
        const key = svcParamKey(key_text) orelse return error.InvalidRdata;
        for (params.items) |p| if (p.key == key) return error.InvalidRdata;

        var value: std.ArrayList(u8) = .empty;
        errdefer value.deinit(b.allocator);
        switch (key) {
            0 => { // mandatory
                if (!has_value) return error.InvalidRdata;
                var it = std.mem.splitScalar(u8, raw_value, ',');
                while (it.next()) |part| {
                    const t = std.mem.trim(u8, part, " \t");
                    if (t.len == 0) return error.InvalidRdata;
                    const k = svcParamKey(t) orelse return error.InvalidRdata;
                    try text.appendU16(&value, b.allocator, k);
                }
            },
            1 => { // alpn
                if (!has_value) return error.InvalidRdata;
                var it = std.mem.splitScalar(u8, raw_value, ',');
                while (it.next()) |part| {
                    const t = std.mem.trim(u8, part, " \t");
                    if (t.len == 0 or t.len > 255) return error.InvalidRdata;
                    try value.append(b.allocator, @intCast(t.len));
                    try value.appendSlice(b.allocator, t);
                }
            },
            2 => { // no-default-alpn
                if (has_value and raw_value.len != 0) return error.InvalidRdata;
            },
            3 => { // port
                if (!has_value) return error.InvalidRdata;
                try text.appendU16(&value, b.allocator, try text.parseU16(raw_value));
            },
            4 => { // ipv4hint
                if (!has_value) return error.InvalidRdata;
                var it = std.mem.splitScalar(u8, raw_value, ',');
                while (it.next()) |part| {
                    const t = std.mem.trim(u8, part, " \t");
                    const ip = std.Io.net.Ip4Address.parse(t, 0) catch return error.InvalidRdata;
                    try value.appendSlice(b.allocator, &ip.bytes);
                }
            },
            5 => { // ech
                if (!has_value) return error.InvalidRdata;
                const decoded = try text.decodedAlloc(b.allocator, raw_value);
                defer b.allocator.free(decoded);
                try text.appendBase64(&value, b.allocator, decoded);
            },
            6 => { // ipv6hint
                if (!has_value) return error.InvalidRdata;
                var it = std.mem.splitScalar(u8, raw_value, ',');
                while (it.next()) |part| {
                    const t = std.mem.trim(u8, part, " \t");
                    const ip = std.Io.net.Ip6Address.parse(t, 0) catch return error.InvalidRdata;
                    try value.appendSlice(b.allocator, &ip.bytes);
                }
            },
            7 => { // dohpath
                if (!has_value) return error.InvalidRdata;
                const decoded = try text.decodedAlloc(b.allocator, raw_value);
                defer b.allocator.free(decoded);
                try value.appendSlice(b.allocator, decoded);
            },
            else => {
                if (has_value) {
                    const decoded = try text.decodedAlloc(b.allocator, raw_value);
                    defer b.allocator.free(decoded);
                    try value.appendSlice(b.allocator, decoded);
                }
            },
        }
        try params.append(b.allocator, .{ .key = key, .value = try value.toOwnedSlice(b.allocator) });
    }

    std.mem.sort(SvcParam, params.items, {}, svcParamLess);
    for (params.items) |p| {
        if (p.value.len > 65535) return error.RdataTooLong;
        try b.u16_(p.key);
        try b.u16_(@intCast(p.value.len));
        try b.out.appendSlice(b.allocator, p.value);
    }
}

fn svcParamLess(_: void, a: SvcParam, b: SvcParam) bool {
    return a.key < b.key;
}

fn svcParamKey(text_: []const u8) ?u16 {
    if (std.ascii.eqlIgnoreCase(text_, "mandatory")) return 0;
    if (std.ascii.eqlIgnoreCase(text_, "alpn")) return 1;
    if (std.ascii.eqlIgnoreCase(text_, "no-default-alpn")) return 2;
    if (std.ascii.eqlIgnoreCase(text_, "port")) return 3;
    if (std.ascii.eqlIgnoreCase(text_, "ipv4hint")) return 4;
    if (std.ascii.eqlIgnoreCase(text_, "ech")) return 5;
    if (std.ascii.eqlIgnoreCase(text_, "ipv6hint")) return 6;
    if (std.ascii.eqlIgnoreCase(text_, "dohpath")) return 7;
    if (std.ascii.startsWithIgnoreCase(text_, "key")) {
        return std.fmt.parseInt(u16, text_[3..], 10) catch null;
    }
    return null;
}

fn parseLoc(b: *Builder, tokens: []const text.Token) !void {
    var i: usize = 0;
    const lat_deg = try parseFloatToken(tokens, &i);
    var lat_min: f64 = 0;
    var lat_sec: f64 = 0;
    if (i < tokens.len and isNumeric(tokens[i].text) and !isDirection(tokens[i].text)) {
        lat_min = try parseFloatToken(tokens, &i);
    }
    if (i < tokens.len and isNumeric(tokens[i].text) and !isDirection(tokens[i].text)) {
        lat_sec = try parseFloatToken(tokens, &i);
    }
    if (i >= tokens.len) return error.InvalidRdata;
    const ns = tokens[i].text[0];
    i += 1;
    const lon_deg = try parseFloatToken(tokens, &i);
    var lon_min: f64 = 0;
    var lon_sec: f64 = 0;
    if (i < tokens.len and isNumeric(tokens[i].text) and !isDirection(tokens[i].text)) {
        lon_min = try parseFloatToken(tokens, &i);
    }
    if (i < tokens.len and isNumeric(tokens[i].text) and !isDirection(tokens[i].text)) {
        lon_sec = try parseFloatToken(tokens, &i);
    }
    if (i >= tokens.len) return error.InvalidRdata;
    const ew = tokens[i].text[0];
    i += 1;
    if (lat_deg < 0 or lat_deg > 90 or lat_min < 0 or lat_min > 59 or lat_sec < 0 or lat_sec >= 60) return error.InvalidRdata;
    if (lon_deg < 0 or lon_deg > 180 or lon_min < 0 or lon_min > 59 or lon_sec < 0 or lon_sec >= 60) return error.InvalidRdata;
    if ((ns != 'N' and ns != 'n' and ns != 'S' and ns != 's') or
        (ew != 'E' and ew != 'e' and ew != 'W' and ew != 'w')) return error.InvalidRdata;

    const alt = try parseMeters(tokens, &i);
    var size: f64 = 1.0;
    var hp: f64 = 10000.0;
    var vp: f64 = 10.0;
    if (i < tokens.len) {
        size = try parseMeters(tokens, &i);
    }
    if (i < tokens.len) {
        hp = try parseMeters(tokens, &i);
    }
    if (i < tokens.len) {
        vp = try parseMeters(tokens, &i);
    }
    if (i != tokens.len) return error.InvalidRdata;

    const lat_ms: u64 = @intFromFloat((lat_deg * 3600.0 + lat_min * 60.0 + lat_sec) * 1000.0);
    const lon_ms: u64 = @intFromFloat((lon_deg * 3600.0 + lon_min * 60.0 + lon_sec) * 1000.0);
    if (lat_ms > 0x7fffffff or lon_ms > 0x7fffffff) return error.InvalidRdata;
    const lat: u32 = if (ns == 'N' or ns == 'n') @intCast(0x80000000 + lat_ms) else @intCast(0x80000000 - lat_ms);
    const lon: u32 = if (ew == 'E' or ew == 'e') @intCast(0x80000000 + lon_ms) else @intCast(0x80000000 - lon_ms);
    const alt_cm: i64 = @intFromFloat((alt + 100000.0) * 100.0);
    if (alt_cm < 0 or alt_cm > 0xffffffff) return error.InvalidRdata;

    try b.u8_(0);
    try b.u8_(encodeLocPrecision(size));
    try b.u8_(encodeLocPrecision(hp));
    try b.u8_(encodeLocPrecision(vp));
    try b.u32_(lat);
    try b.u32_(lon);
    try b.u32_(@intCast(alt_cm));
}

fn parseFloatToken(tokens: []const text.Token, i: *usize) !f64 {
    if (i.* >= tokens.len) return error.InvalidRdata;
    const v = std.fmt.parseFloat(f64, tokens[i.*].text) catch return error.InvalidRdata;
    i.* += 1;
    return v;
}

fn isNumeric(s: []const u8) bool {
    if (s.len == 0) return false;
    return std.ascii.isDigit(s[0]) or s[0] == '-' or s[0] == '+';
}

fn isDirection(s: []const u8) bool {
    return s.len == 1 and (std.ascii.toUpper(s[0]) == 'N' or std.ascii.toUpper(s[0]) == 'S' or std.ascii.toUpper(s[0]) == 'E' or std.ascii.toUpper(s[0]) == 'W');
}

fn parseMeters(tokens: []const text.Token, i: *usize) !f64 {
    if (i.* >= tokens.len) return error.InvalidRdata;
    var s = tokens[i.*].text;
    if (s.len > 0 and (s[s.len - 1] == 'm' or s[s.len - 1] == 'M')) s = s[0 .. s.len - 1];
    const v = std.fmt.parseFloat(f64, s) catch return error.InvalidRdata;
    i.* += 1;
    return v;
}

fn encodeLocPrecision(meters: f64) u8 {
    var cm = @max(meters, 0.0) * 100.0;
    var exp: u8 = 0;
    while (cm >= 10.0 and exp < 9) {
        cm /= 10.0;
        exp += 1;
    }
    var mant: u8 = @intFromFloat(@round(cm));
    if (mant > 9) {
        mant = 1;
        if (exp < 15) exp += 1;
    }
    return (mant << 4) | exp;
}

fn appendSalt(b: *Builder, token_text: []const u8) !void {
    if (std.mem.eql(u8, token_text, "-")) {
        try b.u8_(0);
        return;
    }
    const before = b.out.items.len;
    try text.appendHex(b.out, b.allocator, token_text);
    const salt_len = b.out.items.len - before;
    if (salt_len > 255) return error.RdataTooLong;
    // Insert the length octet before the salt.  The salt is small, so a
    // single memmove is fine.
    try b.out.insert(b.allocator, before, @intCast(salt_len));
}

fn protocolNumber(s: []const u8) ?u8 {
    if (std.ascii.eqlIgnoreCase(s, "tcp")) return 6;
    if (std.ascii.eqlIgnoreCase(s, "udp")) return 17;
    if (std.ascii.eqlIgnoreCase(s, "icmp")) return 1;
    return std.fmt.parseInt(u8, s, 10) catch null;
}

fn appendDashHex(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8, expected: usize) !void {
    var i: usize = 0;
    var count: usize = 0;
    while (i < s.len) {
        if (s[i] == '-') {
            i += 1;
            continue;
        }
        if (i + 2 > s.len) return error.InvalidHex;
        try text.appendHex(out, allocator, s[i .. i + 2]);
        i += 2;
        count += 1;
    }
    if (count != expected) return error.InvalidHex;
}

fn expect(tokens: []const text.Token, n: usize) !void {
    if (tokens.len != n) return error.WrongTokenCount;
}

fn joinTokens(allocator: std.mem.Allocator, tokens: []const text.Token) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (tokens, 0..) |tok, i| {
        if (i != 0) try out.append(allocator, ' ');
        try out.appendSlice(allocator, tok.text);
    }
    return out.toOwnedSlice(allocator);
}

fn parseGeneric(allocator: std.mem.Allocator, tokens: []const text.Token, out: *std.ArrayList(u8)) Error!void {
    if (tokens.len < 2) return error.WrongTokenCount;
    const declared = std.fmt.parseInt(usize, tokens[1].text, 10) catch return error.InvalidRdata;
    const hex = try joinTokens(allocator, tokens[2..]);
    defer allocator.free(hex);
    var cleaned: std.ArrayList(u8) = .empty;
    defer cleaned.deinit(allocator);
    for (hex) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        try cleaned.append(allocator, c);
    }
    try text.appendHex(out, allocator, cleaned.items);
    if (out.items.len != declared) return error.InvalidRdata;
}

/// RFC 4034 section 4.1.2 NSEC type bitmap encoding.  Windows are emitted in
/// increasing order and bits run from the most significant bit of the first
/// octet.
pub fn encodeTypeBitmap(out: *std.ArrayList(u8), allocator: std.mem.Allocator, input: []const u16) !void {
    if (input.len == 0) return;
    var sorted: std.ArrayList(u16) = .empty;
    defer sorted.deinit(allocator);
    try sorted.appendSlice(allocator, input);
    std.mem.sort(u16, sorted.items, {}, std.sort.asc(u16));

    var i: usize = 0;
    while (i < sorted.items.len) {
        const window: u8 = @intCast(sorted.items[i] >> 8);
        var end = i;
        while (end < sorted.items.len and sorted.items[end] >> 8 == window) end += 1;
        var max_off: usize = 0;
        for (sorted.items[i..end]) |t| max_off = @max(max_off, t & 0xff);
        const bitmap_len = max_off / 8 + 1;
        if (bitmap_len > 32) return error.InvalidTypeBitmap;
        try out.append(allocator, window);
        try out.append(allocator, @intCast(bitmap_len));
        const start = out.items.len;
        try out.appendNTimes(allocator, 0, bitmap_len);
        for (sorted.items[i..end]) |t| {
            const off = t & 0xff;
            out.items[start + off / 8] |= @as(u8, 0x80) >> @intCast(off % 8);
        }
        i = end;
    }
}

/// Decodes RFC 4034 type bitmaps into a caller-provided list.  Used by
/// diagnostics and by the NSEC proof code.
pub fn decodeTypeBitmap(allocator: std.mem.Allocator, data: []const u8, out: *std.ArrayList(u16)) !void {
    var i: usize = 0;
    var last_window: ?u8 = null;
    while (i < data.len) {
        if (i + 2 > data.len) return error.InvalidTypeBitmap;
        const window = data[i];
        const len = data[i + 1];
        i += 2;
        if (len == 0 or len > 32) return error.InvalidTypeBitmap;
        if (i + len > data.len) return error.InvalidTypeBitmap;
        if (last_window) |lw| if (window <= lw) return error.InvalidTypeBitmap;
        last_window = window;
        for (0..len) |byte_i| {
            const byte = data[i + byte_i];
            for (0..8) |bit| {
                if (byte & (@as(u8, 0x80) >> @intCast(bit)) != 0) {
                    try out.append(allocator, @as(u16, window) << 8 | @as(u16, @intCast(byte_i * 8 + bit)));
                }
            }
        }
        i += len;
    }
}

/// RFC 4648 section 7 base32hex (extended hex alphabet), without padding.
fn base32hexDecode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var acc: u64 = 0;
    var bits: u6 = 0;
    for (s) |c| {
        const v: u8 = switch (c) {
            '0'...'9' => c - '0',
            'A'...'V' => c - 'A' + 10,
            'a'...'v' => c - 'a' + 10,
            '=' => continue,
            else => return error.InvalidRdata,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            try out.append(allocator, @intCast((acc >> bits) & 0xff));
        }
    }
    return out.toOwnedSlice(allocator);
}

/// Presentation form of the common RDATA types, for diagnostics and the
/// `checkzone --print` mode.  Unknown types are emitted as RFC 3597 \# form.
pub fn toText(
    allocator: std.mem.Allocator,
    rtype: u16,
    rdata: []const u8,
    writer: *std.Io.Writer,
) !void {
    switch (rtype) {
        types.A => {
            if (rdata.len != 4) return error.InvalidRdata;
            try writer.print("{d}.{d}.{d}.{d}", .{ rdata[0], rdata[1], rdata[2], rdata[3] });
        },
        types.AAAA => {
            if (rdata.len != 16) return error.InvalidRdata;
            var addr: std.Io.net.Ip6Address = undefined;
            @memcpy(&addr.bytes, rdata);
            try writer.print("{f}", .{addr});
        },
        types.NS, types.CNAME, types.PTR, types.DNAME => {
            var n: name.Name = undefined;
            const next = name.parseWire(rdata, 0, &n) catch return error.InvalidRdata;
            if (next != rdata.len) return error.InvalidRdata;
            try n.writeText(writer);
        },
        types.MX => {
            if (rdata.len < 3) return error.InvalidRdata;
            var n: name.Name = undefined;
            const next = name.parseWire(rdata, 2, &n) catch return error.InvalidRdata;
            if (next != rdata.len) return error.InvalidRdata;
            try writer.print("{d} ", .{(@as(u16, rdata[0]) << 8) | rdata[1]});
            try n.writeText(writer);
        },
        types.SRV => {
            if (rdata.len < 7) return error.InvalidRdata;
            var n: name.Name = undefined;
            const next = name.parseWire(rdata, 6, &n) catch return error.InvalidRdata;
            if (next != rdata.len) return error.InvalidRdata;
            const pri = (@as(u16, rdata[0]) << 8) | rdata[1];
            const weight = (@as(u16, rdata[2]) << 8) | rdata[3];
            const port = (@as(u16, rdata[4]) << 8) | rdata[5];
            try writer.print("{d} {d} {d} ", .{ pri, weight, port });
            try n.writeText(writer);
        },
        types.SOA => {
            if (rdata.len < 22) return error.InvalidRdata;
            var mname: name.Name = undefined;
            var n = name.parseWire(rdata, 0, &mname) catch return error.InvalidRdata;
            var rname: name.Name = undefined;
            const rn = name.parseWire(rdata, n, &rname) catch return error.InvalidRdata;
            n = rn;
            if (n + 20 != rdata.len) return error.InvalidRdata;
            const serial = readU32(rdata, n);
            const refresh = readU32(rdata, n + 4);
            const retry = readU32(rdata, n + 8);
            const expire = readU32(rdata, n + 12);
            const minimum = readU32(rdata, n + 16);
            try mname.writeText(writer);
            try writer.writeByte(' ');
            try rname.writeText(writer);
            try writer.print(" {d} {d} {d} {d} {d}", .{ serial, refresh, retry, expire, minimum });
        },
        types.TXT, types.SPF => {
            var i: usize = 0;
            var first = true;
            while (i < rdata.len) {
                const l = rdata[i];
                i += 1;
                if (i + l > rdata.len) return error.InvalidRdata;
                if (!first) try writer.writeByte(' ');
                first = false;
                try writer.writeByte('"');
                for (rdata[i .. i + l]) |c| {
                    if (c == '"' or c == '\\') {
                        try writer.writeByte('\\');
                        try writer.writeByte(c);
                    } else if (c >= ' ' and c <= '~') {
                        try writer.writeByte(c);
                    } else {
                        try writer.print("\\{d:0>3}", .{c});
                    }
                }
                try writer.writeByte('"');
                i += l;
            }
        },
        types.DNSKEY, types.CDNSKEY, types.DS, types.CDS, types.RRSIG, types.NSEC, types.TLSA, types.SSHFP, types.CAA => {
            try writeGeneric(allocator, rdata, writer);
        },
        else => try writeGeneric(allocator, rdata, writer),
    }
}

fn writeGeneric(allocator: std.mem.Allocator, rdata: []const u8, writer: *std.Io.Writer) !void {
    _ = allocator;
    try writer.print("\\# {d} ", .{rdata.len});
    for (rdata) |c| try writer.print("{X:0>2}", .{c});
}

fn readU32(data: []const u8, off: usize) u32 {
    return (@as(u32, data[off]) << 24) | (@as(u32, data[off + 1]) << 16) |
        (@as(u32, data[off + 2]) << 8) | data[off + 3];
}

test "parse A and MX" {
    const allocator = std.testing.allocator;
    var origin = try name.parseText("example.com.", null);
    const ctx: Context = .{ .origin = &origin };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    const a_tokens = [_]text.Token{.{ .text = "192.0.2.1" }};
    try parse(allocator, types.A, &a_tokens, ctx, &out);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, out.items);

    out.clearRetainingCapacity();
    const mx_tokens = [_]text.Token{ .{ .text = "10" }, .{ .text = "mail" } };
    try parse(allocator, types.MX, &mx_tokens, ctx, &out);
    try std.testing.expectEqualSlices(u8, "\x00\x0a\x04mail\x07example\x03com\x00", out.items);
}

test "parse generic rfc3597" {
    const allocator = std.testing.allocator;
    var origin = try name.parseText("example.com.", null);
    const ctx: Context = .{ .origin = &origin };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const tokens = [_]text.Token{ .{ .text = "\\#" }, .{ .text = "2" }, .{ .text = "c000" } };
    try parse(allocator, 999, &tokens, ctx, &out);
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00 }, out.items);
}

test "parse SVCB" {
    const allocator = std.testing.allocator;
    var origin = try name.parseText("example.com.", null);
    const ctx: Context = .{ .origin = &origin };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const tokens = [_]text.Token{
        .{ .text = "1" },
        .{ .text = "svc" },
        .{ .text = "alpn=h2,h3" },
        .{ .text = "port=8443" },
        .{ .text = "ipv4hint=192.0.2.1" },
    };
    try parse(allocator, types.SVCB, &tokens, ctx, &out);
    // priority 1, target svc.example.com, then params sorted: alpn(1), port(3), ipv4hint(4)
    try std.testing.expectEqual(@as(u8, 0), out.items[0]);
    try std.testing.expectEqual(@as(u8, 1), out.items[1]);
    try std.testing.expectEqual(@as(u8, 3), out.items[2]); // svc label
    try std.testing.expectEqual(@as(u8, 's'), out.items[3]);
    // ... name follows; just ensure it encoded
    try std.testing.expect(out.items.len > 20);
}

test "parse LOC" {
    const allocator = std.testing.allocator;
    var origin = try name.parseText("example.com.", null);
    const ctx: Context = .{ .origin = &origin };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    const tokens = [_]text.Token{
        .{ .text = "42" },   .{ .text = "21" },  .{ .text = "54" }, .{ .text = "N" },
        .{ .text = "71" },   .{ .text = "06" },  .{ .text = "18" }, .{ .text = "W" },
        .{ .text = "-24m" }, .{ .text = "30m" },
    };
    try parse(allocator, types.LOC, &tokens, ctx, &out);
    try std.testing.expectEqual(@as(usize, 16), out.items.len);
    try std.testing.expectEqual(@as(u8, 0), out.items[0]);
}

test "type bitmap" {
    const allocator = std.testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try encodeTypeBitmap(&out, allocator, &.{ 1, 2, 6, 15, 46, 47 });
    // window 0, length 6, bits for 1,2,6,15,46,47
    try std.testing.expectEqual(@as(u8, 0), out.items[0]);
    try std.testing.expectEqual(@as(u8, 6), out.items[1]);
    try std.testing.expectEqual(@as(u8, 0x62), out.items[2]);
    var decoded: std.ArrayList(u16) = .empty;
    defer decoded.deinit(allocator);
    try decodeTypeBitmap(allocator, out.items, &decoded);
    try std.testing.expectEqualSlices(u16, &.{ 1, 2, 6, 15, 46, 47 }, decoded.items);
}
