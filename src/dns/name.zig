//! Domain names in wire format.
//!
//! A `Name` owns a fixed 255-byte buffer containing uncompressed wire-format
//! labels.  Keeping the wire form (rather than a slice of presentation text)
//! makes RFC 1035 section 4.1.4 compression handling and RFC 4034 canonical
//! ordering straightforward and avoids allocations in the query path.
//!
//! References:
//!   * RFC 1035 sections 2.3.4, 3.1, 4.1.4
//!   * RFC 2181 section 11 (name length limits)
//!   * RFC 4343 (case insensitivity)
//!   * RFC 4034 section 6.1 (canonical name order)

const std = @import("std");

pub const max_name_len: usize = 255;
pub const max_label_len: usize = 63;
pub const max_pointer_jumps: usize = 128;

pub const Error = error{
    NameTooLong,
    LabelTooLong,
    EmptyLabel,
    Truncated,
    BadPointer,
    PointerLoop,
    BadLabelType,
    InvalidText,
};

pub const Name = struct {
    buf: [max_name_len]u8 = undefined,
    len: u8 = 1,

    pub fn root() Name {
        var n: Name = .{ .buf = undefined, .len = 1 };
        n.buf[0] = 0;
        return n;
    }

    pub fn init(bytes: []const u8) Error!Name {
        if (bytes.len == 0 or bytes.len > max_name_len) return error.NameTooLong;
        if (bytes[bytes.len - 1] != 0) return error.InvalidText;
        var n: Name = .{ .len = @intCast(bytes.len) };
        @memcpy(n.buf[0..bytes.len], bytes);
        try n.validate();
        return n;
    }

    pub fn validate(n: *const Name) Error!void {
        if (n.len == 0 or n.len > max_name_len) return error.NameTooLong;
        var i: usize = 0;
        while (i < n.len) {
            const l = n.buf[i];
            if (l == 0) {
                if (i != n.len - 1) return error.InvalidText;
                return;
            }
            if (l & 0xc0 != 0) return error.BadLabelType;
            if (l > max_label_len) return error.LabelTooLong;
            i += 1;
            if (i + l > n.len) return error.Truncated;
            i += l;
        }
        return error.InvalidText;
    }

    pub fn slice(n: *const Name) []const u8 {
        return n.buf[0..n.len];
    }

    pub fn isRoot(n: *const Name) bool {
        return n.len == 1 and n.buf[0] == 0;
    }

    /// RFC 4343: labels are compared case-insensitively, but the original
    /// octets are preserved for the question section echo.
    pub fn eqlIgnoreCase(a: *const Name, b: *const Name) bool {
        if (a.len != b.len) return false;
        var i: usize = 0;
        while (i < a.len) {
            const la = a.buf[i];
            const lb = b.buf[i];
            if (la != lb) return false;
            i += 1;
            if (la == 0) return true;
            const end = i + la;
            if (end > a.len) return false;
            var j: usize = 0;
            while (j < la) : (j += 1) {
                if (lower(a.buf[i + j]) != lower(b.buf[i + j])) return false;
            }
            i = end;
        }
        return true;
    }

    pub fn eql(a: *const Name, b: *const Name) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }

    /// True when `n` is `parent` or a descendant of it.  The wire encoding
    /// makes this a suffix test at a label boundary.
    pub fn isSubdomainOf(n: *const Name, zone: *const Name) bool {
        if (zone.len > n.len) return false;
        if (!std.mem.eql(u8, n.buf[n.len - zone.len .. n.len], zone.slice())) return false;
        return true;
    }

    pub fn parent(n: *const Name) ?Name {
        if (n.len <= 1) return null;
        const first_label_len = n.buf[0];
        const rest = n.len - 1 - first_label_len;
        if (rest == 0) return Name.root();
        var p: Name = .{ .len = rest };
        @memcpy(p.buf[0..rest], n.buf[1 + first_label_len ..][0..rest]);
        return p;
    }

    /// Number of labels excluding the root label.
    pub fn labelCount(n: *const Name) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < n.len and n.buf[i] != 0) {
            count += 1;
            i += 1 + n.buf[i];
        }
        return count;
    }

    /// Returns the labels in wire form (without the root label).
    pub fn labels(n: *const Name, out: *[max_labels]struct { off: u8, len: u8 }) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < n.len and n.buf[i] != 0) {
            out[count] = .{ .off = @intCast(i), .len = n.buf[i] };
            count += 1;
            i += 1 + n.buf[i];
        }
        return count;
    }

    /// RFC 4034 section 6.1 canonical ordering: compare label sequences from
    /// the root towards the leaf, case-insensitively.  A name that is a
    /// proper suffix sorts before its descendants.
    pub fn canonicalCompare(a: *const Name, b: *const Name) std.math.Order {
        var ai: [max_labels]u8 = undefined;
        var bi: [max_labels]u8 = undefined;
        const ac = a.labelOffsets(&ai);
        const bc = b.labelOffsets(&bi);
        var i: usize = 1;
        while (i <= @min(ac, bc)) : (i += 1) {
            const al = a.buf[ai[ac - i]];
            const bl = b.buf[bi[bc - i]];
            const aoff = ai[ac - i] + 1;
            const boff = bi[bc - i] + 1;
            const n = @min(al, bl);
            var j: usize = 0;
            while (j < n) : (j += 1) {
                const x = lower(a.buf[aoff + j]);
                const y = lower(b.buf[boff + j]);
                if (x < y) return .lt;
                if (x > y) return .gt;
            }
            if (al < bl) return .lt;
            if (al > bl) return .gt;
        }
        if (ac < bc) return .lt;
        if (ac > bc) return .gt;
        return .eq;
    }

    fn labelOffsets(n: *const Name, out: *[max_labels]u8) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < n.len and n.buf[i] != 0) {
            if (count == max_labels) break;
            out[count] = @intCast(i);
            count += 1;
            i += 1 + n.buf[i];
        }
        return count;
    }

    fn wireLabelOffsets(n: []const u8, out: *[max_labels]u8) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < n.len and n[i] != 0) {
            if (count == max_labels) break;
            out[count] = @intCast(i);
            count += 1;
            i += 1 + n[i];
        }
        return count;
    }

    /// Canonical ordering for wire-format names (RFC 4034 section 6.1),
    /// without constructing a `Name`.  Used to sort large zones cheaply.
    pub fn canonicalCompareWire(a: []const u8, b: []const u8) std.math.Order {
        var ai: [max_labels]u8 = undefined;
        var bi: [max_labels]u8 = undefined;
        const ac = wireLabelOffsets(a, &ai);
        const bc = wireLabelOffsets(b, &bi);
        var i: usize = 1;
        while (i <= @min(ac, bc)) : (i += 1) {
            const aoff = ai[ac - i];
            const boff = bi[bc - i];
            const al = a[aoff];
            const bl = b[boff];
            const n = @min(al, bl);
            var j: usize = 0;
            while (j < n) : (j += 1) {
                const x = lower(a[aoff + 1 + j]);
                const y = lower(b[boff + 1 + j]);
                if (x < y) return .lt;
                if (x > y) return .gt;
            }
            if (al < bl) return .lt;
            if (al > bl) return .gt;
        }
        if (ac < bc) return .lt;
        if (ac > bc) return .gt;
        return .eq;
    }

    /// Presentation format.  Dots and backslashes inside labels are escaped,
    /// as are non-printable octets, using the RFC 1035 \DDD form.
    pub fn writeText(n: *const Name, writer: anytype) !void {
        if (n.isRoot()) {
            try writer.writeByte('.');
            return;
        }
        var i: usize = 0;
        while (i < n.len and n.buf[i] != 0) {
            const l = n.buf[i];
            i += 1;
            var j: usize = 0;
            while (j < l) : (j += 1) {
                const c = n.buf[i + j];
                if (c == '.' or c == '\\' or c == ';' or c == '(' or c == ')' or c == '"') {
                    try writer.writeByte('\\');
                    try writer.writeByte(c);
                } else if (c >= ' ' and c <= '~') {
                    try writer.writeByte(c);
                } else {
                    try writer.print("\\{d:0>3}", .{c});
                }
            }
            try writer.writeByte('.');
            i += l;
        }
    }

    pub fn toText(n: *const Name, buf: []u8) ![]const u8 {
        var fbs = std.Io.Writer.fixed(buf);
        try n.writeText(&fbs);
        return fbs.buffered();
    }

    pub fn format(n: *const Name, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try n.writeText(writer);
    }
};

fn lower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

pub const max_labels = 127;

/// Parses presentation-format text into a wire-format name.
///
/// `origin` is appended to relative names.  "@" denotes the origin.  A
/// trailing dot makes the name absolute.  Escapes are the RFC 1035 master
/// file escapes: `\DDD` (three decimal digits) and `\X`.
pub fn parseText(text: []const u8, origin: ?*const Name) Error!Name {
    if (text.len == 0) return error.InvalidText;
    if (std.mem.eql(u8, text, "@")) {
        if (origin) |o| return o.*;
        return error.InvalidText;
    }
    if (std.mem.eql(u8, text, ".")) return Name.root();

    var n: Name = .{ .len = 0 };
    var len_pos: usize = 0;
    if (!reserveLabel(&n)) return error.NameTooLong;
    var label_len: usize = 0;
    var i: usize = 0;
    var absolute = false;

    while (i < text.len) {
        const c = text[i];
        if (c == '\\') {
            if (i + 1 >= text.len) return error.InvalidText;
            const e = text[i + 1];
            if (e >= '0' and e <= '9') {
                if (i + 3 >= text.len) return error.InvalidText;
                const d0 = text[i + 1] - '0';
                const d1 = text[i + 2] - '0';
                const d2 = text[i + 3] - '0';
                if (d1 > 9 or d2 > 9) return error.InvalidText;
                const v: u16 = @as(u16, d0) * 100 + @as(u16, d1) * 10 + d2;
                if (v > 255) return error.InvalidText;
                if (!appendLabelByte(&n, &label_len, @intCast(v))) return error.NameTooLong;
                i += 4;
                absolute = false;
            } else {
                if (!appendLabelByte(&n, &label_len, e)) return error.NameTooLong;
                i += 2;
                absolute = false;
            }
            continue;
        }
        if (c == '.') {
            if (label_len == 0) return error.EmptyLabel;
            if (label_len > max_label_len) return error.LabelTooLong;
            n.buf[len_pos] = @intCast(label_len);
            label_len = 0;
            absolute = true;
            i += 1;
            if (i < text.len) {
                absolute = false;
                if (!reserveLabel(&n)) return error.NameTooLong;
                len_pos = n.len - 1;
            }
            continue;
        }
        if (!appendLabelByte(&n, &label_len, c)) return error.NameTooLong;
        absolute = false;
        i += 1;
    }

    if (label_len > max_label_len) return error.LabelTooLong;
    if (!absolute or label_len != 0) n.buf[len_pos] = @intCast(label_len);
    if (!absolute) {
        if (origin) |o| {
            if (n.len + o.len > max_name_len) return error.NameTooLong;
            @memcpy(n.buf[n.len..][0..o.len], o.slice());
            n.len += o.len;
        } else {
            return error.InvalidText;
        }
    } else {
        if (n.len + 1 > max_name_len) return error.NameTooLong;
        n.buf[n.len] = 0;
        n.len += 1;
    }
    try n.validate();
    return n;
}

fn reserveLabel(n: *Name) bool {
    if (n.len + 1 > max_name_len) return false;
    n.len += 1;
    return true;
}

fn appendLabelByte(n: *Name, label_len: *usize, c: u8) bool {
    if (label_len.* >= max_label_len) return false;
    if (n.len + 1 > max_name_len) return false;
    n.buf[n.len] = c;
    n.len += 1;
    label_len.* += 1;
    return true;
}

/// Lowercases a wire-format name in place.  Used to build the canonical form
/// required by RFC 4034 section 6.2.  (The original case is only needed for
/// the question echo, which is copied verbatim from the request.)
pub fn lowerInPlace(wire: []u8) void {
    var i: usize = 0;
    while (i < wire.len and wire[i] != 0) {
        const l = wire[i];
        i += 1;
        var j: usize = 0;
        while (j < l) : (j += 1) {
            wire[i + j] = lower(wire[i + j]);
        }
        i += l;
    }
}

pub fn eqlWireIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (lower(x) != lower(y)) return false;
    }
    return true;
}

/// Decompresses a name at `offset` in `msg`, returning the name and the offset
/// immediately after the encoded name in the original message.
pub fn parseWire(msg: []const u8, offset: usize, out: *Name) Error!usize {
    if (offset >= msg.len) return error.Truncated;
    var pos = offset;
    var next: ?usize = null;
    var jumps: usize = 0;
    var total: usize = 0;
    out.len = 0;

    while (true) {
        if (pos >= msg.len) return error.Truncated;
        const l = msg[pos];
        if (l == 0) {
            if (total + 1 > max_name_len) return error.NameTooLong;
            out.buf[total] = 0;
            total += 1;
            out.len = @intCast(total);
            return next orelse (pos + 1);
        }
        switch (l & 0xc0) {
            0x00 => {
                if (l > max_label_len) return error.LabelTooLong;
                if (pos + 1 + l > msg.len) return error.Truncated;
                if (total + 1 + l > max_name_len) return error.NameTooLong;
                out.buf[total] = l;
                @memcpy(out.buf[total + 1 ..][0..l], msg[pos + 1 ..][0..l]);
                total += 1 + l;
                pos += 1 + l;
            },
            0xc0 => {
                if (pos + 2 > msg.len) return error.Truncated;
                const ptr = (@as(u16, msg[pos] & 0x3f) << 8) | msg[pos + 1];
                if (ptr >= msg.len) return error.BadPointer;
                // RFC 1035: a pointer points to a prior occurrence.  Reject
                // forward pointers and loops.
                if (ptr >= pos) return error.BadPointer;
                if (jumps >= max_pointer_jumps) return error.PointerLoop;
                jumps += 1;
                if (next == null) next = pos + 2;
                pos = ptr;
            },
            else => return error.BadLabelType,
        }
    }
}

/// Writes a name with RFC 1035 compression.  `suffixes` records offsets of
/// labels already written in `buf` so that later names can point at them.
pub const Compressor = struct {
    const Entry = struct { off: u16, len: u8 };
    const SuffixMatch = struct { suffix_off: usize, target: u16 };
    entries: [128]Entry = undefined,
    count: usize = 0,

    pub fn reset(c: *Compressor) void {
        c.count = 0;
    }

    /// Finds the longest suffix of `name` that is already present in `buf`.
    fn find(c: *const Compressor, buf: []const u8, name: []const u8) ?SuffixMatch {
        var best: ?SuffixMatch = null;
        var i: usize = 0;
        while (i < name.len and name[i] != 0) {
            for (c.entries[0..c.count]) |e| {
                if (e.off + e.len > buf.len) continue;
                if (wireSuffixEql(buf[e.off..][0..e.len], name[i..])) {
                    if (best == null or i < best.?.suffix_off) {
                        best = .{ .suffix_off = i, .target = e.off };
                    }
                    break;
                }
            }
            i += 1 + name[i];
        }
        return best;
    }

    fn wireSuffixEql(a: []const u8, b: []const u8) bool {
        // Both slices are complete suffixes ending at the root label.  They
        // are interchangeable only when they have exactly the same length;
        // a shorter entry would drop labels from the current name.
        if (a.len != b.len) return false;
        return eqlWireIgnoreCase(a, b);
    }

    /// Appends `name` to `buf` starting at `buf.len`, using compression when
    /// possible, and records new suffixes.  `buf` must be the full message
    /// written so far (header included).
    pub fn write(c: *Compressor, buf: []u8, pos: *usize, name: []const u8) !void {
        if (pos.* >= buf.len) return error.NoSpace;
        const found = c.find(buf[0..pos.*], name);
        const end = if (found) |f| f.suffix_off else name.len;
        var i: usize = 0;
        while (i < end and name[i] != 0) {
            if (pos.* + 1 + name[i] > buf.len) return error.NoSpace;
            if (c.count < c.entries.len and pos.* < 0x4000) {
                c.entries[c.count] = .{ .off = @intCast(pos.*), .len = @intCast(name.len - i) };
                c.count += 1;
            }
            buf[pos.*] = name[i];
            @memcpy(buf[pos.* + 1 ..][0..name[i]], name[i + 1 ..][0..name[i]]);
            pos.* += 1 + name[i];
            i += 1 + name[i];
        }
        if (found) |f| {
            if (pos.* + 2 > buf.len) return error.NoSpace;
            buf[pos.*] = 0xc0 | @as(u8, @intCast(f.target >> 8));
            buf[pos.* + 1] = @intCast(f.target & 0xff);
            pos.* += 2;
        } else {
            if (pos.* + 1 > buf.len) return error.NoSpace;
            buf[pos.*] = 0;
            pos.* += 1;
        }
    }
};

test "parse and render names" {
    var origin = try parseText("example.com.", null);
    const www = try parseText("www", &origin);
    try std.testing.expectEqualStrings("\x03www\x07example\x03com\x00", www.slice());
    try std.testing.expectEqualStrings("\x07example\x03com\x00", origin.slice());
    try std.testing.expect(www.labelCount() == 3);
    try std.testing.expect(www.isSubdomainOf(&origin));
    try std.testing.expect(!origin.isSubdomainOf(&www));

    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com.", try www.toText(&buf));
}

test "case-insensitive comparison preserves bytes" {
    var a = try parseText("WWW.Example.COM.", null);
    var b = try parseText("www.example.com.", null);
    try std.testing.expect(a.eqlIgnoreCase(&b));
    try std.testing.expect(!a.eql(&b));
}

test "canonical order is reverse-label order" {
    var a = try parseText("a.example.com.", null);
    var b = try parseText("b.example.com.", null);
    var c = try parseText("example.com.", null);
    var d = try parseText("z.example.net.", null);
    try std.testing.expect(a.canonicalCompare(&b) == .lt);
    try std.testing.expect(c.canonicalCompare(&a) == .lt);
    try std.testing.expect(c.canonicalCompare(&d) == .lt);
}

test "parseWire decompresses" {
    const msg = "\x03www\x07example\x03com\x00" ++ "\xc0\x04" ++ "\x00";
    var n: Name = undefined;
    const next = try parseWire(msg, 0, &n);
    try std.testing.expectEqual(@as(usize, 17), next);
    try std.testing.expectEqualStrings("\x03www\x07example\x03com\x00", n.slice());

    const next2 = try parseWire(msg, 17, &n);
    try std.testing.expectEqual(@as(usize, 19), next2);
    try std.testing.expectEqualStrings("\x07example\x03com\x00", n.slice());
}

test "parseWire rejects forward pointer" {
    const msg = "\xc0\x02\x00";
    var n: Name = undefined;
    try std.testing.expectError(error.BadPointer, parseWire(msg, 0, &n));
}

test "compression never drops labels from a longer name" {
    var msg: [512]u8 = undefined;
    @memset(msg[0..12], 0);
    var pos: usize = 12;
    var c: Compressor = .{};
    var origin = try parseText("example.com.", null);
    try c.write(&msg, &pos, origin.slice());
    var long = try parseText("a.b.example.com.", null);
    try c.write(&msg, &pos, long.slice());
    // 3 labels + pointer (not just a pointer to example.com)
    try std.testing.expectEqual(@as(usize, 12 + origin.len + 4 + 2), pos);
    var out: Name = undefined;
    _ = try parseWire(msg[0..pos], 12 + origin.len, &out);
    try std.testing.expect(out.eqlIgnoreCase(&long));
}

test "compression writes a pointer for a shared suffix" {
    var msg: [512]u8 = undefined;
    @memset(msg[0..12], 0);
    var pos: usize = 12;
    var c: Compressor = .{};
    var origin = try parseText("example.com.", null);
    try c.write(&msg, &pos, origin.slice());
    const after_origin = pos;
    var www = try parseText("www.example.com.", null);
    try c.write(&msg, &pos, www.slice());
    // www label + pointer
    try std.testing.expectEqual(after_origin + 4 + 2, pos);
    try std.testing.expectEqual(@as(u8, 0xc0), msg[after_origin + 4]);

    var out: Name = undefined;
    _ = try parseWire(msg[0..pos], after_origin, &out);
    try std.testing.expect(out.eqlIgnoreCase(&www));
}

test "relative name with root origin" {
    const root = Name.root();
    const x = try parseText("example.com", &root);
    try std.testing.expectEqualStrings("\x07example\x03com\x00", x.slice());
}
