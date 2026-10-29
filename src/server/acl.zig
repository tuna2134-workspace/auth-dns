//! Address/key ACLs for zone transfers and administrative operations.
//!
//! Entries are matched in order; the first matching entry decides.  This
//! mirrors BIND's `allow-transfer { ... }` semantics.

const std = @import("std");
const Io = std.Io;

pub const Acl = union(enum) {
    any,
    none,
    v4: struct { net: u32, bits: u8 },
    v6: struct { net: [16]u8, bits: u8 },
    key: []const u8,
};

pub const Set = struct {
    entries: []const Acl,

    pub fn deinit(self: *const Set, allocator: std.mem.Allocator) void {
        for (self.entries) |a| switch (a) {
            .key => |k| allocator.free(k),
            else => {},
        };
        allocator.free(self.entries);
    }

    pub fn allows(self: Set, addr: Io.net.IpAddress, key_name: ?[]const u8) bool {
        for (self.entries) |a| switch (a) {
            .any => return true,
            .none => return false,
            .v4 => |n| {
                if (addr != .ip4) continue;
                const ip = std.mem.readInt(u32, &addr.ip4.bytes, .big);
                const mask: u32 = if (n.bits == 0) 0 else @as(u32, 0xffffffff) << @as(u5, @intCast(32 - n.bits));
                if (ip & mask == n.net & mask) return true;
            },
            .v6 => |n| {
                if (addr != .ip6) continue;
                if (n.bits == 0) return true;
                var remaining = n.bits;
                var i: usize = 0;
                while (remaining >= 8 and i < 16) : (i += 1) {
                    if (addr.ip6.bytes[i] != n.net[i]) break;
                    remaining -= 8;
                }
                if (remaining == 0) return true;
                if (i < 16 and remaining < 8) {
                    const mask: u8 = @as(u8, 0xff) << @intCast(8 - remaining);
                    if (addr.ip6.bytes[i] & mask == n.net[i] & mask) return true;
                }
            },
            .key => |k| {
                if (key_name) |kn| {
                    const ka = std.mem.trimEnd(u8, k, ".");
                    const kb = std.mem.trimEnd(u8, kn, ".");
                    if (std.ascii.eqlIgnoreCase(ka, kb)) return true;
                }
            },
        };
        return false;
    }
};

pub fn parseOne(allocator: std.mem.Allocator, s: []const u8) !Acl {
    if (std.ascii.eqlIgnoreCase(s, "any")) return .any;
    if (std.ascii.eqlIgnoreCase(s, "none")) return .none;
    if (std.ascii.startsWithIgnoreCase(s, "key:")) {
        return .{ .key = try allocator.dupe(u8, std.mem.trim(u8, s[4..], " \t")) };
    }
    const slash = std.mem.indexOfScalar(u8, s, '/');
    const addr_text = if (slash) |i| s[0..i] else s;
    if (std.mem.indexOfScalar(u8, addr_text, ':') != null) {
        const a = Io.net.Ip6Address.parse(addr_text, 0) catch return error.BadAcl;
        const bits: u8 = if (slash) |i| std.fmt.parseInt(u8, s[i + 1 ..], 10) catch return error.BadAcl else 128;
        if (bits > 128) return error.BadAcl;
        return .{ .v6 = .{ .net = a.bytes, .bits = bits } };
    }
    const a = Io.net.Ip4Address.parse(addr_text, 0) catch return error.BadAcl;
    const bits: u8 = if (slash) |i| std.fmt.parseInt(u8, s[i + 1 ..], 10) catch return error.BadAcl else 32;
    if (bits > 32) return error.BadAcl;
    return .{ .v4 = .{ .net = std.mem.readInt(u32, &a.bytes, .big), .bits = bits } };
}

/// Parses a comma-separated ACL list.  Empty input means deny.
pub fn parseList(allocator: std.mem.Allocator, text: []const u8) !Set {
    if (text.len == 0) return .{ .entries = &.{} };
    var list: std.ArrayList(Acl) = .empty;
    errdefer list.deinit(allocator);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        const t = std.mem.trim(u8, part, " \t");
        if (t.len == 0) continue;
        try list.append(allocator, try parseOne(allocator, t));
    }
    return .{ .entries = try list.toOwnedSlice(allocator) };
}

test "ACL matching" {
    const set = try parseList(std.testing.allocator, "192.0.2.0/24, 2001:db8::/32, key:xfr");
    defer set.deinit(std.testing.allocator);
    const a = try Io.net.IpAddress.parse("192.0.2.55", 53);
    try std.testing.expect(set.allows(a, null));
    const b = try Io.net.IpAddress.parse("198.51.100.1", 53);
    try std.testing.expect(!set.allows(b, null));
    const c = try Io.net.IpAddress.parse("2001:db8::1", 53);
    try std.testing.expect(set.allows(c, null));
    try std.testing.expect(set.allows(b, "XFR"));
}
