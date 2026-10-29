//! Semantic analysis for zone files: name resolution, $ORIGIN/$TTL state,
//! $INCLUDE processing and record validation.
//!
//! This is the stage between the syntactic AST and the immutable `Zone`
//! database.  It is deliberately the only place that knows about the current
//! origin, the inherited owner and the default TTL.

const std = @import("std");
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");
const text = @import("../dns/text.zig");
const rdata = @import("../dns/rdata.zig");
const parser = @import("parser.zig");
const ast = @import("ast.zig");
const zone = @import("zone.zig");
const openssl = @import("../dnssec/openssl.zig");
const dnssec_sign = @import("../dnssec/sign.zig");
const keydir = @import("../dnssec/keydir.zig");
const nsec3 = @import("../dns/nsec3.zig");

pub const Options = struct {
    origin: name.Name,
    class: u16 = types.class_in,
    default_ttl: ?u32 = null,
    max_include_depth: u8 = 8,
    max_file_size: usize = 64 * 1024 * 1024,
    dnssec: ?DnssecOptions = null,
};

pub const DnssecOptions = struct {
    /// Single-key compatibility mode.  Mutually exclusive with `key_dir`.
    key_path: ?[]const u8 = null,
    key_flags: u16 = 257,
    /// Directory containing ksk-*.pem and zsk-*.pem.
    key_dir: ?[]const u8 = null,
    auto: bool = false,
    resign_interval: u32 = 7 * 24 * 3600,
    zsk_lifetime: u32 = 90 * 24 * 3600,
    propagation: u32 = 3600,
    validity: u32 = 30 * 24 * 3600,
    nsec3: bool = false,
    nsec3_opt_out: bool = false,
    nsec3_iterations: u16 = 0,
    /// Hex text; empty means the zero-length salt.
    nsec3_salt: []const u8 = "",
};

pub const Error = error{
    MissingOwner,
    OutOfZone,
    WrongClass,
    UnknownType,
    MetaTypeInZone,
    SoaNotAtApex,
    MultipleSoa,
    MissingSoa,
    MissingNs,
    MultipleCname,
    CnameConflict,
    WildcardNs,
    BadWildcard,
    IncludeDepthExceeded,
    RdataTooLong,
} || parser.Error || rdata.Error || zone.BuildError || std.mem.Allocator.Error;

/// Loads and analyses a zone file.  `path` may be absolute or relative to the
/// process working directory.
pub fn load(backing: std.mem.Allocator, io: std.Io, path: []const u8, options: Options) !zone.Zone {
    var tmp = std.heap.ArenaAllocator.init(backing);
    defer tmp.deinit();
    var l = Loader.init(tmp.allocator(), io, options);
    const base = std.fs.path.dirname(path) orelse ".";
    try l.loadFile(path, base, 0);
    try l.finish();
    return finalize(backing, tmp.allocator(), io, options, &l);
}

/// Loads a zone from an in-memory source (used by tests and checkzone).
pub fn loadSource(
    backing: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    source_name: []const u8,
    options: Options,
) !zone.Zone {
    var tmp = std.heap.ArenaAllocator.init(backing);
    defer tmp.deinit();
    const a = tmp.allocator();
    const parsed = try parser.parse(a, source, source_name);
    var l = Loader.init(a, io, options);
    try l.processAst(parsed, ".");
    try l.finish();
    return finalize(backing, a, io, options, &l);
}

fn finalize(
    backing: std.mem.Allocator,
    tmp: std.mem.Allocator,
    io: std.Io,
    options: Options,
    l: *Loader,
) !zone.Zone {
    const dc = options.dnssec orelse
        return zone.Zone.build(backing, l.apex, l.class, l.raw.items, l.warnings.items);
    var data_recs: std.ArrayList(zone.Record) = .empty;
    defer data_recs.deinit(tmp);
    for (l.raw.items) |r| {
        if (r.rtype == types.RRSIG or r.rtype == types.NSEC or r.rtype == types.NSEC3 or
            r.rtype == types.NSEC3PARAM or r.rtype == types.DNSKEY) continue;
        try data_recs.append(tmp, r);
    }
    var unsigned = try zone.Zone.build(backing, l.apex, l.class, data_recs.items, l.warnings.items);
    defer unsigned.deinit();
    var salt: []const u8 = &.{};
    if (dc.nsec3_salt.len > 0) {
        var sb: std.ArrayList(u8) = .empty;
        errdefer sb.deinit(tmp);
        try text.appendHex(&sb, tmp, dc.nsec3_salt);
        salt = sb.items;
    }
    const sign_opts: dnssec_sign.Options = .{
        .validity = dc.validity,
        .nsec3 = if (dc.nsec3) nsec3.Params{
            .opt_out = dc.nsec3_opt_out,
            .iterations = dc.nsec3_iterations,
            .salt = salt,
        } else null,
    };

    if (dc.key_dir) |dir| {
        var loaded = try keydir.load(tmp, io, dir, dc.auto, .{
            .zsk_lifetime = dc.zsk_lifetime,
            .propagation = dc.propagation,
        });
        defer loaded.deinit();
        const signed = try dnssec_sign.signZone(tmp, &unsigned, loaded.specs, sign_opts);
        return zone.Zone.build(backing, l.apex, l.class, signed, l.warnings.items);
    }

    const kp = dc.key_path orelse return error.NoKeys;
    const pem = try std.Io.Dir.cwd().readFileAlloc(io, kp, tmp, .limited(1 << 20));
    var key = try openssl.Key.loadPem(tmp, pem);
    defer key.deinit(tmp);
    var signing_keys: [2]dnssec_sign.SigningKey = undefined;
    signing_keys[0] = .{ .key = &key, .flags = dc.key_flags };
    var nkeys: usize = 1;
    if (dc.key_flags != 256) {
        signing_keys[1] = .{ .key = &key, .flags = 256 };
        nkeys = 2;
    }
    const signed = try dnssec_sign.signZone(tmp, &unsigned, signing_keys[0..nkeys], sign_opts);
    return zone.Zone.build(backing, l.apex, l.class, signed, l.warnings.items);
}

const Loader = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    apex: name.Name,
    origin: name.Name,
    class: u16,
    default_ttl: ?u32,
    last_owner: ?name.Name = null,
    last_ttl: ?u32 = null,
    raw: std.ArrayList(zone.Record) = .empty,
    warnings: std.ArrayList([]const u8) = .empty,
    cname_owners: std.StringHashMapUnmanaged(u32) = .{},
    other_owners: std.StringHashMapUnmanaged(u32) = .{},
    soa_seen: u32 = 0,
    soa_line: u32 = 0,
    ns_apex_seen: u32 = 0,
    max_include_depth: u8,
    max_file_size: usize,
    include_depth: u8 = 0,
    err_line: u32 = 0,
    warned_default_ttl: bool = false,

    fn init(allocator: std.mem.Allocator, io: std.Io, options: Options) Loader {
        var origin = options.origin;
        name.lowerInPlace(origin.buf[0..origin.len]);
        return .{
            .allocator = allocator,
            .io = io,
            .apex = origin,
            .origin = origin,
            .class = options.class,
            .default_ttl = options.default_ttl,
            .max_include_depth = options.max_include_depth,
            .max_file_size = options.max_file_size,
        };
    }

    fn processAst(l: *Loader, parsed: ast.Ast, base_dir: []const u8) anyerror!void {
        try l.processNodes(parsed.nodes, base_dir);
    }

    fn processNodes(l: *Loader, nodes: []const ast.Node, base_dir: []const u8) anyerror!void {
        for (nodes) |node| switch (node) {
            .ttl => |t| {
                l.default_ttl = text.parseTtl(t.value.text) catch return l.fail(t.line, error.InvalidTtl);
            },
            .origin => |o| {
                var n = name.parseText(o.value.text, &l.origin) catch return l.fail(o.line, error.InvalidName);
                name.lowerInPlace(n.buf[0..n.len]);
                l.origin = n;
            },
            .include => |inc| {
                try l.processInclude(inc.path, inc.origin, inc.line, base_dir);
            },
            .record => |r| {
                l.err_line = r.line;
                try l.processRecord(r);
            },
        };
    }

    fn processInclude(l: *Loader, path_tok: text.Token, origin_tok: ?text.Token, line: u32, base_dir: []const u8) anyerror!void {
        if (l.include_depth >= l.max_include_depth) return l.fail(line, error.IncludeDepthExceeded);
        const path = try text.decodedAlloc(l.allocator, path_tok.text);
        var include_origin = l.origin;
        if (origin_tok) |o| {
            include_origin = name.parseText(o.text, &l.origin) catch return l.fail(line, error.InvalidName);
            name.lowerInPlace(include_origin.buf[0..include_origin.len]);
        }
        const saved_origin = l.origin;
        const saved_ttl = l.default_ttl;
        const saved_owner = l.last_owner;
        const saved_last_ttl = l.last_ttl;

        l.origin = include_origin;
        const full = if (std.fs.path.isAbsolute(path))
            path
        else
            try std.fs.path.join(l.allocator, &.{ base_dir, path });
        l.include_depth += 1;
        defer {
            l.include_depth -= 1;
            l.origin = saved_origin;
            l.default_ttl = saved_ttl;
            l.last_owner = saved_owner;
            l.last_ttl = saved_last_ttl;
        }
        try l.loadFile(full, std.fs.path.dirname(full) orelse ".", line);
    }

    fn loadFile(l: *Loader, path: []const u8, base_dir: []const u8, line: u32) anyerror!void {
        const data = std.Io.Dir.cwd().readFileAlloc(l.io, path, l.allocator, .limited(l.max_file_size)) catch |e| {
            l.err_line = line;
            return e;
        };
        const parsed = parser.parse(l.allocator, data, path) catch |e| {
            l.err_line = line;
            return e;
        };
        try l.processAst(parsed, base_dir);
    }

    fn processRecord(l: *Loader, r: ast.Record) !void {
        var owner: name.Name = undefined;
        if (r.owner) |tok| {
            owner = name.parseText(tok.text, &l.origin) catch return l.fail(r.line, error.InvalidName);
        } else {
            owner = l.last_owner orelse return l.fail(r.line, error.MissingOwner);
        }
        name.lowerInPlace(owner.buf[0..owner.len]);
        if (!owner.isSubdomainOf(&l.apex)) return l.fail(r.line, error.OutOfZone);
        try checkWildcard(&owner, r.line);
        l.last_owner = owner;

        const class = if (r.class) |c| (types.classFromText(c.text) orelse return l.fail(r.line, error.WrongClass)) else l.class;
        if (class != l.class) return l.fail(r.line, error.WrongClass);

        const rtype = types.typeFromText(r.rtype.text) orelse return l.fail(r.line, error.UnknownType);
        if (types.isMetaType(rtype)) return l.fail(r.line, error.MetaTypeInZone);

        const ttl = if (r.ttl) |t|
            text.parseTtl(t.text) catch return l.fail(r.line, error.InvalidTtl)
        else
            l.default_ttl orelse l.last_ttl orelse blk: {
                if (!l.warned_default_ttl) {
                    l.warned_default_ttl = true;
                    try l.warn(r.line, "no $TTL or explicit TTL; using 3600", .{});
                }
                break :blk 3600;
            };
        l.last_ttl = ttl;

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(l.allocator);
        rdata.parse(l.allocator, rtype, r.rdata, .{ .origin = &l.origin }, &buf) catch |e| {
            l.err_line = r.line;
            return e;
        };
        if (buf.items.len > 65535) return l.fail(r.line, error.RdataTooLong);

        const owner_wire = try l.allocator.dupe(u8, owner.slice());
        const rdata_wire = try l.allocator.dupe(u8, buf.items);
        try l.raw.append(l.allocator, .{
            .owner = owner_wire,
            .rtype = rtype,
            .class = class,
            .ttl = ttl,
            .rdata = rdata_wire,
            .line = r.line,
        });

        if (rtype == types.SOA) {
            if (!std.mem.eql(u8, owner_wire, l.apex.slice())) return l.fail(r.line, error.SoaNotAtApex);
            l.soa_seen += 1;
            l.soa_line = r.line;
            if (l.soa_seen > 1) return l.fail(r.line, error.MultipleSoa);
            if (l.default_ttl == null) {
                l.default_ttl = zone.soaMinimum(rdata_wire) orelse return l.fail(r.line, error.InvalidSoa);
            }
        }
        if (rtype == types.NS and std.mem.eql(u8, owner_wire, l.apex.slice())) l.ns_apex_seen += 1;

        if (rtype == types.CNAME) {
            if (l.cname_owners.contains(owner_wire)) return l.fail(r.line, error.MultipleCname);
            if (l.other_owners.contains(owner_wire)) return l.fail(r.line, error.CnameConflict);
            try l.cname_owners.put(l.allocator, owner_wire, r.line);
        } else if (rtype != types.RRSIG and rtype != types.NSEC and rtype != types.NSEC3) {
            if (l.cname_owners.contains(owner_wire)) return l.fail(r.line, error.CnameConflict);
            try l.other_owners.put(l.allocator, owner_wire, r.line);
        }

        if (rtype == types.NS and isWildcard(&owner)) return l.fail(r.line, error.WildcardNs);
    }

    fn finish(l: *Loader) !void {
        if (l.soa_seen == 0) return l.fail(0, error.MissingSoa);
        if (l.ns_apex_seen == 0) return l.fail(l.soa_line, error.MissingNs);
    }

    fn warn(l: *Loader, line: u32, comptime fmt: []const u8, args: anytype) !void {
        const msg = try std.fmt.allocPrint(l.allocator, "line {d}: " ++ fmt, .{line} ++ args);
        try l.warnings.append(l.allocator, msg);
    }

    fn fail(l: *Loader, line: u32, err: anyerror) anyerror {
        l.err_line = line;
        return err;
    }
};

fn isWildcard(n: *const name.Name) bool {
    return n.len > 1 and n.buf[0] == 1 and n.buf[1] == '*';
}

fn checkWildcard(n: *const name.Name, line: u32) !void {
    var i: usize = 0;
    var label_idx: usize = 0;
    while (i < n.len and n.buf[i] != 0) {
        const l = n.buf[i];
        if (l == 1 and n.buf[i + 1] == '*' and label_idx != 0) {
            _ = line;
            return error.BadWildcard;
        }
        label_idx += 1;
        i += 1 + l;
    }
}

test "load a small zone" {
    const src =
        \\$TTL 3600
        \\$ORIGIN example.com.
        \\@ IN SOA ns1.example.com. hostmaster.example.com. (
        \\  2024010101 1h 15m 1w 5m )
        \\  IN NS ns1
        \\  IN NS ns2
        \\ns1 IN A 192.0.2.53
        \\ns2 IN A 192.0.2.54
        \\www IN A 192.0.2.1
        \\    IN AAAA 2001:db8::1
        \\mail IN MX 10 mx
        \\mx   IN A 192.0.2.25
        \\txt  IN TXT "hello" "world"
        \\alias IN CNAME www
        \\*.wild IN A 192.0.2.99
        \\sub  IN NS ns.sub
        \\ns.sub IN A 192.0.2.100
        \\
    ;
    var z = try loadSource(std.testing.allocator, std.testing.io, src, "test.zone", .{
        .origin = try name.parseText("example.com.", null),
    });
    defer z.deinit();

    try std.testing.expectEqual(@as(u32, 2024010101), z.serial);
    try std.testing.expectEqual(@as(u32, 300), z.minimum);
    try std.testing.expectEqual(@as(u32, 300), z.negative_ttl);
    try std.testing.expect(z.hasName("\x03www\x07example\x03com\x00"));
    try std.testing.expect(z.hasName("\x04wild\x07example\x03com\x00"));
    try std.testing.expect(z.isDelegation("\x03sub\x07example\x03com\x00"));
    const a = z.rrsetAt("\x03www\x07example\x03com\x00", types.A).?;
    try std.testing.expectEqual(@as(usize, 1), a.rdata.len);
    const mx = z.rrsetAt("\x04mail\x07example\x03com\x00", types.MX).?;
    try std.testing.expectEqual(@as(usize, 1), mx.rdata.len);
}

test "cname conflict is rejected" {
    const src =
        \\$TTL 60
        \\@ SOA ns. hostmaster. 1 1 1 1 1
        \\@ NS ns.
        \\ns A 192.0.2.1
        \\www CNAME ns.
        \\www A 192.0.2.2
        \\
    ;
    try std.testing.expectError(error.CnameConflict, loadSource(std.testing.allocator, std.testing.io, src, "bad.zone", .{
        .origin = try name.parseText("example.com.", null),
    }));
}

test "out of zone record is rejected" {
    const src =
        \\$TTL 60
        \\@ SOA ns. hostmaster. 1 1 1 1 1
        \\@ NS ns.
        \\ns A 192.0.2.1
        \\x.other. A 192.0.2.2
        \\
    ;
    try std.testing.expectError(error.OutOfZone, loadSource(std.testing.allocator, std.testing.io, src, "bad.zone", .{
        .origin = try name.parseText("example.com.", null),
    }));
}
