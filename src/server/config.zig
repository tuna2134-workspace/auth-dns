//! Minimal BIND-style configuration file.
//!
//! Supported grammar:
//!
//!   options {
//!       listen 127.0.0.1 port 15353;
//!       directory "zones";
//!       max-udp-size 1232;
//!   };
//!   key "xfr.example.com" {
//!       algorithm hmac-sha256;
//!       secret "base64==";
//!   };
//!   zone "example.com" {
//!       type primary;
//!       file "example.com.zone";
//!       journal "example.com.jnl";
//!       allow-transfer { any; };
//!       dnssec-key "keys/example.com.pem";
//!       dnssec-flags 257;
//!   };
//!
//! Comments: #, // and /* ... */.  Unknown statements are rejected rather
//! than silently ignored, so a typo cannot quietly weaken an ACL.

const std = @import("std");
const Io = std.Io;
const name = @import("../dns/name.zig");
const text = @import("../dns/text.zig");
const tsig = @import("../dns/tsig.zig");
const acl = @import("acl.zig");
const server = @import("server.zig");
const secondary = @import("secondary.zig");

pub const Error = error{ConfigError};

const TokenKind = enum { word, string, lbrace, rbrace, semi, equal, eof };
const Token = struct { kind: TokenKind, text: []const u8, line: u32 };

const Lexer = struct {
    src: []const u8,
    pos: usize = 0,
    line: u32 = 1,

    fn next(l: *Lexer) !Token {
        while (l.pos < l.src.len) {
            const c = l.src[l.pos];
            if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
                if (c == '\n') l.line += 1;
                l.pos += 1;
                continue;
            }
            if (c == '#') {
                l.skipLine();
                continue;
            }
            if (c == '/' and l.pos + 1 < l.src.len and l.src[l.pos + 1] == '/') {
                l.skipLine();
                continue;
            }
            if (c == '/' and l.pos + 1 < l.src.len and l.src[l.pos + 1] == '*') {
                l.pos += 2;
                while (l.pos + 1 < l.src.len and !(l.src[l.pos] == '*' and l.src[l.pos + 1] == '/')) {
                    if (l.src[l.pos] == '\n') l.line += 1;
                    l.pos += 1;
                }
                if (l.pos + 1 < l.src.len) l.pos += 2;
                continue;
            }
            break;
        }
        if (l.pos >= l.src.len) return .{ .kind = .eof, .text = "", .line = l.line };
        const line = l.line;
        const c = l.src[l.pos];
        switch (c) {
            '{' => {
                l.pos += 1;
                return .{ .kind = .lbrace, .text = "{", .line = line };
            },
            '}' => {
                l.pos += 1;
                return .{ .kind = .rbrace, .text = "}", .line = line };
            },
            ';' => {
                l.pos += 1;
                return .{ .kind = .semi, .text = ";", .line = line };
            },
            '=' => {
                l.pos += 1;
                return .{ .kind = .equal, .text = "=", .line = line };
            },
            '"' => {
                l.pos += 1;
                const start = l.pos;
                while (l.pos < l.src.len and l.src[l.pos] != '"') {
                    if (l.src[l.pos] == '\\' and l.pos + 1 < l.src.len) l.pos += 2 else l.pos += 1;
                }
                const end = l.pos;
                if (l.pos < l.src.len) l.pos += 1;
                return .{ .kind = .string, .text = l.src[start..end], .line = line };
            },
            else => {},
        }
        const start = l.pos;
        while (l.pos < l.src.len) {
            const d = l.src[l.pos];
            if (d == ' ' or d == '\t' or d == '\r' or d == '\n' or d == ';' or d == '{' or d == '}' or d == '"') break;
            l.pos += 1;
        }
        return .{ .kind = .word, .text = l.src[start..l.pos], .line = line };
    }

    fn skipLine(l: *Lexer) void {
        while (l.pos < l.src.len and l.src[l.pos] != '\n') l.pos += 1;
    }
};

pub const Config = struct {
    arena: std.heap.ArenaAllocator,
    listeners: []const server.Listen,
    zones: []const server.ZoneSpec,
    keys: []const tsig.Key,
    max_udp_size: u16 = 1232,
    tcp_max_size: usize = 65535,
    tcp_idle_seconds: u32 = 30,
    max_tcp_connections: u32 = 256,
    rate_limit_qps: u32 = 0,
    rate_limit_burst: u32 = 0,

    pub fn deinit(c: *Config) void {
        c.arena.deinit();
    }
};

const ZoneBuild = struct {
    origin: name.Name,
    file: []const u8 = "",
    role: server.Role = .primary,
    primaries: std.ArrayList(secondary.Primary) = .empty,
    allow_notify: acl.Set = .{ .entries = &.{} },
    allow_update: acl.Set = .{ .entries = &.{} },
    also_notify: std.ArrayList(server.NotifyTarget) = .empty,
    journal: ?[]const u8 = null,
    allow: acl.Set = .{ .entries = &.{} },
    dnssec_key: ?[]const u8 = null,
    dnssec_key_dir: ?[]const u8 = null,
    dnssec_auto: bool = false,
    dnssec_resign_interval: u32 = 7 * 24 * 3600,
    dnssec_zsk_lifetime: u32 = 90 * 24 * 3600,
    dnssec_propagation: u32 = 3600,
    dnssec_flags: u16 = 257,
    dnssec_nsec3: bool = false,
    dnssec_nsec3_opt_out: bool = false,
    dnssec_nsec3_iterations: u16 = 0,
    dnssec_nsec3_salt: []const u8 = "",
};

const KeyBuild = struct {
    name: []const u8,
    algorithm: []const u8,
    secret_b64: []const u8,
};

const Parser = struct {
    allocator: std.mem.Allocator,
    tokens: []const Token,
    pos: usize = 0,
    err_line: u32 = 0,
    listen_list: std.ArrayList(server.Listen) = .empty,
    zone_list: std.ArrayList(ZoneBuild) = .empty,
    key_list: std.ArrayList(KeyBuild) = .empty,
    directory: []const u8 = "",
    max_udp: u16 = 1232,
    tcp_max: usize = 65535,
    tcp_idle: u32 = 30,
    max_tcp: u32 = 256,
    rate_qps: u32 = 0,
    rate_burst: u32 = 0,

    fn peek(p: *Parser) Token {
        return p.tokens[@min(p.pos, p.tokens.len - 1)];
    }
    fn advance(p: *Parser) Token {
        const t = p.peek();
        if (p.pos < p.tokens.len) p.pos += 1;
        return t;
    }
    fn expect(p: *Parser, kind: TokenKind) !Token {
        const t = p.advance();
        if (t.kind != kind) return p.fail(t.line);
        return t;
    }
    fn fail(p: *Parser, line: u32) Error {
        p.err_line = line;
        return error.ConfigError;
    }
    fn parse(p: *Parser) !void {
        while (p.peek().kind != .eof) {
            const t = p.advance();
            if (t.kind != .word) return p.fail(t.line);
            if (std.mem.eql(u8, t.text, "options")) {
                try p.parseOptions();
            } else if (std.mem.eql(u8, t.text, "zone")) {
                try p.parseZone();
            } else if (std.mem.eql(u8, t.text, "key")) {
                try p.parseKey();
            } else {
                return p.fail(t.line);
            }
        }
    }

    fn parseOptions(p: *Parser) !void {
        _ = try p.expect(.lbrace);
        while (p.peek().kind != .rbrace) {
            const t = p.advance();
            if (t.kind != .word) return p.fail(t.line);
            if (std.mem.eql(u8, t.text, "listen")) {
                const a = p.advance();
                if (a.kind != .word and a.kind != .string) return p.fail(a.line);
                var addr = Io.net.IpAddress.parseLiteral(a.text) catch return p.fail(a.line);
                if (p.peek().kind == .word and std.mem.eql(u8, p.peek().text, "port")) {
                    _ = p.advance();
                    const port_tok = p.advance();
                    const port = std.fmt.parseInt(u16, port_tok.text, 10) catch return p.fail(port_tok.line);
                    addr.setPort(port);
                }
                try p.listen_list.append(p.allocator, .{ .addr = addr });
            } else if (std.mem.eql(u8, t.text, "directory")) {
                const a = p.advance();
                if (a.kind != .string and a.kind != .word) return p.fail(a.line);
                p.directory = a.text;
            } else if (std.mem.eql(u8, t.text, "max-udp-size")) {
                const a = p.advance();
                p.max_udp = std.fmt.parseInt(u16, a.text, 10) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "tcp-max-size")) {
                const a = p.advance();
                p.tcp_max = std.fmt.parseInt(usize, a.text, 10) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "tcp-idle-timeout")) {
                const a = p.advance();
                p.tcp_idle = std.fmt.parseInt(u32, a.text, 10) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "max-tcp-connections")) {
                const a = p.advance();
                p.max_tcp = std.fmt.parseInt(u32, a.text, 10) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "rate-limit")) {
                const a = p.advance();
                p.rate_qps = std.fmt.parseInt(u32, a.text, 10) catch return p.fail(a.line);
                if (p.peek().kind == .word) {
                    const b = p.advance();
                    p.rate_burst = std.fmt.parseInt(u32, b.text, 10) catch return p.fail(b.line);
                }
            } else {
                return p.fail(t.line);
            }
            try p.endStatement();
        }
        _ = p.advance();
        _ = p.maybeSemi();
    }

    fn parseZone(p: *Parser) !void {
        const nt = p.advance();
        if (nt.kind != .string and nt.kind != .word) return p.fail(nt.line);
        const root = name.Name.root();
        var origin = name.parseText(nt.text, &root) catch return p.fail(nt.line);
        name.lowerInPlace(origin.buf[0..origin.len]);
        _ = try p.expect(.lbrace);
        var z: ZoneBuild = .{ .origin = origin };
        while (p.peek().kind != .rbrace) {
            const t = p.advance();
            if (t.kind != .word) return p.fail(t.line);
            if (std.mem.eql(u8, t.text, "type")) {
                const a = p.advance();
                if (std.ascii.eqlIgnoreCase(a.text, "primary") or std.ascii.eqlIgnoreCase(a.text, "master")) {
                    z.role = .primary;
                } else if (std.ascii.eqlIgnoreCase(a.text, "secondary") or std.ascii.eqlIgnoreCase(a.text, "slave")) {
                    z.role = .secondary;
                } else {
                    return p.fail(a.line);
                }
            } else if (std.mem.eql(u8, t.text, "primary")) {
                const a = p.advance();
                const addr = Io.net.IpAddress.parseLiteral(a.text) catch return p.fail(a.line);
                var key_name: ?[]const u8 = null;
                if (p.peek().kind == .word or p.peek().kind == .string) {
                    const k = p.advance();
                    key_name = k.text;
                }
                try z.primaries.append(p.allocator, .{ .addr = addr, .key_name = key_name });
            } else if (std.mem.eql(u8, t.text, "allow-notify")) {
                z.allow_notify = try p.parseAcl();
            } else if (std.mem.eql(u8, t.text, "allow-update")) {
                z.allow_update = try p.parseAcl();
            } else if (std.mem.eql(u8, t.text, "also-notify")) {
                const a = p.advance();
                const addr = Io.net.IpAddress.parseLiteral(a.text) catch return p.fail(a.line);
                var key_name: ?[]const u8 = null;
                if (p.peek().kind == .word or p.peek().kind == .string) {
                    const k = p.advance();
                    key_name = k.text;
                }
                try z.also_notify.append(p.allocator, .{ .addr = addr, .key_name = key_name });
            } else if (std.mem.eql(u8, t.text, "file")) {
                const a = p.advance();
                z.file = a.text;
            } else if (std.mem.eql(u8, t.text, "journal")) {
                const a = p.advance();
                z.journal = a.text;
            } else if (std.mem.eql(u8, t.text, "dnssec-key")) {
                const a = p.advance();
                z.dnssec_key = a.text;
            } else if (std.mem.eql(u8, t.text, "dnssec-key-dir")) {
                const a = p.advance();
                z.dnssec_key_dir = a.text;
            } else if (std.mem.eql(u8, t.text, "dnssec-auto")) {
                const a = p.advance();
                z.dnssec_auto = std.ascii.eqlIgnoreCase(a.text, "yes") or std.ascii.eqlIgnoreCase(a.text, "true") or std.mem.eql(u8, a.text, "1");
            } else if (std.mem.eql(u8, t.text, "dnssec-resign-interval")) {
                const a = p.advance();
                z.dnssec_resign_interval = text.parseTtl(a.text) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "dnssec-zsk-lifetime")) {
                const a = p.advance();
                z.dnssec_zsk_lifetime = text.parseTtl(a.text) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "dnssec-propagation")) {
                const a = p.advance();
                z.dnssec_propagation = text.parseTtl(a.text) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "dnssec-flags")) {
                const a = p.advance();
                z.dnssec_flags = std.fmt.parseInt(u16, a.text, 10) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "dnssec-nsec3")) {
                const a = p.advance();
                z.dnssec_nsec3 = std.ascii.eqlIgnoreCase(a.text, "yes") or std.ascii.eqlIgnoreCase(a.text, "true") or std.mem.eql(u8, a.text, "1");
            } else if (std.mem.eql(u8, t.text, "dnssec-nsec3-opt-out")) {
                const a = p.advance();
                z.dnssec_nsec3_opt_out = std.ascii.eqlIgnoreCase(a.text, "yes") or std.ascii.eqlIgnoreCase(a.text, "true") or std.mem.eql(u8, a.text, "1");
            } else if (std.mem.eql(u8, t.text, "dnssec-nsec3-iterations")) {
                const a = p.advance();
                z.dnssec_nsec3_iterations = std.fmt.parseInt(u16, a.text, 10) catch return p.fail(a.line);
            } else if (std.mem.eql(u8, t.text, "dnssec-nsec3-salt")) {
                const a = p.advance();
                z.dnssec_nsec3_salt = a.text;
            } else if (std.mem.eql(u8, t.text, "allow-transfer")) {
                z.allow = try p.parseAcl();
            } else {
                return p.fail(t.line);
            }
            try p.endStatement();
        }
        _ = p.advance();
        _ = p.maybeSemi();
        if (z.file.len == 0) return p.fail(nt.line);
        if (z.dnssec_key != null and z.dnssec_key_dir != null) return p.fail(nt.line);
        try p.zone_list.append(p.allocator, z);
    }

    fn parseAcl(p: *Parser) !acl.Set {
        _ = try p.expect(.lbrace);
        var list: std.ArrayList(acl.Acl) = .empty;
        while (p.peek().kind != .rbrace) {
            const t = p.advance();
            if (t.kind == .semi) continue;
            if (t.kind != .word and t.kind != .string) return p.fail(t.line);
            if (std.ascii.eqlIgnoreCase(t.text, "key")) {
                const n = p.advance();
                if (n.kind != .string and n.kind != .word) return p.fail(n.line);
                var kb: [256]u8 = undefined;
                const s = std.fmt.bufPrint(&kb, "key:{s}", .{n.text}) catch return p.fail(n.line);
                try list.append(p.allocator, try acl.parseOne(p.allocator, s));
            } else {
                try list.append(p.allocator, try acl.parseOne(p.allocator, t.text));
            }
            _ = p.maybeSemi();
        }
        _ = p.advance();
        return .{ .entries = try list.toOwnedSlice(p.allocator) };
    }

    fn parseKey(p: *Parser) !void {
        const nt = p.advance();
        if (nt.kind != .string and nt.kind != .word) return p.fail(nt.line);
        _ = try p.expect(.lbrace);
        var algorithm: []const u8 = "hmac-sha256";
        var secret: []const u8 = "";
        while (p.peek().kind != .rbrace) {
            const t = p.advance();
            if (t.kind != .word) return p.fail(t.line);
            if (std.mem.eql(u8, t.text, "algorithm")) {
                const a = p.advance();
                algorithm = a.text;
            } else if (std.mem.eql(u8, t.text, "secret")) {
                const a = p.advance();
                if (a.kind != .string and a.kind != .word) return p.fail(a.line);
                secret = a.text;
            } else {
                return p.fail(t.line);
            }
            try p.endStatement();
        }
        _ = p.advance();
        _ = p.maybeSemi();
        if (secret.len == 0) return p.fail(nt.line);
        try p.key_list.append(p.allocator, .{ .name = nt.text, .algorithm = algorithm, .secret_b64 = secret });
    }

    fn endStatement(p: *Parser) !void {
        const t = p.advance();
        if (t.kind != .semi and t.kind != .rbrace) return p.fail(t.line);
        if (t.kind == .rbrace) p.pos -= 1;
    }

    fn maybeSemi(p: *Parser) bool {
        if (p.peek().kind == .semi) {
            _ = p.advance();
            return true;
        }
        return false;
    }
};

pub fn load(gpa: std.mem.Allocator, io: Io, path: []const u8) !Config {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const data = try Io.Dir.cwd().readFileAlloc(io, path, a, .limited(4 * 1024 * 1024));

    var toks: std.ArrayList(Token) = .empty;
    defer toks.deinit(a);
    var lx = Lexer{ .src = data };
    while (true) {
        const t = try lx.next();
        try toks.append(a, t);
        if (t.kind == .eof) break;
    }
    var p = Parser{ .allocator = a, .tokens = toks.items };
    try p.parse();

    const base_dir = std.fs.path.dirname(path) orelse ".";
    const dir = if (p.directory.len > 0) p.directory else base_dir;

    var zones: std.ArrayList(server.ZoneSpec) = .empty;
    for (p.zone_list.items) |*z| {
        const file = try resolve(a, dir, z.file);
        const journal = if (z.journal) |j| try resolve(a, dir, j) else null;
        const key_path = if (z.dnssec_key) |k| try resolve(a, dir, k) else null;
        const key_dir = if (z.dnssec_key_dir) |d| try resolve(a, dir, d) else null;
        try zones.append(a, .{
            .origin = z.origin,
            .file = file,
            .role = z.role,
            .primaries = try z.primaries.toOwnedSlice(a),
            .allow_notify = z.allow_notify,
            .allow_update = z.allow_update,
            .also_notify = try z.also_notify.toOwnedSlice(a),
            .journal_path = journal,
            .allow_transfer = z.allow,
            .dnssec = if (key_path != null or z.dnssec_key_dir != null) .{
                .key_path = key_path,
                .key_dir = key_dir,
                .auto = z.dnssec_auto,
                .resign_interval = z.dnssec_resign_interval,
                .zsk_lifetime = z.dnssec_zsk_lifetime,
                .propagation = z.dnssec_propagation,
                .key_flags = z.dnssec_flags,
                .nsec3 = z.dnssec_nsec3,
                .nsec3_opt_out = z.dnssec_nsec3_opt_out,
                .nsec3_iterations = z.dnssec_nsec3_iterations,
                .nsec3_salt = z.dnssec_nsec3_salt,
            } else null,
        });
    }

    var keys: std.ArrayList(tsig.Key) = .empty;
    for (p.key_list.items) |k| {
        const dec = &std.base64.standard.Decoder;
        const n = dec.calcSizeForSlice(k.secret_b64) catch return p.fail(0);
        const secret = try a.alloc(u8, n);
        dec.decode(secret, k.secret_b64) catch return p.fail(0);
        try keys.append(a, try tsig.buildKey(a, k.name, k.algorithm, secret));
    }

    var listeners: std.ArrayList(server.Listen) = .empty;
    if (p.listen_list.items.len == 0) {
        try listeners.append(a, .{ .addr = try Io.net.IpAddress.parse("127.0.0.1", 15353) });
    } else {
        try listeners.appendSlice(a, p.listen_list.items);
    }
    if (zones.items.len == 0) return p.fail(0);

    return .{
        .arena = arena,
        .listeners = try listeners.toOwnedSlice(a),
        .zones = try zones.toOwnedSlice(a),
        .keys = try keys.toOwnedSlice(a),
        .max_udp_size = p.max_udp,
        .tcp_max_size = p.tcp_max,
        .tcp_idle_seconds = p.tcp_idle,
        .max_tcp_connections = p.max_tcp,
        .rate_limit_qps = p.rate_qps,
        .rate_limit_burst = p.rate_burst,
    };
}

fn resolve(a: std.mem.Allocator, dir: []const u8, path: []const u8) ![]const u8 {
    if (std.fs.path.isAbsolute(path)) return a.dupe(u8, path);
    return std.fs.path.join(a, &.{ dir, path });
}
