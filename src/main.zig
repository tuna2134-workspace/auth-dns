//! Command-line entry point.
//!
//!   auth-dns serve    --listen 127.0.0.1:53 --zone example.com=zones/example.com.zone
//!   auth-dns checkzone --origin example.com. --file zones/example.com.zone
//!   auth-dns version

const std = @import("std");
const Io = std.Io;
const auth_dns = @import("auth_dns");

const name = auth_dns.name;
const types = auth_dns.types;
const sema = auth_dns.sema;
const server_mod = auth_dns.server;
const acl = auth_dns.acl;
const tsig = auth_dns.tsig;
const config_mod = auth_dns.config;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        printUsage(init);
        return;
    }
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "serve")) {
        return cmdServe(init, args[2..]);
    } else if (std.mem.eql(u8, cmd, "checkzone")) {
        return cmdCheckZone(init, args[2..]);
    } else if (std.mem.eql(u8, cmd, "ds")) {
        return cmdDs(init, args[2..]);
    } else if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version")) {
        var buf: [4096]u8 = undefined;
        var fw = Io.File.stdout().writer(init.io, &buf);
        try fw.interface.print("auth-dns {s} (Zig {s}, {s})\n", .{
            auth_dns.version,
            @import("builtin").zig_version_string,
            auth_dns.openssl.version(),
        });
        try fw.interface.flush();
        return;
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help")) {
        printUsage(init);
        return;
    }
    std.debug.print("unknown command: {s}\n", .{cmd});
    printUsage(init);
    std.process.exit(2);
}

fn cmdServe(init: std.process.Init, argv: []const []const u8) !void {
    const gpa = init.gpa;
    var listens: std.ArrayList(server_mod.Listen) = .empty;
    defer listens.deinit(gpa);
    var zones: std.ArrayList(server_mod.ZoneSpec) = .empty;
    defer zones.deinit(gpa);
    var keys: std.ArrayList(tsig.Key) = .empty;
    defer keys.deinit(gpa);

    var config_path: ?[]const u8 = null;
    var allow_text: []const u8 = "none";
    var allow_update_text: []const u8 = "none";
    var dnssec_key: ?[]const u8 = null;
    var dnssec_flags: u16 = 257;
    var dnssec_nsec3: bool = false;
    var dnssec_nsec3_iterations: u16 = 0;
    var dnssec_nsec3_salt: []const u8 = "";
    var journal_dir: ?[]const u8 = null;
    var max_udp: u16 = 1232;
    var tcp_idle: u32 = 30;
    var max_tcp: u32 = 256;
    var rate_qps: u32 = 0;
    var rate_burst: u32 = 0;

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.eql(u8, a, "--config") or std.mem.eql(u8, a, "-c")) {
            config_path = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--listen") or std.mem.eql(u8, a, "-l")) {
            const v = try nextArg(argv, &i, a);
            const addr = Io.net.IpAddress.parseLiteral(v) catch {
                std.debug.print("invalid listen address: {s}\n", .{v});
                std.process.exit(2);
            };
            try listens.append(gpa, .{ .addr = addr });
        } else if (std.mem.eql(u8, a, "--zone") or std.mem.eql(u8, a, "-z")) {
            const v = try nextArg(argv, &i, a);
            const eq = std.mem.indexOfScalar(u8, v, '=') orelse {
                std.debug.print("--zone expects NAME=FILE\n", .{});
                std.process.exit(2);
            };
            const root = name.Name.root();
            const origin = name.parseText(v[0..eq], &root) catch {
                std.debug.print("invalid zone origin: {s}\n", .{v[0..eq]});
                std.process.exit(2);
            };
            try zones.append(gpa, .{ .origin = origin, .file = v[eq + 1 ..] });
        } else if (std.mem.eql(u8, a, "--allow-transfer")) {
            allow_text = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--allow-update")) {
            allow_update_text = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--dnssec-key")) {
            dnssec_key = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--dnssec-flags")) {
            dnssec_flags = std.fmt.parseInt(u16, try nextArg(argv, &i, a), 10) catch 257;
        } else if (std.mem.eql(u8, a, "--dnssec-nsec3")) {
            dnssec_nsec3 = true;
        } else if (std.mem.eql(u8, a, "--dnssec-nsec3-iterations")) {
            dnssec_nsec3_iterations = std.fmt.parseInt(u16, try nextArg(argv, &i, a), 10) catch 0;
        } else if (std.mem.eql(u8, a, "--dnssec-nsec3-salt")) {
            dnssec_nsec3_salt = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--journal-dir")) {
            journal_dir = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--tsig")) {
            const v = try nextArg(argv, &i, a);
            var it = std.mem.splitScalar(u8, v, ':');
            const kn = it.next() orelse "";
            const alg = it.next() orelse "";
            const secret_b64 = it.next() orelse "";
            if (kn.len == 0 or alg.len == 0 or secret_b64.len == 0) {
                std.debug.print("--tsig expects NAME:ALGORITHM:BASE64SECRET\n", .{});
                std.process.exit(2);
            }
            const dec = &std.base64.standard.Decoder;
            const n = dec.calcSizeForSlice(secret_b64) catch {
                std.debug.print("invalid TSIG base64 secret\n", .{});
                std.process.exit(2);
            };
            const secret = try gpa.alloc(u8, n);
            dec.decode(secret, secret_b64) catch {
                std.debug.print("invalid TSIG base64 secret\n", .{});
                std.process.exit(2);
            };
            try keys.append(gpa, try tsig.buildKey(gpa, kn, alg, secret));
            gpa.free(secret);
        } else if (std.mem.eql(u8, a, "--max-udp-size")) {
            max_udp = std.fmt.parseInt(u16, try nextArg(argv, &i, a), 10) catch 1232;
        } else if (std.mem.eql(u8, a, "--tcp-idle")) {
            tcp_idle = std.fmt.parseInt(u32, try nextArg(argv, &i, a), 10) catch 30;
        } else if (std.mem.eql(u8, a, "--max-tcp-connections")) {
            max_tcp = std.fmt.parseInt(u32, try nextArg(argv, &i, a), 10) catch 256;
        } else if (std.mem.eql(u8, a, "--rate-limit")) {
            const v = try nextArg(argv, &i, a);
            if (std.mem.indexOfScalar(u8, v, ':')) |colon| {
                rate_qps = std.fmt.parseInt(u32, v[0..colon], 10) catch 0;
                rate_burst = std.fmt.parseInt(u32, v[colon + 1 ..], 10) catch 0;
            } else {
                rate_qps = std.fmt.parseInt(u32, v, 10) catch 0;
            }
        } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            printServeUsage(init);
            return;
        } else {
            std.debug.print("unknown option: {s}\n", .{a});
            std.process.exit(2);
        }
    }

    if (config_path) |cp| {
        var cfg = try config_mod.load(gpa, init.io, cp);
        defer cfg.deinit();
        var srv = try server_mod.Server.init(gpa, init.io, .{
            .listeners = cfg.listeners,
            .zones = cfg.zones,
            .keys = cfg.keys,
            .max_udp_size = cfg.max_udp_size,
            .tcp_max_size = cfg.tcp_max_size,
            .tcp_idle_seconds = cfg.tcp_idle_seconds,
            .max_tcp_connections = cfg.max_tcp_connections,
            .rate_limit_qps = cfg.rate_limit_qps,
            .rate_limit_burst = cfg.rate_limit_burst,
        });
        defer srv.deinit();
        try srv.run();
        return;
    }

    if (zones.items.len == 0) {
        std.debug.print("at least one --zone is required\n", .{});
        std.process.exit(2);
    }
    if (listens.items.len == 0) {
        try listens.append(gpa, .{ .addr = try Io.net.IpAddress.parse("127.0.0.1", 15353) });
    }

    const transfer_acl = try acl.parseList(gpa, allow_text);
    const update_acl = try acl.parseList(gpa, allow_update_text);
    for (zones.items) |*zs| {
        zs.allow_transfer = transfer_acl;
        zs.allow_update = update_acl;
        if (dnssec_key) |k| {
            zs.dnssec = .{
                .key_path = k,
                .key_flags = dnssec_flags,
                .nsec3 = dnssec_nsec3,
                .nsec3_iterations = dnssec_nsec3_iterations,
                .nsec3_salt = dnssec_nsec3_salt,
            };
        }
        if (journal_dir) |dir| {
            var tbuf: [name.max_name_len]u8 = undefined;
            const zone_text = try zs.origin.toText(&tbuf);
            zs.journal_path = try std.fmt.allocPrint(gpa, "{s}/{s}.jnl", .{ dir, std.mem.trimEnd(u8, zone_text, ".") });
        }
    }

    var server = try server_mod.Server.init(gpa, init.io, .{
        .listeners = listens.items,
        .zones = zones.items,
        .keys = keys.items,
        .max_udp_size = max_udp,
        .tcp_idle_seconds = tcp_idle,
        .max_tcp_connections = max_tcp,
        .rate_limit_qps = rate_qps,
        .rate_limit_burst = rate_burst,
    });
    defer server.deinit();
    try server.run();
}

fn cmdDs(init: std.process.Init, argv: []const []const u8) !void {
    const gpa = init.gpa;
    var key_path: ?[]const u8 = null;
    var zone_name: ?[]const u8 = null;
    var flags: u16 = 257;
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.eql(u8, a, "--key") or std.mem.eql(u8, a, "-k")) {
            key_path = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--name") or std.mem.eql(u8, a, "-n")) {
            zone_name = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--flags")) {
            flags = std.fmt.parseInt(u16, try nextArg(argv, &i, a), 10) catch 257;
        } else {
            std.debug.print("unknown option: {s}\n", .{a});
            std.process.exit(2);
        }
    }
    if (key_path == null or zone_name == null) {
        std.debug.print("ds requires --key and --name\n", .{});
        std.process.exit(2);
    }
    const root = name.Name.root();
    var origin = name.parseText(zone_name.?, &root) catch {
        std.debug.print("invalid zone name\n", .{});
        std.process.exit(2);
    };
    name.lowerInPlace(origin.buf[0..origin.len]);
    const pem = try Io.Dir.cwd().readFileAlloc(init.io, key_path.?, gpa, .limited(1 << 20));
    defer gpa.free(pem);
    var key = auth_dns.openssl.Key.loadPem(gpa, pem) catch |e| {
        std.debug.print("cannot load key: {t}\n", .{e});
        std.process.exit(1);
    };
    defer key.deinit(gpa);
    const dnskey = try auth_dns.openssl.dnskeyRdata(gpa, flags, &key);
    defer gpa.free(dnskey);
    const tag = auth_dns.openssl.keyTag(dnskey);
    const ds = try auth_dns.openssl.dsRdata(gpa, origin.slice(), dnskey);
    defer gpa.free(ds);

    const b64len = std.base64.standard.Encoder.calcSize(key.publicKey().len);
    const b64 = try gpa.alloc(u8, b64len);
    defer gpa.free(b64);
    const b64str = std.base64.standard.Encoder.encode(b64, key.publicKey());

    var buf: [8192]u8 = undefined;
    var fw = Io.File.stdout().writer(init.io, &buf);
    const w = &fw.interface;
    var nbuf: [name.max_name_len]u8 = undefined;
    const zt = try origin.toText(&nbuf);
    try w.print("{s} 3600 IN DNSKEY {d} 3 {d} {s}\n", .{ zt, flags, key.algorithmNumber(), b64str });
    try w.print("{s} 3600 IN DS {d} {d} 2 ", .{ zt, tag, key.algorithmNumber() });
    for (ds[4..]) |b| try w.print("{X:0>2}", .{b});
    try w.writeByte('\n');
    try w.flush();
}

fn cmdCheckZone(init: std.process.Init, argv: []const []const u8) !void {
    const gpa = init.gpa;
    var origin: ?name.Name = null;
    var file: ?[]const u8 = null;
    var dnssec_key: ?[]const u8 = null;
    var nsec3_enabled = false;
    var nsec3_iterations: u16 = 0;
    var nsec3_salt: []const u8 = "";

    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.eql(u8, a, "--origin") or std.mem.eql(u8, a, "-o")) {
            const v = try nextArg(argv, &i, a);
            const root = name.Name.root();
            origin = name.parseText(v, &root) catch {
                std.debug.print("invalid origin: {s}\n", .{v});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, a, "--file") or std.mem.eql(u8, a, "-f")) {
            file = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--dnssec-key")) {
            dnssec_key = try nextArg(argv, &i, a);
        } else if (std.mem.eql(u8, a, "--dnssec-nsec3")) {
            nsec3_enabled = true;
        } else if (std.mem.eql(u8, a, "--dnssec-nsec3-iterations")) {
            nsec3_iterations = std.fmt.parseInt(u16, try nextArg(argv, &i, a), 10) catch 0;
        } else if (std.mem.eql(u8, a, "--dnssec-nsec3-salt")) {
            nsec3_salt = try nextArg(argv, &i, a);
        } else {
            std.debug.print("unknown option: {s}\n", .{a});
            std.process.exit(2);
        }
    }
    if (origin == null or file == null) {
        std.debug.print("checkzone requires --origin and --file\n", .{});
        std.process.exit(2);
    }

    var z = sema.load(gpa, init.io, file.?, .{
        .origin = origin.?,
        .dnssec = if (dnssec_key) |k| .{
            .key_path = k,
            .nsec3 = nsec3_enabled,
            .nsec3_iterations = nsec3_iterations,
            .nsec3_salt = nsec3_salt,
        } else null,
    }) catch |e| {
        std.debug.print("zone {s}: load failed: {t}\n", .{ file.?, e });
        std.process.exit(1);
    };
    defer z.deinit();

    var buf: [8192]u8 = undefined;
    var fw = Io.File.stdout().writer(init.io, &buf);
    const w = &fw.interface;
    var nbuf: [name.max_name_len]u8 = undefined;
    try w.print("zone {s} loaded: serial {d}, {d} records, {d} RRsets{s}\n", .{
        try z.origin.toText(&nbuf),           z.serial, z.record_count, z.rrsets.len,
        if (z.isSigned()) ", signed" else "",
    });
    for (z.warnings) |warning| try w.print("warning: {s}\n", .{warning});
    try w.flush();
}

fn nextArg(argv: []const []const u8, i: *usize, flag: []const u8) ![]const u8 {
    if (i.* + 1 >= argv.len) {
        std.debug.print("{s} requires an argument\n", .{flag});
        std.process.exit(2);
    }
    i.* += 1;
    return argv[i.*];
}

fn printUsage(init: std.process.Init) void {
    var buf: [4096]u8 = undefined;
    var fw = Io.File.stdout().writer(init.io, &buf);
    const w = &fw.interface;
    w.writeAll(
        \\auth-dns - authoritative DNS server
        \\
        \\usage:
        \\  auth-dns serve --config named.conf
        \\  auth-dns serve [options]
        \\  auth-dns checkzone --origin NAME --file FILE [--dnssec-key PEM]
        \\      [--dnssec-nsec3] [--dnssec-nsec3-iterations N] [--dnssec-nsec3-salt HEX]
        \\  auth-dns ds --key PEM --name NAME [--flags 257]
        \\  auth-dns version
        \\
        \\serve options:
        \\  -l, --listen ADDR:PORT       listen address (repeatable; default 127.0.0.1:15353)
        \\  -z, --zone NAME=FILE         zone apex and master file (repeatable)
        \\      --allow-transfer ACL     ACL list, e.g. "127.0.0.1,192.0.2.0/24,key:xfr"
        \\      --allow-update ACL       ACL list for RFC 2136 dynamic updates
        \\      --dnssec-key PEM         sign every zone with this private key
        \\      --dnssec-flags N         DNSKEY flags (default 257)
        \\      --dnssec-nsec3           generate an NSEC3 chain (instead of NSEC)
        \\      --dnssec-nsec3-iterations N
        \\      --dnssec-nsec3-salt HEX  NSEC3 salt (hex)
        \\      --journal-dir DIR        enable IXFR journals under DIR
        \\      --tsig NAME:ALG:SECRET   add a TSIG key (secret is base64)
        \\      --max-udp-size N         EDNS UDP payload limit (default 1232)
        \\      --tcp-idle SECONDS       TCP idle timeout (default 30, 0 = off)
        \\      --max-tcp-connections N  concurrent TCP connection limit
        \\      --rate-limit QPS[:BURST] per-source query rate limit
        \\
    ) catch {};
    w.flush() catch {};
}

fn printServeUsage(init: std.process.Init) void {
    printUsage(init);
}
