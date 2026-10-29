//! DNSSEC key directory management.
//!
//! Layout:
//!   keys/example.com/ksk-<unix>.pem   flags 257
//!   keys/example.com/zsk-<unix>.pem   flags 256
//!
//! The newest ZSK is the active one; older ZSKs are kept during the
//! propagation window and then removed.  KSKs are not rotated automatically
//! because that requires a parent DS update.

const std = @import("std");
const Io = std.Io;
const openssl = @import("openssl.zig");
const sign = @import("sign.zig");

pub const Role = enum { ksk, zsk };

pub const FileInfo = struct {
    path: []const u8,
    role: Role,
    created: u64,
};

pub const Loaded = struct {
    allocator: std.mem.Allocator,
    keys: []openssl.Key,
    specs: []sign.SigningKey,
    files: []FileInfo,

    pub fn deinit(l: *Loaded) void {
        for (l.keys) |*k| k.deinit(l.allocator);
        l.allocator.free(l.keys);
        l.allocator.free(l.specs);
        for (l.files) |f| l.allocator.free(f.path);
        l.allocator.free(l.files);
    }
};

pub const Options = struct {
    zsk_lifetime: u32 = 90 * 24 * 3600,
    propagation: u32 = 3600,
};

pub fn now() u64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.posix.CLOCK.REALTIME, &ts) != 0) return 0;
    return @intCast(@max(ts.sec, 0));
}

pub fn ensureDir(io: Io, dir: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, dir);
}

/// Generates a P-256 private key with the OpenSSL CLI.  The core signing path
/// still uses libcrypto directly; this is only key lifecycle management.
pub fn generate(allocator: std.mem.Allocator, io: Io, dir: []const u8, role: Role, timestamp: u64) ![]u8 {
    try ensureDir(io, dir);
    var ts = timestamp;
    var path: []u8 = undefined;
    while (true) {
        path = try std.fmt.allocPrint(allocator, "{s}/{s}-{d}.pem", .{ dir, @tagName(role), ts });
        const exists = blk: {
            std.Io.Dir.cwd().access(io, path, .{}) catch |e| switch (e) {
                error.FileNotFound => break :blk false,
                else => {
                    allocator.free(path);
                    return e;
                },
            };
            break :blk true;
        };
        if (!exists) break;
        allocator.free(path);
        ts += 1;
    }
    errdefer allocator.free(path);
    const result = std.process.run(allocator, io, .{
        .argv = &.{
            "openssl",  "genpkey",                 "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:P-256", "-out",       path,
        },
    }) catch return error.KeyGenerationFailed;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            return error.KeyGenerationFailed;
        },
        else => {
            std.Io.Dir.cwd().deleteFile(io, path) catch {};
            return error.KeyGenerationFailed;
        },
    }
    return path;
}

pub fn list(allocator: std.mem.Allocator, io: Io, dir: []const u8) ![]FileInfo {
    var out: std.ArrayList(FileInfo) = .empty;
    errdefer {
        for (out.items) |f| allocator.free(f.path);
        out.deinit(allocator);
    }
    var d = std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return out.toOwnedSlice(allocator),
        else => return e,
    };
    defer d.close(io);
    var it = d.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file and entry.kind != .sym_link) continue;
        const role: Role = if (std.mem.startsWith(u8, entry.name, "ksk-"))
            .ksk
        else if (std.mem.startsWith(u8, entry.name, "zsk-"))
            .zsk
        else
            continue;
        if (!std.mem.endsWith(u8, entry.name, ".pem")) continue;
        const dash = std.mem.indexOfScalar(u8, entry.name, '-') orelse continue;
        const dot = std.mem.lastIndexOfScalar(u8, entry.name, '.') orelse continue;
        if (dot <= dash + 1) continue;
        const ts = std.fmt.parseInt(u64, entry.name[dash + 1 .. dot], 10) catch 0;
        const full = try std.fs.path.join(allocator, &.{ dir, entry.name });
        try out.append(allocator, .{ .path = full, .role = role, .created = ts });
    }
    std.mem.sort(FileInfo, out.items, {}, fileLess);
    return out.toOwnedSlice(allocator);
}

fn fileLess(_: void, a: FileInfo, b: FileInfo) bool {
    if (a.created != b.created) return a.created < b.created;
    return std.mem.order(u8, a.path, b.path) == .lt;
}

pub fn load(allocator: std.mem.Allocator, io: Io, dir: []const u8, auto: bool, opts: Options) !Loaded {
    if (auto) _ = try maintain(allocator, io, dir, opts);
    const files = try list(allocator, io, dir);
    if (files.len == 0) {
        allocator.free(files);
        return error.NoKeys;
    }
    var keys = try allocator.alloc(openssl.Key, files.len);
    var specs = try allocator.alloc(sign.SigningKey, files.len);
    var loaded: usize = 0;
    errdefer {
        for (keys[0..loaded]) |*k| k.deinit(allocator);
        allocator.free(keys);
        allocator.free(specs);
        for (files) |f| allocator.free(f.path);
        allocator.free(files);
    }
    for (files, 0..) |f, i| {
        const pem = try std.Io.Dir.cwd().readFileAlloc(io, f.path, allocator, .limited(1 << 20));
        defer allocator.free(pem);
        keys[i] = try openssl.Key.loadPem(allocator, pem);
        loaded += 1;
        specs[i] = .{
            .key = &keys[i],
            .flags = if (f.role == .ksk) 257 else 256,
        };
    }
    return .{ .allocator = allocator, .keys = keys, .specs = specs, .files = files };
}

/// Ensures a KSK and a ZSK exist and performs ZSK rollover bookkeeping.
/// Returns true when the key set changed and the zone should be re-signed.
pub fn maintain(allocator: std.mem.Allocator, io: Io, dir: []const u8, opts: Options) !bool {
    try ensureDir(io, dir);
    const t = now();
    const files = try list(allocator, io, dir);
    defer {
        for (files) |f| allocator.free(f.path);
        allocator.free(files);
    }
    var changed = false;
    var has_ksk = false;
    var zsk_count: usize = 0;
    var newest_zsk: ?FileInfo = null;
    for (files) |f| {
        switch (f.role) {
            .ksk => has_ksk = true,
            .zsk => {
                zsk_count += 1;
                if (newest_zsk == null or f.created > newest_zsk.?.created) newest_zsk = f;
            },
        }
    }
    if (!has_ksk) {
        const p = try generate(allocator, io, dir, .ksk, t);
        allocator.free(p);
        changed = true;
    }
    if (zsk_count == 0) {
        const p = try generate(allocator, io, dir, .zsk, t);
        allocator.free(p);
        changed = true;
        return true;
    }
    const nz = newest_zsk.?;
    if (nz.created + opts.zsk_lifetime <= t) {
        const p = try generate(allocator, io, dir, .zsk, t);
        allocator.free(p);
        changed = true;
        return true;
    }
    if (zsk_count > 1 and nz.created + opts.propagation <= t) {
        for (files) |f| {
            if (f.role != .zsk) continue;
            if (std.mem.eql(u8, f.path, nz.path)) continue;
            std.Io.Dir.cwd().deleteFile(io, f.path) catch {};
            changed = true;
        }
    }
    return changed;
}
