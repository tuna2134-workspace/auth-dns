//! UDP/TCP authoritative server.
//!
//! UDP queries are answered synchronously on a per-listener thread.  TCP uses
//! one thread per connection (RFC 7766 requires multiple queries per
//! connection; AXFR/IXFR sessions are naturally long-lived).  The zone set is
//! immutable, so concurrent readers need no locking.

const std = @import("std");
const Io = std.Io;
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");
const message = @import("../dns/message.zig");
const zone = @import("../zone/zone.zig");
const sema = @import("../zone/sema.zig");
const journal_mod = @import("../zone/journal.zig");
const transfer = @import("../zone/transfer.zig");
const ZoneSet = @import("queryset.zig").ZoneSet;
const Responder = @import("query.zig").Responder;
const acl = @import("acl.zig");
const ratelimit = @import("ratelimit.zig");
const tsig = @import("../dns/tsig.zig");
const secondary = @import("secondary.zig");
const update = @import("update.zig");
const keydir = @import("../dnssec/keydir.zig");

pub const Listen = struct {
    addr: Io.net.IpAddress,
};

pub const ZoneSpec = struct {
    origin: name.Name,
    file: []const u8,
    role: Role = .primary,
    primaries: []const secondary.Primary = &.{},
    allow_notify: acl.Set = .{ .entries = &.{} },
    allow_update: acl.Set = .{ .entries = &.{} },
    also_notify: []const NotifyTarget = &.{},
    journal_path: ?[]const u8 = null,
    allow_transfer: acl.Set = .{ .entries = &.{} },
    dnssec: ?sema.DnssecOptions = null,
};

pub const Role = enum { primary, secondary };

pub const NotifyTarget = struct {
    addr: Io.net.IpAddress,
    key_name: ?[]const u8 = null,
};

pub const Config = struct {
    listeners: []const Listen,
    zones: []const ZoneSpec,
    keys: []const tsig.Key = &.{},
    max_udp_size: u16 = 1232,
    tcp_max_size: usize = 65535,
    tcp_idle_seconds: u32 = 30,
    max_tcp_connections: u32 = 256,
    rate_limit_qps: u32 = 0,
    rate_limit_burst: u32 = 0,
};

const ZoneEntry = struct {
    zone: zone.Zone,
    journal: journal_mod.Journal,
    journal_path: ?[]const u8,
    zone_file: []const u8,
    origin: name.Name,
    role: Role,
    primaries: []const secondary.Primary,
    allow_notify: acl.Set,
    allow_update: acl.Set,
    also_notify: []const NotifyTarget,
    allow_transfer: acl.Set,
    dnssec: ?sema.DnssecOptions = null,
    next_refresh_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    last_sign_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    next_sig_check_ms: u64 = 0,
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: Io,
    config: Config,
    entries: []ZoneEntry,
    zone_ptrs: []*const zone.Zone,
    udp: []Io.net.Socket,
    tcp: []Io.net.Server,
    lock: Io.RwLock = .init,
    rate: ratelimit.Limiter = .{},
    replay: tsig.ReplayCache = .{},
    active_tcp: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    next_dnssec_check_ms: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, io: Io, config: Config) !Server {
        const entries = try gpa.alloc(ZoneEntry, config.zones.len);
        errdefer gpa.free(entries);
        var loaded: usize = 0;
        errdefer {
            for (entries[0..loaded]) |*e| {
                e.journal.deinit();
                e.zone.deinit();
            }
        }

        for (config.zones, 0..) |zs, i| {
            var z = if (zs.role == .secondary) blk: {
                const existing = sema.load(gpa, io, zs.file, .{
                    .origin = zs.origin,
                }) catch |e| switch (e) {
                    error.FileNotFound => {
                        if (zs.primaries.len == 0) {
                            std.debug.print("secondary zone {s} has no primary\n", .{zs.file});
                            return e;
                        }
                        const xfr_key = findTsigKey(config.keys, zs.primaries[0].key_name);
                        if (zs.primaries[0].key_name != null and xfr_key == null) return error.UnknownTsigKey;
                        const res = secondary.fetch(gpa, io, zs.origin, types.class_in, zs.primaries[0], null, xfr_key) catch |fe| {
                            std.debug.print("initial transfer for {s} failed: {t}\n", .{ zs.file, fe });
                            return fe;
                        };
                        switch (res) {
                            .up_to_date => return error.BadTransfer,
                            .zone => |zz| break :blk zz,
                        }
                    },
                    else => return e,
                };
                break :blk existing;
            } else sema.load(gpa, io, zs.file, .{
                .origin = zs.origin,
                .dnssec = zs.dnssec,
            }) catch |e| {
                std.debug.print("cannot load zone file {s}: {t}\n", .{ zs.file, e });
                return e;
            };
            errdefer z.deinit();

            if (zs.role == .secondary) {
                // Persist the transferred zone so the next start can resume.
                zone.writeFile(&z, gpa, io, zs.file) catch |e| {
                    std.debug.print("cannot write secondary zone {s}: {t}\n", .{ zs.file, e });
                };
            }

            var j = if (zs.journal_path) |p|
                journal_mod.Journal.load(gpa, io, p) catch |e| {
                    std.debug.print("cannot load journal {s}: {t}\n", .{ p, e });
                    return e;
                }
            else
                journal_mod.Journal.init(gpa);
            errdefer j.deinit();
            if (j.deltas.items.len > 0 and j.deltas.items[j.deltas.items.len - 1].to_serial != z.serial) {
                j.clear();
            }
            entries[i] = .{
                .zone = z,
                .journal = j,
                .journal_path = zs.journal_path,
                .zone_file = zs.file,
                .origin = zs.origin,
                .role = zs.role,
                .primaries = zs.primaries,
                .allow_notify = zs.allow_notify,
                .allow_update = zs.allow_update,
                .also_notify = zs.also_notify,
                .allow_transfer = zs.allow_transfer,
                .dnssec = zs.dnssec,
                .next_refresh_ms = std.atomic.Value(u64).init(if (zs.role == .secondary) nowMs() + @as(u64, z.refresh) * 1000 else 0),
                .last_sign_ms = std.atomic.Value(u64).init(nowMs()),
            };
            loaded += 1;

            var nbuf: [name.max_name_len]u8 = undefined;
            for (z.warnings) |w| std.debug.print("zone {s}: warning: {s}\n", .{ z.origin.toText(&nbuf) catch z.origin_wire, w });
            std.debug.print("loaded {s} zone {s} serial {d} ({d} records){s}\n", .{
                @tagName(zs.role), z.origin.toText(&nbuf) catch z.origin_wire, z.serial, z.record_count, if (z.isSigned()) " [signed]" else "",
            });
        }

        const zone_ptrs = try gpa.alloc(*const zone.Zone, entries.len);
        errdefer gpa.free(zone_ptrs);
        for (entries, 0..) |*e, i| zone_ptrs[i] = &e.zone;

        var udp: std.ArrayList(Io.net.Socket) = .empty;
        errdefer {
            for (udp.items) |*s| s.close(io);
            udp.deinit(gpa);
        }
        var tcp: std.ArrayList(Io.net.Server) = .empty;
        errdefer {
            for (tcp.items) |*s| s.deinit(io);
            tcp.deinit(gpa);
        }
        for (config.listeners) |l| {
            var udp_sock = try l.addr.bind(io, .{ .mode = .dgram });
            udp.append(gpa, udp_sock) catch |e| {
                udp_sock.close(io);
                return e;
            };
            var tcp_srv = try l.addr.listen(io, .{ .reuse_address = true });
            tcp.append(gpa, tcp_srv) catch |e| {
                tcp_srv.deinit(io);
                return e;
            };
            std.debug.print("listening on {f}\n", .{l.addr});
        }

        return .{
            .gpa = gpa,
            .io = io,
            .config = config,
            .entries = entries,
            .zone_ptrs = zone_ptrs,
            .udp = try udp.toOwnedSlice(gpa),
            .tcp = try tcp.toOwnedSlice(gpa),
            .rate = ratelimit.Limiter.init(config.rate_limit_qps, config.rate_limit_burst),
        };
    }

    pub fn deinit(self: *Server) void {
        self.rate.deinit(self.gpa);
        self.replay.deinit(self.gpa);
        for (self.udp) |*s| s.close(self.io);
        for (self.tcp) |*s| s.deinit(self.io);
        self.gpa.free(self.udp);
        self.gpa.free(self.tcp);
        for (self.entries) |*e| {
            e.journal.deinit();
            e.zone.deinit();
        }
        self.gpa.free(self.entries);
        self.gpa.free(self.zone_ptrs);
    }

    pub fn run(self: *Server) !void {
        var zs = ZoneSet{ .zones = self.zone_ptrs };
        var responder = Responder{
            .zones = &zs,
            .opts = .{
                .max_udp_size = self.config.max_udp_size,
                .tcp_max_size = self.config.tcp_max_size,
            },
        };

        for (self.udp) |*sock| {
            const t = std.Thread.spawn(.{}, udpLoop, .{ self, &responder, sock }) catch |e| {
                std.debug.print("udp thread: {t}\n", .{e});
                continue;
            };
            t.detach();
        }
        for (self.tcp) |*srv| {
            const t = std.Thread.spawn(.{}, tcpLoop, .{ self, &responder, srv }) catch |e| {
                std.debug.print("tcp thread: {t}\n", .{e});
                continue;
            };
            t.detach();
        }
        installReloadHandler();
        while (true) {
            if (reload_requested.swap(false, .acquire)) {
                self.reload() catch |e| std.debug.print("reload failed: {t}\n", .{e});
            }
            self.refreshSecondaries();
            self.maintainDnssec();
            Io.sleep(self.io, .fromNanoseconds(1 * std.time.ns_per_s), .awake) catch {};
        }
    }

    fn reload(self: *Server) !void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.config.zones, 0..) |spec, i| {
            if (spec.role == .secondary) {
                self.entries[i].next_refresh_ms.store(0, .release);
                continue;
            }
            var newz = sema.load(self.gpa, self.io, spec.file, .{
                .origin = spec.origin,
                .dnssec = spec.dnssec,
            }) catch |e| {
                std.debug.print("reload zone {s}: {t}\n", .{ spec.file, e });
                continue;
            };
            const old = &self.entries[i].zone;
            const serial_changed = newz.serial != old.serial;
            if (newz.serial == old.serial) {
                // A periodic re-sign changes only RRSIGs; keep the IXFR
                // history in that case.  Any real data change with the same
                // serial is not representable by IXFR, so invalidate it.
                var d = journal_mod.diff(self.gpa, old, &newz) catch {
                    self.entries[i].journal.clear();
                    var t = newz;
                    t.deinit();
                    continue;
                };
                var only_sigs = true;
                for (d.removed) |r| if (r.rtype != types.RRSIG) {
                    only_sigs = false;
                };
                for (d.added) |r| if (r.rtype != types.RRSIG) {
                    only_sigs = false;
                };
                d.deinit(self.gpa);
                if (!only_sigs) self.entries[i].journal.clear();
            } else if (zone.serialGreater(newz.serial, old.serial)) {
                var delta = journal_mod.diff(self.gpa, old, &newz) catch |e| {
                    std.debug.print("reload diff: {t}\n", .{e});
                    var t = newz;
                    t.deinit();
                    continue;
                };
                self.entries[i].journal.append(delta) catch |e| {
                    delta.deinit(self.gpa);
                    std.debug.print("reload journal: {t}\n", .{e});
                    var t = newz;
                    t.deinit();
                    continue;
                };
                if (self.entries[i].journal_path) |p| {
                    self.entries[i].journal.save(self.io, p) catch |e| {
                        std.debug.print("journal save {s}: {t}\n", .{ p, e });
                    };
                }
            } else {
                self.entries[i].journal.clear();
            }
            old.deinit();
            self.entries[i].zone = newz;
            if (serial_changed) self.sendNotify(&self.entries[i]);
            var nbuf: [name.max_name_len]u8 = undefined;
            std.debug.print("reloaded zone {s} serial {d}\n", .{ newz.origin.toText(&nbuf) catch newz.origin_wire, newz.serial });
        }
    }

    fn processUpdate(self: *Server, q: *const message.Message, from: Io.net.IpAddress, tsig_req: ?*const tsig.Request) types.Rcode {
        if (q.header.qdcount != 1) return .formerr;
        const qq = q.question() orelse return .formerr;
        if (qq.qtype != types.SOA or qq.qclass != types.class_in) return .formerr;
        var lower: [name.max_name_len]u8 = undefined;
        const qn = zone.Zone.normalize(qq.qname.slice(), &lower);
        var entry: ?*ZoneEntry = null;
        for (self.entries) |*e| {
            if (e.role != .primary) continue;
            if (std.mem.eql(u8, qn, e.origin.slice())) {
                entry = e;
                break;
            }
        }
        const e = entry orelse return .notauth;
        const key_name: ?[]const u8 = if (tsig_req) |r| r.key.name_text else null;
        if (!e.allow_update.allows(from, key_name)) {
            std.debug.print("update refused by ACL from {f}\n", .{from});
            return .refused;
        }

        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const outcome = update.apply(a, &e.zone, q, e.dnssec != null) catch |err| {
            std.debug.print("update apply error: {t}\n", .{err});
            return .servfail;
        };
        switch (outcome) {
            .rcode => |rc| {
                std.debug.print("update rcode {s}\n", .{types.rcodeToText(@backingInt(rc))});
                return rc;
            },
            .ok => |recs| {
                const tmp = std.fmt.allocPrint(a, "{s}.tmp", .{e.zone_file}) catch return .servfail;
                zone.writeRecords(recs, a, self.io, tmp) catch return .servfail;
                const newz = sema.load(self.gpa, self.io, tmp, .{
                    .origin = e.origin,
                    .dnssec = e.dnssec,
                }) catch |err| {
                    std.debug.print("update reload {s} failed: {t}\n", .{ tmp, err });
                    return .refused;
                };
                var old = e.zone;
                var delta = journal_mod.diff(self.gpa, &old, &newz) catch {
                    var t = newz;
                    t.deinit();
                    return .servfail;
                };
                std.Io.Dir.cwd().rename(tmp, std.Io.Dir.cwd(), e.zone_file, self.io) catch {
                    delta.deinit(self.gpa);
                    std.Io.Dir.cwd().deleteFile(self.io, tmp) catch {};
                    var t = newz;
                    t.deinit();
                    return .servfail;
                };
                e.journal.append(delta) catch |err| {
                    std.debug.print("update journal append: {t}\n", .{err});
                    delta.deinit(self.gpa);
                };
                if (e.journal_path) |p| e.journal.save(self.io, p) catch {};
                e.zone = newz;
                old.deinit();
                e.last_sign_ms.store(nowMs(), .release);
                self.sendNotify(e);
                return .noerror;
            },
        }
    }

    fn updateResponse(self: *Server, buf: []u8, q: *const message.Message, rcode: types.Rcode) []u8 {
        _ = self;
        var h: message.Header = .{ .id = q.header.id };
        h.setQr(true);
        h.setOpcode(5);
        h.setRcode(@backingInt(rcode));
        var b = message.Builder.init(buf, h, buf.len) catch return buf[0..0];
        if (q.question()) |qq| b.addQuestion(qq.qname.slice(), qq.qtype, qq.qclass) catch {};
        return b.finish();
    }

    fn sendUpdateUdp(self: *Server, sock: *Io.net.Socket, to: Io.net.IpAddress, q: *const message.Message, rcode: types.Rcode, tsig_req: ?*const tsig.Request) void {
        var buf: [4096]u8 = undefined;
        const wire = self.updateResponse(&buf, q, rcode);
        if (tsig_req) |req| {
            const signed = tsig.appendResponse(self.gpa, &buf, wire.len, req.key, .{
                .prior_mac = req.mac,
                .original_id = req.original_id,
            }) catch return;
            sock.send(self.io, &to, buf[0..signed.len]) catch {};
            return;
        }
        sock.send(self.io, &to, wire) catch {};
    }

    fn sendUpdateTcp(self: *Server, stream: *const Io.net.Stream, q: *const message.Message, rcode: types.Rcode, tsig_req: ?*const tsig.Request) void {
        var buf: [4096]u8 = undefined;
        const wire = self.updateResponse(&buf, q, rcode);
        if (tsig_req) |req| {
            const signed = tsig.appendResponse(self.gpa, &buf, wire.len, req.key, .{
                .prior_mac = req.mac,
                .original_id = req.original_id,
            }) catch return;
            self.writeTcp(stream, buf[0..signed.len]) catch {};
            return;
        }
        self.writeTcp(stream, wire) catch {};
    }

    fn maintainDnssec(self: *Server) void {
        const now = nowMs();
        if (now < self.next_dnssec_check_ms) return;
        self.next_dnssec_check_ms = now + 1_000;
        for (self.entries) |*e| {
            if (e.role != .primary) continue;
            const dc = e.dnssec orelse continue;
            if (!dc.auto) continue;
            const dir = dc.key_dir orelse continue;
            if (keydir.maintain(self.gpa, self.io, dir, .{
                .zsk_lifetime = dc.zsk_lifetime,
                .propagation = dc.propagation,
            }) catch |err| {
                std.debug.print("dnssec key maintenance {s}: {t}\n", .{ dir, err });
                continue;
            }) {
                self.reSignEntry(e, dc, true) catch |err| {
                    std.debug.print("dnssec re-sign after key change {s}: {t}\n", .{ e.zone_file, err });
                };
                continue;
            }
            const interval_ms = @as(u64, @max(dc.resign_interval, 1)) * 1000;
            const due = now - e.last_sign_ms.load(.acquire) >= interval_ms;
            var expiring = false;
            if (now >= e.next_sig_check_ms) {
                e.next_sig_check_ms = now + 60_000;
                expiring = self.signaturesExpiring(e, dc.validity);
            }
            if (due or expiring) {
                self.reSignEntry(e, dc, false) catch |err| {
                    std.debug.print("dnssec periodic re-sign {s}: {t}\n", .{ e.zone_file, err });
                };
            }
        }
    }

    fn signaturesExpiring(self: *Server, e: *ZoneEntry, validity: u32) bool {
        _ = self;
        const now_s: u64 = epochSeconds();
        const threshold: u64 = @as(u64, validity) / 3;
        for (e.zone.allRRsets()) |*rs| {
            if (rs.rtype != types.RRSIG) continue;
            for (rs.rdata) |rd| {
                if (rd.len < 12) continue;
                const exp = std.mem.readInt(u32, rd[8..12], .big);
                if (@as(u64, exp) <= now_s + threshold) return true;
            }
        }
        return false;
    }

    fn reSignEntry(self: *Server, e: *ZoneEntry, dc: sema.DnssecOptions, key_changed: bool) !void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);

        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();

        const flat = try zone.flatten(&e.zone, a);
        var recs: std.ArrayList(zone.Record) = .empty;
        for (flat) |r| {
            if (r.rtype == types.RRSIG or r.rtype == types.NSEC or r.rtype == types.NSEC3 or
                r.rtype == types.NSEC3PARAM or r.rtype == types.DNSKEY) continue;
            try recs.append(a, r);
        }
        var soa_index: ?usize = null;
        for (recs.items, 0..) |r, i| {
            if (r.rtype == types.SOA and std.mem.eql(u8, r.owner, e.origin.slice())) {
                soa_index = i;
                break;
            }
        }
        const si = soa_index orelse return error.MissingSoa;
        const new_serial = zone.appendSerial(e.zone.serial);
        recs.items[si].rdata = try zone.soaWithSerial(a, recs.items[si].rdata, new_serial);

        const tmp = try std.fmt.allocPrint(a, "{s}.tmp", .{e.zone_file});
        try zone.writeRecords(recs.items, a, self.io, tmp);
        const newz = sema.load(self.gpa, self.io, tmp, .{
            .origin = e.origin,
            .dnssec = dc,
        }) catch |err| {
            std.Io.Dir.cwd().deleteFile(self.io, tmp) catch {};
            return err;
        };
        var old = e.zone;
        var delta = journal_mod.diff(self.gpa, &old, &newz) catch |err| {
            var t = newz;
            t.deinit();
            return err;
        };
        std.Io.Dir.cwd().rename(tmp, std.Io.Dir.cwd(), e.zone_file, self.io) catch |err| {
            delta.deinit(self.gpa);
            std.Io.Dir.cwd().deleteFile(self.io, tmp) catch {};
            var t = newz;
            t.deinit();
            return err;
        };
        e.journal.append(delta) catch |err| {
            std.debug.print("re-sign journal append: {t}\n", .{err});
            delta.deinit(self.gpa);
        };
        if (e.journal_path) |p| e.journal.save(self.io, p) catch {};
        e.zone = newz;
        old.deinit();
        e.last_sign_ms.store(nowMs(), .release);
        self.sendNotify(e);
        var nbuf: [name.max_name_len]u8 = undefined;
        std.debug.print("re-signed zone {s} serial {d}{s}\n", .{
            e.zone.origin.toText(&nbuf) catch e.zone.origin_wire,
            e.zone.serial,
            if (key_changed) " after key change" else "",
        });
    }

    fn refreshSecondaries(self: *Server) void {
        const now = nowMs();
        for (self.entries, 0..) |*e, i| {
            if (e.role != .secondary) continue;
            if (now < e.next_refresh_ms.load(.acquire)) continue;
            self.refreshSecondary(e, self.config.zones[i]) catch |err| {
                std.debug.print("secondary refresh {s}: {t}\n", .{ e.zone_file, err });
                const retry = @max(@as(u64, e.zone.retry), 5);
                e.next_refresh_ms.store(nowMs() + retry * 1000, .release);
            };
        }
    }

    fn refreshSecondary(self: *Server, e: *ZoneEntry, spec: ZoneSpec) !void {
        if (spec.primaries.len == 0) return error.NoPrimary;
        const xfr_key = findTsigKey(self.config.keys, spec.primaries[0].key_name);
        if (spec.primaries[0].key_name != null and xfr_key == null) return error.UnknownTsigKey;
        const res = secondary.fetch(self.gpa, self.io, e.origin, e.zone.class, spec.primaries[0], &e.zone, xfr_key) catch |err| {
            return err;
        };
        switch (res) {
            .up_to_date => {},
            .zone => |newz| {
                var delta = journal_mod.diff(self.gpa, &e.zone, &newz) catch |err| {
                    var t = newz;
                    t.deinit();
                    return err;
                };
                self.lock.lockUncancelable(self.io);
                defer self.lock.unlock(self.io);
                e.journal.append(delta) catch |err| {
                    delta.deinit(self.gpa);
                    var t = newz;
                    t.deinit();
                    return err;
                };
                if (e.journal_path) |p| e.journal.save(self.io, p) catch |err| {
                    std.debug.print("journal save {s}: {t}\n", .{ p, err });
                };
                var old = e.zone;
                e.zone = newz;
                old.deinit();
                zone.writeFile(&e.zone, self.gpa, self.io, e.zone_file) catch |err| {
                    std.debug.print("secondary zone write {s}: {t}\n", .{ e.zone_file, err });
                };
                var nbuf: [name.max_name_len]u8 = undefined;
                std.debug.print("secondary zone {s} updated to serial {d}\n", .{
                    e.zone.origin.toText(&nbuf) catch e.zone.origin_wire, e.zone.serial,
                });
                self.sendNotify(e);
            },
        }
        const interval = @max(@as(u64, e.zone.refresh), 5);
        e.next_refresh_ms.store(nowMs() + interval * 1000, .release);
    }

    fn sendNotify(self: *Server, e: *ZoneEntry) void {
        if (e.also_notify.len == 0 or self.udp.len == 0) return;
        var buf: [512]u8 = undefined;
        var random_id: u16 = 0;
        self.io.random(std.mem.asBytes(&random_id));
        var h: message.Header = .{ .id = random_id };
        h.setOpcode(4);
        h.setAa(true);
        var b = message.Builder.init(&buf, h, buf.len) catch return;
        b.addQuestion(e.origin.slice(), types.SOA, types.class_in) catch return;
        const wire = b.finish();
        for (e.also_notify) |target| {
            std.debug.print("sending NOTIFY {s} to {f}{s}\n", .{
                @tagName(e.role),                               target.addr,
                if (target.key_name != null) " (TSIG)" else "",
            });
            var sbuf: [1024]u8 = undefined;
            @memcpy(sbuf[0..wire.len], wire);
            var out: []const u8 = sbuf[0..wire.len];
            if (target.key_name) |kn| {
                const key = findTsigKey(self.config.keys, kn) orelse {
                    std.debug.print("NOTIFY TSIG key {s} not found\n", .{kn});
                    continue;
                };
                const signed = tsig.appendRequest(self.gpa, &sbuf, wire.len, key, random_id) catch |err| {
                    std.debug.print("NOTIFY TSIG sign failed: {t}\n", .{err});
                    continue;
                };
                out = sbuf[0..signed.len];
            }
            self.udp[0].send(self.io, &target.addr, out) catch |err| {
                std.debug.print("NOTIFY send failed: {t}\n", .{err});
            };
        }
    }

    fn entryForZone(self: *Server, z: *const zone.Zone) ?*ZoneEntry {
        for (self.entries) |*e| {
            if (&e.zone == z) return e;
        }
        return null;
    }

    fn udpLoop(self: *Server, responder: *const Responder, sock: *Io.net.Socket) void {
        var buf: [65535]u8 = undefined;
        while (true) {
            const msg = sock.receive(self.io, &buf) catch |e| {
                std.debug.print("udp receive: {t}\n", .{e});
                continue;
            };
            self.handleUdp(responder, sock, msg);
        }
    }

    fn handleUdp(self: *Server, responder: *const Responder, sock: *Io.net.Socket, msg: Io.net.IncomingMessage) void {
        if (self.rate.enabled() and !self.rate.allow(self.gpa, msg.from)) return;
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();

        var q = message.parse(a, msg.data) catch {
            self.sendUdpRcode(sock, msg.from, msg.data, 1);
            return;
        };
        var tsig_req: ?tsig.Request = null;
        if (q.tsig()) |rr| {
            var ctx: tsig.VerifyContext = .{};
            tsig_req = tsig.verifyRequest(a, q.raw, rr, self.config.keys, &ctx) catch |e| {
                if (e == error.BadTime and ctx.key != null and ctx.mac_valid) {
                    self.sendUdpBadTime(sock, msg.from, msg.data, &ctx);
                    return;
                }
                const rcode: u4 = switch (e) {
                    error.BadKey, error.BadMac, error.BadTime, error.MacTooShort, error.MacTooLong => 9,
                    else => 1,
                };
                self.sendUdpRcode(sock, msg.from, msg.data, rcode);
                return;
            };
            if (!self.replay.checkAndUpdate(self.gpa, ctx.key.?.name_wire, ctx.parsed.?.time_signed, ctx.parsed.?.fudge)) {
                self.sendUdpBadTime(sock, msg.from, msg.data, &ctx);
                return;
            }
        }
        if (q.header.opcode() == 4) {
            if (!q.header.qr()) self.handleNotifyUdp(&q, msg.from, sock, if (tsig_req) |*r| r else null);
            return;
        }
        if (q.header.opcode() == 5) {
            if (q.header.qr()) return;
            const rcode = self.processUpdate(&q, msg.from, if (tsig_req) |*r| r else null);
            self.sendUpdateUdp(sock, msg.from, &q, rcode, if (tsig_req) |*r| r else null);
            return;
        }
        const reserve: usize = if (tsig_req != null) 512 else 0;

        var rbuf: [65535]u8 = undefined;
        self.lock.lockSharedUncancelable(self.io);
        const res = responder.respondReserved(&q, &rbuf, self.config.max_udp_size, false, reserve) catch {
            self.lock.unlockShared(self.io);
            self.sendUdpRcode(sock, msg.from, msg.data, 2);
            return;
        };
        self.lock.unlockShared(self.io);
        switch (res) {
            .message => |wire| {
                var out = wire;
                if (tsig_req) |req| {
                    const signed = tsig.appendResponse(a, &rbuf, wire.len, req.key, .{
                        .prior_mac = req.mac,
                        .original_id = req.original_id,
                    }) catch {
                        self.sendUdpRcode(sock, msg.from, msg.data, 2);
                        return;
                    };
                    out = rbuf[0..signed.len];
                }
                sock.send(self.io, &msg.from, out) catch {};
            },
            .transfer => self.sendUdpRcode(sock, msg.from, msg.data, 5),
        }
    }

    fn notifyResponse(self: *Server, buf: []u8, q: *const message.Message, rcode: types.Rcode) []u8 {
        _ = self;
        var h: message.Header = .{ .id = q.header.id };
        h.setQr(true);
        h.setOpcode(4);
        h.setRcode(@backingInt(rcode));
        var b = message.Builder.init(buf, h, buf.len) catch return buf[0..0];
        if (q.question()) |qq| b.addQuestion(qq.qname.slice(), qq.qtype, qq.qclass) catch {};
        return b.finish();
    }

    fn handleNotifyUdp(self: *Server, q: *const message.Message, from: Io.net.IpAddress, sock: *Io.net.Socket, tsig_req: ?*const tsig.Request) void {
        const key_name: ?[]const u8 = if (tsig_req) |r| r.key.name_text else null;
        const rcode = self.acceptNotify(q, from, key_name);
        var buf: [1024]u8 = undefined;
        const wire = self.notifyResponse(&buf, q, rcode);
        if (tsig_req) |req| {
            const signed = tsig.appendResponse(self.gpa, &buf, wire.len, req.key, .{
                .prior_mac = req.mac,
                .original_id = req.original_id,
            }) catch return;
            sock.send(self.io, &from, buf[0..signed.len]) catch {};
            return;
        }
        sock.send(self.io, &from, wire) catch {};
    }

    fn handleNotifyTcp(self: *Server, q: *const message.Message, from: Io.net.IpAddress, stream: *const Io.net.Stream, tsig_req: ?*const tsig.Request) void {
        const key_name: ?[]const u8 = if (tsig_req) |r| r.key.name_text else null;
        const rcode = self.acceptNotify(q, from, key_name);
        var buf: [1024]u8 = undefined;
        const wire = self.notifyResponse(&buf, q, rcode);
        if (tsig_req) |req| {
            const signed = tsig.appendResponse(self.gpa, &buf, wire.len, req.key, .{
                .prior_mac = req.mac,
                .original_id = req.original_id,
            }) catch return;
            self.writeTcp(stream, buf[0..signed.len]) catch {};
            return;
        }
        self.writeTcp(stream, wire) catch {};
    }

    fn acceptNotify(self: *Server, q: *const message.Message, from: Io.net.IpAddress, key_name: ?[]const u8) types.Rcode {
        if (q.header.qr() or q.header.qdcount != 1) return .formerr;
        const qq = q.question() orelse return .formerr;
        if (qq.qtype != types.SOA or qq.qclass != types.class_in) return .formerr;
        var lower: [name.max_name_len]u8 = undefined;
        const qn = zone.Zone.normalize(qq.qname.slice(), &lower);
        for (self.entries) |*e| {
            if (e.role != .secondary) continue;
            if (!std.mem.eql(u8, qn, e.origin.slice())) continue;
            if (!e.allow_notify.allows(from, key_name)) {
                std.debug.print("NOTIFY refused from {f}\n", .{from});
                return .refused;
            }
            std.debug.print("NOTIFY accepted for {s} from {f}{s}\n", .{
                e.zone_file,                             from,
                if (key_name != null) " (TSIG)" else "",
            });
            e.next_refresh_ms.store(0, .release);
            return .noerror;
        }
        return .notauth;
    }

    fn sendUdpRcode(self: *Server, sock: *Io.net.Socket, to: Io.net.IpAddress, query: []const u8, rcode: u4) void {
        var buf: [512]u8 = undefined;
        if (query.len < 12) return;
        const len = self.buildError(&buf, query, rcode);
        sock.send(self.io, &to, buf[0..len]) catch {};
    }

    fn buildError(self: *Server, buf: []u8, query: []const u8, rcode: u4) usize {
        _ = self;
        @memset(buf[0..12], 0);
        buf[0] = query[0];
        buf[1] = query[1];
        buf[2] = 0x80 | (query[2] & 0x78); // QR=1, preserve opcode
        buf[3] = @intCast(rcode);
        // Echo the question when it is well-formed; otherwise leave QDCOUNT=0.
        if (query.len >= 12) {
            const qd = (@as(u16, query[4]) << 8) | query[5];
            if (qd == 1) {
                var n: name.Name = undefined;
                const after = name.parseWire(query, 12, &n) catch return 12;
                if (after + 4 <= query.len) {
                    const qlen = after + 4 - 12;
                    @memcpy(buf[12..][0..qlen], query[12..][0..qlen]);
                    buf[4] = 0;
                    buf[5] = 1;
                    return 12 + qlen;
                }
            }
        }
        return 12;
    }

    fn tcpLoop(self: *Server, responder: *const Responder, srv: *Io.net.Server) void {
        while (true) {
            var stream = srv.accept(self.io) catch |e| {
                std.debug.print("tcp accept: {t}\n", .{e});
                continue;
            };
            const active = self.active_tcp.fetchAdd(1, .acq_rel);
            if (active >= self.config.max_tcp_connections) {
                _ = self.active_tcp.fetchSub(1, .acq_rel);
                stream.close(self.io);
                continue;
            }
            const t = std.Thread.spawn(.{}, connThread, .{ self, responder, stream }) catch {
                _ = self.active_tcp.fetchSub(1, .acq_rel);
                stream.close(self.io);
                continue;
            };
            t.detach();
        }
    }

    fn connThread(self: *Server, responder: *const Responder, stream: Io.net.Stream) void {
        defer {
            _ = self.active_tcp.fetchSub(1, .acq_rel);
            stream.close(self.io);
        }
        const timeout_ms: i32 = if (self.config.tcp_idle_seconds == 0)
            -1
        else
            std.math.cast(i32, @as(u64, self.config.tcp_idle_seconds) * 1000) orelse -1;
        while (true) {
            var lenbuf: [2]u8 = undefined;
            readExact(stream.socket.handle, &lenbuf, timeout_ms) catch return;
            const len = (@as(usize, lenbuf[0]) << 8) | lenbuf[1];
            if (len < 12) return;
            if (self.rate.enabled() and !self.rate.allow(self.gpa, stream.socket.address)) return;
            var qbuf: [65535]u8 = undefined;
            readExact(stream.socket.handle, qbuf[0..len], timeout_ms) catch return;

            var arena = std.heap.ArenaAllocator.init(self.gpa);
            defer arena.deinit();
            var q = message.parse(arena.allocator(), qbuf[0..len]) catch {
                std.debug.print("tcp parse error\n", .{});
                self.writeTcpRcode(&stream, qbuf[0..len], 1);
                continue;
            };
            var tsig_req: ?tsig.Request = null;
            if (q.tsig()) |rr| {
                var ctx: tsig.VerifyContext = .{};
                tsig_req = tsig.verifyRequest(arena.allocator(), q.raw, rr, self.config.keys, &ctx) catch |e| {
                    if (e == error.BadTime and ctx.key != null and ctx.mac_valid) {
                        self.writeTcpBadTime(&stream, qbuf[0..len], &ctx);
                        continue;
                    }
                    const rcode: u4 = switch (e) {
                        error.BadKey, error.BadMac, error.BadTime, error.MacTooShort, error.MacTooLong => 9,
                        else => 1,
                    };
                    self.writeTcpRcode(&stream, qbuf[0..len], rcode);
                    continue;
                };
                if (!self.replay.checkAndUpdate(self.gpa, ctx.key.?.name_wire, ctx.parsed.?.time_signed, ctx.parsed.?.fudge)) {
                    self.writeTcpBadTime(&stream, qbuf[0..len], &ctx);
                    continue;
                }
            }
            if (q.header.opcode() == 4) {
                if (!q.header.qr()) self.handleNotifyTcp(&q, stream.socket.address, &stream, if (tsig_req) |*r| r else null);
                continue;
            }
            if (q.header.opcode() == 5) {
                if (q.header.qr()) continue;
                const rcode = self.processUpdate(&q, stream.socket.address, if (tsig_req) |*r| r else null);
                self.sendUpdateTcp(&stream, &q, rcode, if (tsig_req) |*r| r else null);
                continue;
            }
            const reserve: usize = if (tsig_req != null) 512 else 0;

            var rbuf: [65535]u8 = undefined;
            self.lock.lockSharedUncancelable(self.io);
            const res = responder.respondReserved(&q, &rbuf, self.config.tcp_max_size, true, reserve) catch {
                self.lock.unlockShared(self.io);
                self.writeTcpRcode(&stream, qbuf[0..len], 2);
                continue;
            };
            switch (res) {
                .message => |wire| {
                    self.lock.unlockShared(self.io);
                    if (tsig_req) |req| {
                        const signed = tsig.appendResponse(arena.allocator(), &rbuf, wire.len, req.key, .{
                            .prior_mac = req.mac,
                            .original_id = req.original_id,
                        }) catch {
                            self.writeTcpRcode(&stream, qbuf[0..len], 2);
                            continue;
                        };
                        self.writeTcp(&stream, rbuf[0..signed.len]) catch return;
                    } else {
                        self.writeTcp(&stream, wire) catch return;
                    }
                },
                .transfer => |tr| {
                    self.handleTransfer(&stream, &q, tr, if (tsig_req) |*r| r else null, true) catch return;
                },
            }
        }
    }

    fn handleTransfer(
        self: *Server,
        stream: *const Io.net.Stream,
        q: *const message.Message,
        tr: anytype,
        tsig_req: ?*const tsig.Request,
        prelocked: bool,
    ) !void {
        if (!prelocked) self.lock.lockSharedUncancelable(self.io);
        var lock_held = true;
        defer if (lock_held) self.lock.unlockShared(self.io);
        const entry = self.entryForZone(tr.zone) orelse return error.UnknownZone;
        const key_name: ?[]const u8 = if (tsig_req) |r| r.key.name_text else null;
        var nbuf: [name.max_name_len]u8 = undefined;
        const zname = tr.zone.origin.toText(&nbuf) catch tr.zone.origin_wire;
        if (key_name) |k| {
            std.debug.print("transfer {s} {s} from {f} key={s}\n", .{ @tagName(tr.kind), zname, stream.socket.address, k });
        } else {
            std.debug.print("transfer {s} {s} from {f}\n", .{ @tagName(tr.kind), zname, stream.socket.address });
        }
        if (!entry.allow_transfer.allows(stream.socket.address, key_name)) {
            lock_held = false;
            self.lock.unlockShared(self.io);
            var buf: [512]u8 = undefined;
            const wire = buildRefused(&buf, q);
            try self.writeTcp(stream, wire);
            return;
        }
        const topts: transfer.Options = .{ .max_message_size = if (tsig_req != null) 65535 - 512 else 65535 };
        const msgs = switch (tr.kind) {
            .axfr => try transfer.buildAxfr(self.gpa, tr.zone, q, topts),
            .ixfr => try transfer.buildIxfr(self.gpa, tr.zone, &entry.journal, q, topts),
        };
        lock_held = false;
        self.lock.unlockShared(self.io);
        defer {
            for (msgs) |m| self.gpa.free(m);
            self.gpa.free(msgs);
        }
        if (tsig_req) |req| {
            var prior_buf: [64]u8 = undefined;
            var prior_mac: []const u8 = &.{};
            for (msgs, 0..) |m, idx| {
                const sbuf = try self.gpa.alloc(u8, m.len + 512);
                defer self.gpa.free(sbuf);
                @memcpy(sbuf[0..m.len], m);
                const signed = try tsig.appendResponse(self.gpa, sbuf, m.len, req.key, .{
                    .prior_mac = if (idx == 0) req.mac else prior_mac,
                    .original_id = req.original_id,
                    .timers_only = idx != 0,
                });
                @memcpy(prior_buf[0..signed.mac_len], signed.mac[0..signed.mac_len]);
                prior_mac = prior_buf[0..signed.mac_len];
                try self.writeTcp(stream, sbuf[0..signed.len]);
            }
        } else {
            for (msgs) |m| try self.writeTcp(stream, m);
        }
    }

    fn writeTcp(self: *Server, stream: *const Io.net.Stream, wire: []const u8) !void {
        const len: u16 = std.math.cast(u16, wire.len) orelse return error.MessageTooLarge;
        var prefix: [2]u8 = .{ @intCast(len >> 8), @intCast(len & 0xff) };
        const timeout_ms: i32 = if (self.config.tcp_idle_seconds == 0)
            -1
        else
            std.math.cast(i32, @as(u64, self.config.tcp_idle_seconds) * 1000) orelse -1;
        try sendAll(stream.socket.handle, &prefix, timeout_ms);
        try sendAll(stream.socket.handle, wire, timeout_ms);
    }

    fn writeTcpRcode(self: *Server, stream: *const Io.net.Stream, query: []const u8, rcode: u4) void {
        var buf: [512]u8 = undefined;
        const len = self.buildError(&buf, query, rcode);
        self.writeTcp(stream, buf[0..len]) catch {};
    }

    fn sendUdpBadTime(self: *Server, sock: *Io.net.Socket, to: Io.net.IpAddress, query: []const u8, ctx: *const tsig.VerifyContext) void {
        var buf: [2048]u8 = undefined;
        const len = self.buildError(&buf, query, 9);
        const other = tsig.serverTime48();
        const signed = tsig.appendResponse(self.gpa, &buf, len, ctx.key.?, .{
            .prior_mac = ctx.parsed.?.mac,
            .original_id = ctx.parsed.?.original_id,
            .time_signed = ctx.parsed.?.time_signed,
            .fudge = ctx.parsed.?.fudge,
            .error_code = 18,
            .other = &other,
        }) catch return;
        sock.send(self.io, &to, buf[0..signed.len]) catch {};
    }

    fn writeTcpBadTime(self: *Server, stream: *const Io.net.Stream, query: []const u8, ctx: *const tsig.VerifyContext) void {
        var buf: [2048]u8 = undefined;
        const len = self.buildError(&buf, query, 9);
        const other = tsig.serverTime48();
        const signed = tsig.appendResponse(self.gpa, &buf, len, ctx.key.?, .{
            .prior_mac = ctx.parsed.?.mac,
            .original_id = ctx.parsed.?.original_id,
            .time_signed = ctx.parsed.?.time_signed,
            .fudge = ctx.parsed.?.fudge,
            .error_code = 18,
            .other = &other,
        }) catch return;
        self.writeTcp(stream, buf[0..signed.len]) catch {};
    }
};

fn sendAll(fd: std.posix.fd_t, data: []const u8, timeout_ms: i32) !void {
    var off: usize = 0;
    while (off < data.len) {
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
        const n = std.posix.poll(&fds, timeout_ms) catch return error.WriteFailed;
        if (n == 0) return error.Timeout;
        const rev = fds[0].revents;
        if (rev & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) return error.Closed;
        const r = std.c.send(fd, @ptrCast(data.ptr + off), data.len - off, @intCast(std.posix.MSG.NOSIGNAL));
        if (r < 0) return error.WriteFailed;
        if (r == 0) return error.Closed;
        off += @intCast(r);
    }
}

fn readExact(fd: std.posix.fd_t, buf: []u8, timeout_ms: i32) !void {
    var off: usize = 0;
    while (off < buf.len) {
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const n = std.posix.poll(&fds, timeout_ms) catch return error.ReadFailed;
        if (n == 0) return error.Timeout;
        const rev = fds[0].revents;
        if (rev & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0) return error.EndOfStream;
        const r = std.c.recv(fd, @ptrCast(buf.ptr + off), buf.len - off, 0);
        if (r == 0) return error.EndOfStream;
        if (r < 0) return error.ReadFailed;
        off += @intCast(r);
    }
}

fn buildRefused(buf: []u8, q: *const message.Message) []u8 {
    var h: message.Header = .{ .id = q.header.id };
    h.setQr(true);
    h.setRd(q.header.rd());
    h.setRcode(5);
    var b = message.Builder.init(buf, h, buf.len) catch return buf[0..0];
    if (q.question()) |qq| b.addQuestion(qq.qname.slice(), qq.qtype, qq.qclass) catch {};
    return b.finish();
}

var reload_requested = std.atomic.Value(bool).init(false);

fn onHup(_: std.posix.SIG) callconv(.c) void {
    reload_requested.store(true, .release);
}

fn installReloadHandler() void {
    var act: std.posix.Sigaction = .{
        .handler = .{ .handler = onHup },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &act, null);
}

fn findTsigKey(keys: []const tsig.Key, name_text: ?[]const u8) ?*const tsig.Key {
    const n = name_text orelse return null;
    for (keys) |*k| {
        const ka = std.mem.trimEnd(u8, k.name_text, ".");
        const kb = std.mem.trimEnd(u8, n, ".");
        if (std.ascii.eqlIgnoreCase(ka, kb)) return k;
    }
    return null;
}

fn epochSeconds() u64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.posix.CLOCK.REALTIME, &ts) != 0) return 0;
    return @intCast(@max(ts.sec, 0));
}

fn nowMs() u64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts) != 0) return 0;
    return @as(u64, @intCast(@max(ts.sec, 0))) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
}
