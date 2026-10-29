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
const tsig = @import("../dns/tsig.zig");

pub const Listen = struct {
    addr: Io.net.IpAddress,
};

pub const ZoneSpec = struct {
    origin: name.Name,
    file: []const u8,
    journal_path: ?[]const u8 = null,
    allow_transfer: acl.Set = .{ .entries = &.{} },
    dnssec: ?sema.DnssecOptions = null,
};

pub const Config = struct {
    listeners: []const Listen,
    zones: []const ZoneSpec,
    keys: []const tsig.Key = &.{},
    max_udp_size: u16 = 1232,
    tcp_max_size: usize = 65535,
};

const ZoneEntry = struct {
    zone: zone.Zone,
    journal: journal_mod.Journal,
    journal_path: ?[]const u8,
    allow_transfer: acl.Set,
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
            var z = sema.load(gpa, io, zs.file, .{
                .origin = zs.origin,
                .dnssec = zs.dnssec,
            }) catch |e| {
                std.debug.print("cannot load zone file {s}: {t}\n", .{ zs.file, e });
                return e;
            };
            errdefer z.deinit();
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
                .allow_transfer = zs.allow_transfer,
            };
            loaded += 1;

            var nbuf: [name.max_name_len]u8 = undefined;
            for (z.warnings) |w| std.debug.print("zone {s}: warning: {s}\n", .{ z.origin.toText(&nbuf) catch z.origin_wire, w });
            std.debug.print("loaded zone {s} serial {d} ({d} records){s}\n", .{
                z.origin.toText(&nbuf) catch z.origin_wire, z.serial, z.record_count, if (z.isSigned()) " [signed]" else "",
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
        };
    }

    pub fn deinit(self: *Server) void {
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
            Io.sleep(self.io, .fromNanoseconds(1 * std.time.ns_per_s), .awake) catch {};
        }
    }

    fn reload(self: *Server) !void {
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.config.zones, 0..) |spec, i| {
            var newz = sema.load(self.gpa, self.io, spec.file, .{
                .origin = spec.origin,
                .dnssec = spec.dnssec,
            }) catch |e| {
                std.debug.print("reload zone {s}: {t}\n", .{ spec.file, e });
                continue;
            };
            const old = &self.entries[i].zone;
            if (newz.serial == old.serial) {
                // A periodic re-sign changes only RRSIGs; keep the IXFR
                // history in that case.  Any real data change with the same
                // serial is not representable by IXFR, so invalidate it.
                var d = journal_mod.diff(self.gpa, old, &newz) catch {
                    self.entries[i].journal.clear();
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
                    continue;
                };
                self.entries[i].journal.append(delta) catch |e| {
                    delta.deinit(self.gpa);
                    std.debug.print("reload journal: {t}\n", .{e});
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
            var nbuf: [name.max_name_len]u8 = undefined;
            std.debug.print("reloaded zone {s} serial {d}\n", .{ newz.origin.toText(&nbuf) catch newz.origin_wire, newz.serial });
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
        var arena = std.heap.ArenaAllocator.init(self.gpa);
        defer arena.deinit();
        const a = arena.allocator();

        var q = message.parse(a, msg.data) catch {
            self.sendUdpRcode(sock, msg.from, msg.data, 1);
            return;
        };
        var tsig_req: ?tsig.Request = null;
        if (q.tsig()) |rr| {
            tsig_req = tsig.verifyRequest(a, q.raw, rr, self.config.keys) catch |e| {
                const rcode: u4 = switch (e) {
                    error.BadKey, error.BadMac, error.BadTime, error.MacTooShort, error.MacTooLong => 9,
                    else => 1,
                };
                self.sendUdpRcode(sock, msg.from, msg.data, rcode);
                return;
            };
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
                    const signed = tsig.appendResponse(a, &rbuf, wire.len, req.key, req.mac, req.original_id, false) catch {
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
        buf[2] = 0x80; // QR=1, opcode 0
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
            const t = std.Thread.spawn(.{}, connThread, .{ self, responder, stream }) catch {
                stream.close(self.io);
                continue;
            };
            t.detach();
        }
    }

    fn connThread(self: *Server, responder: *const Responder, stream: Io.net.Stream) void {
        defer stream.close(self.io);
        var read_buf: [4096]u8 = undefined;
        var reader = stream.reader(self.io, &read_buf);
        while (true) {
            var lenbuf: [2]u8 = undefined;
            readExact(&reader, &lenbuf) catch return;
            const len = (@as(usize, lenbuf[0]) << 8) | lenbuf[1];
            if (len < 12) return;
            var qbuf: [65535]u8 = undefined;
            readExact(&reader, qbuf[0..len]) catch return;

            var arena = std.heap.ArenaAllocator.init(self.gpa);
            defer arena.deinit();
            var q = message.parse(arena.allocator(), qbuf[0..len]) catch {
                std.debug.print("tcp parse error\n", .{});
                self.writeTcpRcode(&stream, qbuf[0..len], 1);
                continue;
            };
            var tsig_req: ?tsig.Request = null;
            if (q.tsig()) |rr| {
                tsig_req = tsig.verifyRequest(arena.allocator(), q.raw, rr, self.config.keys) catch |e| {
                    const rcode: u4 = switch (e) {
                        error.BadKey, error.BadMac, error.BadTime, error.MacTooShort, error.MacTooLong => 9,
                        else => 1,
                    };
                    self.writeTcpRcode(&stream, qbuf[0..len], rcode);
                    continue;
                };
            }
            const reserve: usize = if (tsig_req != null) 512 else 0;

            var rbuf: [65535]u8 = undefined;
            self.lock.lockSharedUncancelable(self.io);
            const res = responder.respondReserved(&q, &rbuf, self.config.tcp_max_size, true, reserve) catch {
                self.lock.unlockShared(self.io);
                self.writeTcpRcode(&stream, qbuf[0..len], 2);
                continue;
            };
            self.lock.unlockShared(self.io);
            switch (res) {
                .message => |wire| {
                    if (tsig_req) |req| {
                        const signed = tsig.appendResponse(arena.allocator(), &rbuf, wire.len, req.key, req.mac, req.original_id, false) catch {
                            self.writeTcpRcode(&stream, qbuf[0..len], 2);
                            continue;
                        };
                        self.writeTcp(&stream, rbuf[0..signed.len]) catch return;
                    } else {
                        self.writeTcp(&stream, wire) catch return;
                    }
                },
                .transfer => |tr| {
                    self.handleTransfer(&stream, &q, tr, if (tsig_req) |*r| r else null) catch return;
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
    ) !void {
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
            var buf: [512]u8 = undefined;
            const wire = buildRefused(&buf, q);
            try self.writeTcp(stream, wire);
            return;
        }
        self.lock.lockSharedUncancelable(self.io);
        const topts: transfer.Options = .{ .max_message_size = if (tsig_req != null) 65535 - 512 else 65535 };
        const msgs = switch (tr.kind) {
            .axfr => transfer.buildAxfr(self.gpa, tr.zone, q, topts) catch |e| {
                self.lock.unlockShared(self.io);
                return e;
            },
            .ixfr => transfer.buildIxfr(self.gpa, tr.zone, &entry.journal, q, topts) catch |e| {
                self.lock.unlockShared(self.io);
                return e;
            },
        };
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
                const signed = try tsig.appendResponse(
                    self.gpa,
                    sbuf,
                    m.len,
                    req.key,
                    if (idx == 0) req.mac else prior_mac,
                    req.original_id,
                    idx != 0,
                );
                @memcpy(prior_buf[0..signed.mac_len], signed.mac[0..signed.mac_len]);
                prior_mac = prior_buf[0..signed.mac_len];
                try self.writeTcp(stream, sbuf[0..signed.len]);
            }
        } else {
            for (msgs) |m| try self.writeTcp(stream, m);
        }
    }

    fn writeTcp(self: *Server, stream: *const Io.net.Stream, wire: []const u8) !void {
        var wbuf: [8192]u8 = undefined;
        var w = stream.writer(self.io, &wbuf);
        const len: u16 = std.math.cast(u16, wire.len) orelse return error.MessageTooLarge;
        var prefix: [2]u8 = .{ @intCast(len >> 8), @intCast(len & 0xff) };
        try w.interface.writeAll(&prefix);
        try w.interface.writeAll(wire);
        try w.interface.flush();
    }

    fn writeTcpRcode(self: *Server, stream: *const Io.net.Stream, query: []const u8, rcode: u4) void {
        var buf: [512]u8 = undefined;
        const len = self.buildError(&buf, query, rcode);
        self.writeTcp(stream, buf[0..len]) catch {};
    }
};

fn readExact(reader: *Io.net.Stream.Reader, buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = reader.interface.readSliceShort(buf[off..]) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;
        off += n;
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
