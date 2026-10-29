//! Authoritative query processing (RFC 1034 section 4.3.2, RFC 1035 section
//! 4.1, RFC 2308, RFC 4592).
//!
//! The responder never recurses.  It answers from the longest matching zone,
//! returns referrals for delegated subtrees, and synthesises wildcard answers
//! only when RFC 4592's closest-encloser rule allows it.

const std = @import("std");
const name = @import("../dns/name.zig");
const types = @import("../dns/types.zig");
const message = @import("../dns/message.zig");
const edns = @import("../dns/edns.zig");
const version = @import("../version.zig").version;
const nsec3 = @import("../dns/nsec3.zig");
const zone = @import("../zone/zone.zig");
const ZoneSet = @import("queryset.zig").ZoneSet;

pub const Options = struct {
    max_udp_size: u16 = edns.recommended_udp_size,
    tcp_max_size: usize = 65535,
    /// Include RRSIG/NSEC material when the request has DO=1 and the zone is
    /// signed.  Explicit QTYPE=RRSIG/DNSKEY/NSEC always works.
    dnssec: bool = true,
};

pub const TransferKind = enum { axfr, ixfr };
pub const Transfer = struct {
    kind: TransferKind,
    zone: *const zone.Zone,
};

pub const Result = union(enum) {
    message: []u8,
    transfer: Transfer,
};

pub const Responder = struct {
    zones: *const ZoneSet,
    opts: Options = .{},

    pub fn respond(
        self: *const Responder,
        query: *const message.Message,
        buf: []u8,
        limit_in: usize,
        is_tcp: bool,
    ) !Result {
        return self.respondReserved(query, buf, limit_in, is_tcp, 0);
    }

    /// `tsig_reserve` leaves room for a response TSIG RR inside the
    /// requestor's advertised UDP size.
    pub fn respondReserved(
        self: *const Responder,
        query: *const message.Message,
        buf: []u8,
        limit_in: usize,
        is_tcp: bool,
        tsig_reserve: usize,
    ) !Result {
        const q = query.question() orelse return self.errorResponse(query, buf, limit_in, .formerr, false, 0);
        var limit = @min(limit_in, buf.len);
        if (limit > tsig_reserve + 12) limit -= tsig_reserve;

        var h: message.Header = .{ .id = query.header.id };
        h.setQr(true);
        h.setOpcode(query.header.opcode());
        h.setRd(query.header.rd());
        h.setCd(query.header.cd());

        if (query.header.qr()) {
            return self.errorResponse(query, buf, limit, .formerr, false, 0);
        }
        if (query.header.opcode() != 0) {
            return self.errorResponse(query, buf, limit, .notimp, false, 0);
        }
        if (query.header.qdcount != 1) {
            return self.errorResponse(query, buf, limit, .formerr, false, 0);
        }

        // EDNS(0) validation.  The OPT must be in the additional section, at
        // most one, owned by the root, and version 0 (RFC 6891 section 6.1).
        var opt_present = false;
        var opt: edns.Opt = .{};
        var opt_count: usize = 0;
        var opt_bad = false;
        for (query.answers) |rr| if (rr.rtype == types.OPT) {
            opt_bad = true;
        };
        for (query.authority) |rr| if (rr.rtype == types.OPT) {
            opt_bad = true;
        };
        for (query.additional) |rr| {
            if (rr.rtype == types.OPT) {
                opt_count += 1;
                if (opt_count == 1) {
                    opt_present = true;
                    if (!rr.owner.isRoot()) {
                        opt_bad = true;
                    } else {
                        _ = edns.parse(rr.rdata) catch {
                            opt_bad = true;
                        };
                        opt = edns.decodeTtl(rr.ttl);
                        opt.udp_size = rr.class;
                        opt.options = rr.rdata;
                    }
                }
            }
        }
        if (opt_count > 1) opt_bad = true;
        if (opt_bad) return self.errorResponse(query, buf, limit, .formerr, opt_present, 0);

        if (is_tcp) {
            limit = @min(limit, self.opts.tcp_max_size);
        } else if (opt_present) {
            limit = @min(limit, @as(usize, @max(512, opt.udp_size)));
        } else {
            limit = @min(limit, 512);
        }

        // The response must reserve space for its OPT RR.
        const reserve: usize = if (opt_present) 11 else 0;
        var b = try message.Builder.init(buf, h, limit - @min(limit, reserve));
        try b.addQuestion(q.qname.slice(), q.qtype, q.qclass);

        const req_do = opt_present and opt.doBit();
        if (opt_present and opt.version != 0) {
            // BADVERS: extended RCODE 16 => header RCODE 0, OPT ext-RCODE 1.
            b.setRcode(0);
            if (opt_present) try b.addOpt(self.opts.max_udp_size, 1, 0, if (req_do) edns.do_flag else 0, &.{});
            return .{ .message = b.finish() };
        }

        if (q.qclass == types.class_ch) {
            if (q.qtype == types.TXT and
                (name.eqlWireIgnoreCase(q.qname.slice(), "\x07version\x04bind\x00") or
                    name.eqlWireIgnoreCase(q.qname.slice(), "\x08hostname\x04bind\x00")))
            {
                var txt: [64]u8 = undefined;
                const s = "auth-dns " ++ version;
                txt[0] = @intCast(s.len);
                @memcpy(txt[1..][0..s.len], s);
                try b.addRecord(.answer, q.qname.slice(), types.TXT, types.class_ch, 0, txt[0 .. 1 + s.len]);
                if (opt_present) b.addOpt(self.opts.max_udp_size, 0, 0, 0, &.{}) catch {};
                return .{ .message = b.finish() };
            }
            return self.errorResponse(query, buf, limit, .refused, opt_present, 0);
        }
        if (q.qclass != types.class_in) {
            return self.errorResponse(query, buf, limit, .refused, opt_present, 0);
        }
        if (types.isMetaType(q.qtype) and q.qtype != types.AXFR and q.qtype != types.IXFR and q.qtype != types.ANY) {
            return self.errorResponse(query, buf, limit, .notimp, opt_present, 0);
        }

        var lower_buf: [name.max_name_len]u8 = undefined;
        const qlower = zone.Zone.normalize(q.qname.slice(), &lower_buf);
        const z = self.zones.find(qlower) orelse
            return self.errorResponse(query, buf, limit, .refused, opt_present, 0);

        if (q.qtype == types.AXFR or q.qtype == types.IXFR) {
            if (!is_tcp) {
                b.setTc(true);
                if (opt_present) try b.addOpt(self.opts.max_udp_size, 0, 0, if (opt.doBit()) edns.do_flag else 0, &.{});
                return .{ .message = b.finish() };
            }
            return .{ .transfer = .{
                .kind = if (q.qtype == types.AXFR) .axfr else .ixfr,
                .zone = z,
            } };
        }

        const do = req_do and self.opts.dnssec;
        b.header.setAa(true);

        var added = AddedSet{};
        const status = self.answerName(&b, &added, z, q.qname.slice(), qlower, q.qtype, do, 0) catch |e| switch (e) {
            error.NoSpace => return self.truncated(query, buf, limit, b.header, opt_present, req_do),
            else => return e,
        };
        switch (status) {
            .answered => b.setRcode(0),
            .nodata => b.setRcode(0),
            .nxdomain => b.setRcode(3),
            .referral => {
                b.header.setAa(false);
                b.setRcode(0);
            },
            .servfail => b.setRcode(2),
        }

        if (opt_present) {
            b.addOpt(self.opts.max_udp_size, 0, 0, if (req_do) edns.do_flag else 0, &.{}) catch |e| switch (e) {
                error.NoSpace => return self.truncated(query, buf, limit, b.header, opt_present, req_do),
                else => return e,
            };
        }
        return .{ .message = b.finish() };
    }

    const Status = enum { answered, nodata, nxdomain, referral, servfail };

    fn answerName(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        owner_wire: []const u8,
        qname_lower: []const u8,
        qtype: u16,
        do: bool,
        depth: u8,
    ) anyerror!Status {
        // Delegation cut: everything at or below it is a referral, except a
        // DS query for the cut itself, which the parent answers.
        if (z.findDelegation(qname_lower)) |deleg| {
            if (std.mem.eql(u8, deleg, qname_lower) and qtype == types.DS) {
                if (z.rrsetAt(deleg, types.DS)) |ds| {
                    try self.addRRset(b, added, z, owner_wire, deleg, ds, .answer, null, do);
                    b.header.setAa(true);
                    return .answered;
                }
                try self.addNegativeSoa(b, added, z, do, deleg, false);
                return .nodata;
            }
            try self.addReferral(b, added, z, deleg, do);
            return .referral;
        }

        if (z.hasName(qname_lower)) {
            if (qtype == types.RRSIG) {
                var any = false;
                for (z.rrsetsAt(qname_lower)) |idx| {
                    const rs = &z.rrsets[idx];
                    if (rs.rtype != types.RRSIG) continue;
                    try self.addRRset(b, added, z, owner_wire, qname_lower, rs, .answer, null, do);
                    any = true;
                }
                if (!any) {
                    try self.addNegativeSoa(b, added, z, do, qname_lower, false);
                    return .nodata;
                }
                return .answered;
            }
            if (qtype == types.ANY) {
                if (z.rrsetAt(qname_lower, types.CNAME)) |cname| {
                    try self.addRRset(b, added, z, owner_wire, qname_lower, cname, .answer, null, do);
                    return .answered;
                }
                var any = false;
                for (z.rrsetsAt(qname_lower)) |idx| {
                    const rs = &z.rrsets[idx];
                    if (!do and (rs.rtype == types.RRSIG or rs.rtype == types.NSEC or rs.rtype == types.NSEC3)) continue;
                    try self.addRRset(b, added, z, owner_wire, qname_lower, rs, .answer, null, do);
                    any = true;
                }
                if (!any) {
                    try self.addNegativeSoa(b, added, z, do, qname_lower, false);
                    return .nodata;
                }
                return .answered;
            }

            if (qtype == types.CNAME) {
                if (z.rrsetAt(qname_lower, types.CNAME)) |rs| {
                    try self.addRRset(b, added, z, owner_wire, qname_lower, rs, .answer, null, do);
                    return .answered;
                }
                try self.addNegativeSoa(b, added, z, do, qname_lower, false);
                return .nodata;
            }

            // A CNAME owner answers non-DNSSEC queries with the CNAME and a
            // chased target (RFC 2181 section 10.1).
            if (z.rrsetAt(qname_lower, types.CNAME)) |cname| {
                if (qtype != types.RRSIG and qtype != types.DNSKEY and qtype != types.NSEC and qtype != types.NSEC3 and qtype != types.DS) {
                    try self.addRRset(b, added, z, owner_wire, qname_lower, cname, .answer, null, do);
                    return self.chase(b, added, z, cname, qtype, do, depth);
                }
            }

            if (z.rrsetAt(qname_lower, qtype)) |rs| {
                try self.addRRset(b, added, z, owner_wire, qname_lower, rs, .answer, null, do);
                return .answered;
            }
            try self.addNegativeSoa(b, added, z, do, qname_lower, false);
            return .nodata;
        }

        // No exact match: RFC 4592 wildcard processing.
        const ce = z.closestEncloser(qname_lower) orelse z.origin_wire;
        var wbuf: [name.max_name_len]u8 = undefined;
        const wildcard = zone.Zone.makeWildcard(ce, &wbuf) orelse {
            try self.addNegativeSoa(b, added, z, do, qname_lower, true);
            return .nxdomain;
        };
        var wildcard_exists = false;
        for (z.rrsetsAt(wildcard)) |_| wildcard_exists = true;
        if (wildcard_exists) {
            if (qtype == types.ANY) {
                var any = false;
                for (z.rrsetsAt(wildcard)) |idx| {
                    const rs = &z.rrsets[idx];
                    if (!do and (rs.rtype == types.RRSIG or rs.rtype == types.NSEC or rs.rtype == types.NSEC3)) continue;
                    try self.addRRset(b, added, z, owner_wire, wildcard, rs, .answer, null, do);
                    any = true;
                }
                if (!any) {
                    try self.addNegativeSoa(b, added, z, do, qname_lower, false);
                    return .nodata;
                }
                if (do and z.isSigned()) try self.addWildcardProof(b, added, z, qname_lower, wildcard, do);
                return .answered;
            }
            if (qtype == types.RRSIG) {
                var any = false;
                for (z.rrsetsAt(wildcard)) |idx| {
                    const rs = &z.rrsets[idx];
                    if (rs.rtype != types.RRSIG) continue;
                    try self.addRRset(b, added, z, owner_wire, wildcard, rs, .answer, null, do);
                    any = true;
                }
                if (any) {
                    if (do and z.isSigned()) try self.addWildcardProof(b, added, z, qname_lower, wildcard, do);
                    return .answered;
                }
            }
            if (z.rrsetAt(wildcard, types.CNAME)) |cname| {
                if (qtype != types.CNAME) {
                    if (qtype != types.RRSIG and qtype != types.DNSKEY and qtype != types.NSEC and qtype != types.NSEC3 and qtype != types.DS) {
                        try self.addRRset(b, added, z, owner_wire, wildcard, cname, .answer, null, do);
                        const st = try self.chase(b, added, z, cname, qtype, do, depth);
                        if (do and z.isSigned()) try self.addWildcardProof(b, added, z, qname_lower, wildcard, do);
                        return st;
                    }
                }
            }
            if (z.rrsetAt(wildcard, qtype)) |rs| {
                try self.addRRset(b, added, z, owner_wire, wildcard, rs, .answer, null, do);
                if (do and z.isSigned()) try self.addWildcardProof(b, added, z, qname_lower, wildcard, do);
                return .answered;
            }
            try self.addNegativeSoa(b, added, z, do, qname_lower, false);
            return .nodata;
        }

        try self.addNegativeSoa(b, added, z, do, qname_lower, true);
        return .nxdomain;
    }

    fn chase(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        cname: *const zone.RRset,
        qtype: u16,
        do: bool,
        depth: u8,
    ) anyerror!Status {
        if (depth >= 16) return .servfail;
        if (cname.rdata.len == 0) return .servfail;
        var target: name.Name = undefined;
        _ = name.parseWire(cname.rdata[0], 0, &target) catch return .servfail;
        name.lowerInPlace(target.buf[0..target.len]);
        if (std.mem.eql(u8, target.slice(), z.origin_wire) and false) return .servfail;
        if (target.isSubdomainOf(&z.origin)) {
            return self.answerName(b, added, z, target.slice(), target.slice(), qtype, do, depth + 1);
        }
        // Out-of-zone target: the CNAME alone is the authoritative answer.
        return .answered;
    }

    fn addRRset(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        response_owner: []const u8,
        lookup_owner: []const u8,
        rs: *const zone.RRset,
        section: message.Section,
        ttl_override: ?u32,
        do: bool,
    ) anyerror!void {
        if (!added.add(response_owner, rs.rtype, rs.covered orelse 0)) return;
        const ttl = ttl_override orelse rs.ttl;
        for (rs.rdata) |rd| {
            try b.addRecord(section, response_owner, rs.rtype, z.class, ttl, rd);
        }
        if (section == .answer and (rs.rtype == types.NS or rs.rtype == types.MX or rs.rtype == types.SRV)) {
            for (rs.rdata) |rd| {
                const off: usize = switch (rs.rtype) {
                    types.NS => 0,
                    types.MX => 2,
                    types.SRV => 6,
                    else => unreachable,
                };
                var target: name.Name = undefined;
                _ = name.parseWire(rd, off, &target) catch continue;
                name.lowerInPlace(target.buf[0..target.len]);
                try self.addGlue(b, added, z, target.slice());
            }
        }
        if (do and self.opts.dnssec and z.isSigned() and section != .additional and rs.rtype != types.RRSIG) {
            if (z.sigRRsetFor(lookup_owner, rs.rtype)) |sigs| {
                if (added.add(response_owner, types.RRSIG, rs.rtype)) {
                    for (sigs.rdata) |rd| {
                        try b.addRecord(section, response_owner, types.RRSIG, z.class, ttl, rd);
                    }
                }
            }
        }
    }

    fn addNegativeSoa(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        do: bool,
        qname_lower: []const u8,
        nxdomain: bool,
    ) !void {
        b.header.setAa(true);
        try self.addRRset(b, added, z, z.origin_wire, z.origin_wire, &z.soa, .authority, z.negative_ttl, do);
        if (do and z.isSigned()) {
            if (z.nsec3Params() != null) {
                try self.addNsec3Proof(b, added, z, qname_lower, nxdomain, do);
            } else {
                try self.addNsecProof(b, added, z, qname_lower, nxdomain, do);
            }
        }
    }

    fn addReferral(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        deleg: []const u8,
        do: bool,
    ) !void {
        b.header.setAa(false);
        const ns = z.rrsetAt(deleg, types.NS) orelse return;
        try self.addRRset(b, added, z, deleg, deleg, ns, .authority, null, false);
        for (ns.rdata) |rd| {
            var target: name.Name = undefined;
            _ = name.parseWire(rd, 0, &target) catch continue;
            name.lowerInPlace(target.buf[0..target.len]);
            try self.addGlue(b, added, z, target.slice());
        }
        if (do and z.isSigned()) {
            if (z.rrsetAt(deleg, types.DS)) |ds| {
                try self.addRRset(b, added, z, deleg, deleg, ds, .authority, null, do);
            } else if (z.nsec3Params()) |params| {
                if (params.opt_out) {
                    try self.addNsec3OptOutProof(b, added, z, deleg, do);
                } else {
                    try self.addNsec3Exact(b, added, z, deleg, do);
                }
            } else if (z.nsecAt(deleg)) |nsec| {
                try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
            } else if (z.nsecCovering(deleg)) |nsec| {
                try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
            }
        }
    }

    fn addGlue(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        target_lower: []const u8,
    ) !void {
        if (!isSubdomainWire(target_lower, z.origin_wire)) return;
        if (z.rrsetAt(target_lower, types.A)) |rs| {
            try self.addRRset(b, added, z, rs.owner, rs.owner, rs, .additional, null, false);
        }
        if (z.rrsetAt(target_lower, types.AAAA)) |rs| {
            try self.addRRset(b, added, z, rs.owner, rs.owner, rs, .additional, null, false);
        }
    }

    /// RFC 4035 section 3.1.3.3: a wildcard answer needs an NSEC proving that
    /// the QNAME itself does not exist.  Include the wildcard's own NSEC too,
    /// which proves the wildcard exists and carries the type bitmap.
    fn addWildcardProof(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        qname_lower: []const u8,
        wildcard: []const u8,
        do: bool,
    ) !void {
        if (z.nsec3Params() != null) {
            const ce = z.closestEncloser(qname_lower) orelse z.origin_wire;
            var ce_name = name.Name.init(ce) catch return;
            try self.addNsec3Exact(b, added, z, ce_name.slice(), do);
            if (nextCloserName(qname_lower, &ce_name)) |nc| {
                try self.addNsec3Covering(b, added, z, nc.slice(), do);
            }
            try self.addNsec3Exact(b, added, z, wildcard, do);
            return;
        }
        if (z.nsecAt(wildcard)) |nsec| {
            try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
        }
        if (z.nsecCovering(qname_lower)) |nsec| {
            try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
        }
    }

    fn hashOwner(z: *const zone.Zone, lookup_name: []const u8, out: *name.Name) ?[]const u8 {
        const params = z.nsec3Params() orelse return null;
        var h: [nsec3.hash_len]u8 = undefined;
        nsec3.hashName(lookup_name, params, &h) catch return null;
        return nsec3.makeOwner(&h, z.origin_wire, out) catch null;
    }

    fn addNsec3Exact(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        lookup_name: []const u8,
        do: bool,
    ) !void {
        var hn: name.Name = undefined;
        const owner = hashOwner(z, lookup_name, &hn) orelse return;
        if (z.nsec3At(owner)) |rs| {
            try self.addRRset(b, added, z, rs.owner, rs.owner, rs, .authority, null, do);
        }
    }

    fn addNsec3Covering(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        lookup_name: []const u8,
        do: bool,
    ) !void {
        var hn: name.Name = undefined;
        const owner = hashOwner(z, lookup_name, &hn) orelse return;
        if (z.nsec3Covering(owner)) |rs| {
            try self.addRRset(b, added, z, rs.owner, rs.owner, rs, .authority, null, do);
        }
    }

    /// RFC 5155 section 7.2.4: opt-out DS absence uses an opt-out covering
    /// NSEC3 plus the closest provable encloser.
    fn addNsec3OptOutProof(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        qname_lower: []const u8,
        do: bool,
    ) !void {
        try self.addNsec3Covering(b, added, z, qname_lower, do);
        var n = name.Name.init(qname_lower) catch return;
        while (n.parent()) |p| {
            n = p;
            var hn: name.Name = undefined;
            const owner = hashOwner(z, n.slice(), &hn) orelse continue;
            if (z.nsec3At(owner)) |rs| {
                try self.addRRset(b, added, z, rs.owner, rs.owner, rs, .authority, null, do);
                return;
            }
        }
    }

    /// RFC 5155 section 7.2 denial of existence.
    fn addNsec3Proof(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        qname_lower: []const u8,
        nxdomain: bool,
        do: bool,
    ) !void {
        const params = z.nsec3Params() orelse return;
        if (!nxdomain and params.opt_out and z.isDelegation(qname_lower) and
            z.rrsetAt(qname_lower, types.DS) == null)
        {
            try self.addNsec3OptOutProof(b, added, z, qname_lower, do);
            return;
        }

        var hn: name.Name = undefined;
        if (hashOwner(z, qname_lower, &hn)) |owner| {
            if (z.nsec3At(owner)) |rs| {
                try self.addRRset(b, added, z, rs.owner, rs.owner, rs, .authority, null, do);
                if (!nxdomain) return;
            }
        }

        const ce = z.closestEncloser(qname_lower) orelse z.origin_wire;
        var ce_name = name.Name.init(ce) catch return;
        try self.addNsec3Exact(b, added, z, ce_name.slice(), do);

        if (nextCloserName(qname_lower, &ce_name)) |nc| {
            try self.addNsec3Covering(b, added, z, nc.slice(), do);
        }

        if (nxdomain or !z.hasName(qname_lower)) {
            var wbuf: [name.max_name_len]u8 = undefined;
            if (zone.Zone.makeWildcard(ce_name.slice(), &wbuf)) |wildcard| {
                try self.addNsec3Covering(b, added, z, wildcard, do);
            }
        }
    }

    /// RFC 4035 denial of existence.  NODATA needs the NSEC at the name (or
    /// the covering NSEC for an empty non-terminal); NXDOMAIN needs a covering
    /// NSEC for the QNAME and another covering the wildcard at the closest
    /// encloser.
    fn addNsecProof(
        self: *const Responder,
        b: *message.Builder,
        added: *AddedSet,
        z: *const zone.Zone,
        qname_lower: []const u8,
        nxdomain: bool,
        do: bool,
    ) !void {
        if (z.nsecAt(qname_lower)) |nsec| {
            try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
        } else if (z.nsecCovering(qname_lower)) |nsec| {
            try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
        }
        const ce = z.closestEncloser(qname_lower) orelse z.origin_wire;
        var wbuf: [name.max_name_len]u8 = undefined;
        const wildcard = zone.Zone.makeWildcard(ce, &wbuf) orelse return;
        if (nxdomain) {
            if (z.nsecAt(wildcard)) |nsec| {
                try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
            } else if (z.nsecCovering(wildcard)) |nsec| {
                try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
            }
        } else if (!z.hasName(qname_lower)) {
            // NODATA at a wildcard-expanded name: the wildcard's own NSEC
            // proves that the requested type is absent (RFC 4035 3.1.3.4).
            if (z.nsecAt(wildcard)) |nsec| {
                try self.addRRset(b, added, z, nsec.owner, nsec.owner, nsec, .authority, null, do);
            }
        }
    }

    fn truncated(
        self: *const Responder,
        query: *const message.Message,
        buf: []u8,
        limit: usize,
        h: message.Header,
        opt_present: bool,
        do: bool,
    ) !Result {
        const q = query.question().?;
        const reserve: usize = if (opt_present) 11 else 0;
        var hh = h;
        hh.setTc(true);
        var b = try message.Builder.init(buf, hh, limit - @min(limit, reserve));
        try b.addQuestion(q.qname.slice(), q.qtype, q.qclass);
        if (opt_present) b.addOpt(self.opts.max_udp_size, 0, 0, if (do) edns.do_flag else 0, &.{}) catch {};
        return .{ .message = b.finish() };
    }

    fn errorResponse(
        self: *const Responder,
        query: *const message.Message,
        buf: []u8,
        limit: usize,
        rcode: types.Rcode,
        opt_present: bool,
        ext_rcode: u8,
    ) !Result {
        var h: message.Header = .{ .id = query.header.id };
        h.setQr(true);
        h.setOpcode(query.header.opcode());
        h.setRd(query.header.rd());
        h.setCd(query.header.cd());
        h.setRcode(@backingInt(rcode));
        const reserve: usize = if (opt_present) 11 else 0;
        var b = try message.Builder.init(buf, h, limit - @min(limit, reserve));
        if (query.question()) |q| try b.addQuestion(q.qname.slice(), q.qtype, q.qclass);
        if (opt_present) b.addOpt(self.opts.max_udp_size, ext_rcode, 0, 0, &.{}) catch {};
        return .{ .message = b.finish() };
    }
};

const AddedSet = struct {
    const Key = struct { owner: []const u8, rtype: u16, covered: u16 };
    items: [128]Key = undefined,
    len: usize = 0,

    fn add(s: *AddedSet, owner: []const u8, rtype: u16, covered: u16) bool {
        for (s.items[0..s.len]) |k| {
            if (k.rtype == rtype and k.covered == covered and name.eqlWireIgnoreCase(k.owner, owner)) return false;
        }
        if (s.len >= s.items.len) return false;
        s.items[s.len] = .{ .owner = owner, .rtype = rtype, .covered = covered };
        s.len += 1;
        return true;
    }
};

fn nextCloserName(qname: []const u8, ce: *const name.Name) ?name.Name {
    const q = name.Name.init(qname) catch return null;
    const ql = q.labelCount();
    const cl = ce.labelCount();
    if (ql <= cl) return null;
    const target: usize = ql - cl - 1;
    var i: usize = 0;
    var idx: usize = 0;
    while (i < q.len and q.buf[i] != 0) {
        if (idx == target) {
            const rest = q.len - i;
            var out: name.Name = .{ .len = @intCast(rest) };
            @memcpy(out.buf[0..rest], q.buf[i..][0..rest]);
            return out;
        }
        i += 1 + q.buf[i];
        idx += 1;
    }
    return null;
}

fn isSubdomainWire(q: []const u8, origin: []const u8) bool {
    if (origin.len > q.len) return false;
    return std.mem.eql(u8, q[q.len - origin.len ..], origin);
}

const testing_zone_src =
    \\$TTL 3600
    \\$ORIGIN example.com.
    \\@ IN SOA ns1.example.com. hostmaster.example.com. (
    \\  2024010101 1h 15m 1w 5m )
    \\  IN NS ns1
    \\  IN NS ns2.example.net.
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

fn testZone() !zone.Zone {
    return @import("../zone/sema.zig").loadSource(std.testing.allocator, std.testing.io, testing_zone_src, "test.zone", .{
        .origin = try name.parseText("example.com.", null),
    });
}

fn buildQuery(buf: []u8, id: u16, qname: []const u8, qtype: u16) ![]u8 {
    var h: message.Header = .{ .id = id };
    h.setRd(true);
    var b = try message.Builder.init(buf, h, buf.len);
    try b.addQuestion(qname, qtype, types.class_in);
    return b.finish();
}

fn parseQuery(allocator: std.mem.Allocator, buf: []u8, id: u16, qname: []const u8, qtype: u16) !message.Message {
    const wire = try buildQuery(buf, id, qname, qtype);
    return message.parse(allocator, wire);
}

test "authoritative A answer" {
    var z = try testZone();
    defer z.deinit();
    const zs = ZoneSet{ .zones = &.{&z} };
    const r = Responder{ .zones = &zs };
    var qbuf: [512]u8 = undefined;
    var q = try parseQuery(std.testing.allocator, &qbuf, 0x1234, "\x03www\x07example\x03com\x00", types.A);
    defer q.deinit(std.testing.allocator);
    var rbuf: [512]u8 = undefined;
    const res = try r.respond(&q, &rbuf, rbuf.len, false);
    const wire = res.message;
    var m = try message.parse(std.testing.allocator, wire);
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 0x1234), m.header.id);
    try std.testing.expect(m.header.aa());
    try std.testing.expectEqual(@as(usize, 1), m.answers.len);
    try std.testing.expectEqual(types.A, m.answers[0].rtype);
    try std.testing.expectEqual(@as(usize, 4), m.answers[0].rdata.len);
    try std.testing.expectEqual(@as(u8, 192), m.answers[0].rdata[0]);
}

test "nxdomain includes negative SOA" {
    var z = try testZone();
    defer z.deinit();
    const zs = ZoneSet{ .zones = &.{&z} };
    const r = Responder{ .zones = &zs };
    var qbuf: [512]u8 = undefined;
    var q = try parseQuery(std.testing.allocator, &qbuf, 7, "\x07missing\x07example\x03com\x00", types.A);
    defer q.deinit(std.testing.allocator);
    var rbuf: [512]u8 = undefined;
    const res = try r.respond(&q, &rbuf, rbuf.len, false);
    var m = try message.parse(std.testing.allocator, res.message);
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u4, 3), m.header.rcode());
    try std.testing.expect(m.header.aa());
    try std.testing.expectEqual(@as(usize, 1), m.authority.len);
    try std.testing.expectEqual(types.SOA, m.authority[0].rtype);
    try std.testing.expectEqual(@as(u32, 300), m.authority[0].ttl);
}

test "nodata includes SOA" {
    var z = try testZone();
    defer z.deinit();
    const zs = ZoneSet{ .zones = &.{&z} };
    const r = Responder{ .zones = &zs };
    var qbuf: [512]u8 = undefined;
    var q = try parseQuery(std.testing.allocator, &qbuf, 8, "\x03www\x07example\x03com\x00", types.MX);
    defer q.deinit(std.testing.allocator);
    var rbuf: [512]u8 = undefined;
    const res = try r.respond(&q, &rbuf, rbuf.len, false);
    var m = try message.parse(std.testing.allocator, res.message);
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u4, 0), m.header.rcode());
    try std.testing.expectEqual(@as(usize, 0), m.answers.len);
    try std.testing.expectEqual(types.SOA, m.authority[0].rtype);
}

test "wildcard synthesis" {
    var z = try testZone();
    defer z.deinit();
    const zs = ZoneSet{ .zones = &.{&z} };
    const r = Responder{ .zones = &zs };
    var qbuf: [512]u8 = undefined;
    var q = try parseQuery(std.testing.allocator, &qbuf, 9, "\x01x\x04wild\x07example\x03com\x00", types.A);
    defer q.deinit(std.testing.allocator);
    var rbuf: [512]u8 = undefined;
    const res = try r.respond(&q, &rbuf, rbuf.len, false);
    var m = try message.parse(std.testing.allocator, res.message);
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u4, 0), m.header.rcode());
    try std.testing.expectEqual(@as(usize, 1), m.answers.len);
    try std.testing.expect(m.answers[0].owner.eqlIgnoreCase(&q.questions[0].qname));
    try std.testing.expectEqual(@as(u8, 99), m.answers[0].rdata[3]);
}

test "referral has NS and glue, AA clear" {
    var z = try testZone();
    defer z.deinit();
    const zs = ZoneSet{ .zones = &.{&z} };
    const r = Responder{ .zones = &zs };
    var qbuf: [512]u8 = undefined;
    var q = try parseQuery(std.testing.allocator, &qbuf, 10, "\x01x\x03sub\x07example\x03com\x00", types.A);
    defer q.deinit(std.testing.allocator);
    var rbuf: [512]u8 = undefined;
    const res = try r.respond(&q, &rbuf, rbuf.len, false);
    var m = try message.parse(std.testing.allocator, res.message);
    defer m.deinit(std.testing.allocator);
    try std.testing.expect(!m.header.aa());
    try std.testing.expectEqual(@as(usize, 0), m.answers.len);
    try std.testing.expectEqual(types.NS, m.authority[0].rtype);
    var found_glue = false;
    for (m.additional) |rr| {
        if (rr.rtype == types.A) found_glue = true;
    }
    try std.testing.expect(found_glue);
}

test "cname chain in zone" {
    var z = try testZone();
    defer z.deinit();
    const zs = ZoneSet{ .zones = &.{&z} };
    const r = Responder{ .zones = &zs };
    var qbuf: [512]u8 = undefined;
    var q = try parseQuery(std.testing.allocator, &qbuf, 11, "\x05alias\x07example\x03com\x00", types.A);
    defer q.deinit(std.testing.allocator);
    var rbuf: [512]u8 = undefined;
    const res = try r.respond(&q, &rbuf, rbuf.len, false);
    var m = try message.parse(std.testing.allocator, res.message);
    defer m.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), m.answers.len);
    try std.testing.expectEqual(types.CNAME, m.answers[0].rtype);
    try std.testing.expectEqual(types.A, m.answers[1].rtype);
}

test "edns opt is echoed and DO accepted" {
    var z = try testZone();
    defer z.deinit();
    const zs = ZoneSet{ .zones = &.{&z} };
    const r = Responder{ .zones = &zs };
    var qbuf: [512]u8 = undefined;
    const h: message.Header = .{ .id = 12 };
    var b = try message.Builder.init(&qbuf, h, qbuf.len);
    try b.addQuestion("\x03www\x07example\x03com\x00", types.A, types.class_in);
    try b.addOpt(1232, 0, 0, edns.do_flag, &.{});
    var q = try message.parse(std.testing.allocator, b.finish());
    defer q.deinit(std.testing.allocator);
    var rbuf: [512]u8 = undefined;
    const res = try r.respond(&q, &rbuf, rbuf.len, false);
    var m = try message.parse(std.testing.allocator, res.message);
    defer m.deinit(std.testing.allocator);
    const opt = m.opt().?;
    try std.testing.expectEqual(@as(u16, 1232), opt.class);
    try std.testing.expect(opt.ttl & 0x8000 != 0);
}
