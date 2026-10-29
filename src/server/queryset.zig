//! A set of loaded zones with longest-suffix matching.

const std = @import("std");
const name = @import("../dns/name.zig");
const zone = @import("../zone/zone.zig");

pub const ZoneSet = struct {
    zones: []const *const zone.Zone,

    pub fn find(zs: *const ZoneSet, qname_lower: []const u8) ?*const zone.Zone {
        var best: ?*const zone.Zone = null;
        var best_len: usize = 0;
        for (zs.zones) |z| {
            const origin = z.origin_wire;
            if (origin.len > qname_lower.len) continue;
            if (!std.mem.eql(u8, qname_lower[qname_lower.len - origin.len ..], origin)) continue;
            if (origin.len > best_len) {
                best = z;
                best_len = origin.len;
            }
        }
        return best;
    }
};
