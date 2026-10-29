//! Simple per-source token bucket for query rate limiting.
//!
//! This is a coarse protection, not RRL: it limits requests per client
//! address before parsing.  Entries are capped and cleared wholesale when the
//! table grows too large, which keeps memory bounded under spoofed-source
//! floods.

const std = @import("std");
const Io = std.Io;

pub const Key = struct {
    bytes: [16]u8 = std.mem.zeroes([16]u8),
    len: u8 = 0,

    pub fn from(addr: Io.net.IpAddress) Key {
        switch (addr) {
            .ip4 => |a| {
                var k: Key = .{ .len = 4 };
                @memcpy(k.bytes[0..4], &a.bytes);
                return k;
            },
            .ip6 => |a| {
                var k: Key = .{ .len = 16 };
                @memcpy(&k.bytes, &a.bytes);
                return k;
            },
        }
    }
};

const Bucket = struct {
    tokens: f64,
    last_ms: u64,
};

pub const Limiter = struct {
    lock: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    buckets: std.AutoHashMapUnmanaged(Key, Bucket) = .{},
    qps: f64 = 0,
    burst: f64 = 0,
    max_entries: usize = 4096,

    pub fn init(qps: u32, burst: u32) Limiter {
        return .{
            .qps = @floatFromInt(qps),
            .burst = @floatFromInt(if (burst == 0) qps else burst),
        };
    }

    pub fn deinit(l: *Limiter, allocator: std.mem.Allocator) void {
        l.buckets.deinit(allocator);
    }

    pub fn enabled(l: *const Limiter) bool {
        return l.qps > 0;
    }

    fn acquire(l: *Limiter) void {
        while (l.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn release(l: *Limiter) void {
        l.lock.store(false, .release);
    }

    pub fn allow(l: *Limiter, allocator: std.mem.Allocator, addr: Io.net.IpAddress) bool {
        if (l.qps <= 0) return true;
        const now = nowMs();
        l.acquire();
        defer l.release();

        if (l.buckets.count() > l.max_entries) {
            l.buckets.clearRetainingCapacity();
        }
        const gop = l.buckets.getOrPut(allocator, Key.from(addr)) catch return true;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .tokens = l.burst, .last_ms = now };
        } else {
            const elapsed_ms = now -| gop.value_ptr.last_ms;
            if (elapsed_ms > 0) {
                const add = (@as(f64, @floatFromInt(elapsed_ms)) / 1000.0) * l.qps;
                gop.value_ptr.tokens = @min(l.burst, gop.value_ptr.tokens + add);
                gop.value_ptr.last_ms = now;
            }
        }
        if (gop.value_ptr.tokens < 1.0) return false;
        gop.value_ptr.tokens -= 1.0;
        return true;
    }
};

fn nowMs() u64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts) != 0) return 0;
    return @as(u64, @intCast(@max(ts.sec, 0))) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
}

test "token bucket" {
    var l = Limiter.init(10, 2);
    defer l.deinit(std.testing.allocator);
    const a = try Io.net.IpAddress.parse("192.0.2.1", 53);
    try std.testing.expect(l.allow(std.testing.allocator, a));
    try std.testing.expect(l.allow(std.testing.allocator, a));
    try std.testing.expect(!l.allow(std.testing.allocator, a));
}
