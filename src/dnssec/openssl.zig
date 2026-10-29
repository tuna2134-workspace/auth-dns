//! Minimal OpenSSL 3 libcrypto binding used for DNSSEC and TSIG.
//!
//! We deliberately bind only libcrypto, not libssl: an authoritative DNS
//! server needs HMAC, hashes and public-key signing.  libssl is only relevant
//! if DNS-over-TLS is added.  The declarations are hand-written because Zig
//! 0.17 removed `@cImport`; they cover exactly the stable OpenSSL 3 ABI.
//!
//! Supported DNSSEC algorithms:
//!   8  RSASHA256
//!   13 ECDSAP256SHA256
//!   14 ECDSAP384SHA384
//!   15 ED25519

const std = @import("std");

const EVP_PKEY = opaque {};
const EVP_MD = opaque {};
const EVP_MD_CTX = opaque {};
const EVP_PKEY_CTX = opaque {};
const BIO = opaque {};
const BIO_METHOD = opaque {};
const ECDSA_SIG = opaque {};
const BIGNUM = opaque {};

extern fn OpenSSL_version(t: c_int) [*:0]const u8;
extern fn EVP_sha1() ?*const EVP_MD;
extern fn EVP_sha256() ?*const EVP_MD;
extern fn EVP_sha384() ?*const EVP_MD;
extern fn EVP_sha512() ?*const EVP_MD;
extern fn EVP_Digest(data: ?*const anyopaque, count: usize, md: ?[*]u8, size: ?*c_uint, md_type: ?*const EVP_MD, impl: ?*anyopaque) c_int;
extern fn HMAC(md: ?*const EVP_MD, key: ?*const anyopaque, key_len: c_int, data: ?*const anyopaque, data_len: usize, md_out: ?[*]u8, out_len: ?*c_uint) ?[*]u8;

extern fn BIO_new_mem_buf(buf: ?*const anyopaque, len: c_int) ?*BIO;
extern fn BIO_new(type: ?*const BIO_METHOD) ?*BIO;
extern fn BIO_s_mem() ?*const BIO_METHOD;
extern fn BIO_free(bio: ?*BIO) c_int;
extern fn BIO_ctrl(bio: *BIO, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
extern fn PEM_read_bio_PrivateKey(bio: *BIO, x: ?*?*EVP_PKEY, cb: ?*anyopaque, u: ?*anyopaque) ?*EVP_PKEY;
extern fn PEM_write_bio_PrivateKey(bio: *BIO, key: *EVP_PKEY, enc: ?*anyopaque, kstr: ?[*]u8, klen: c_int, cb: ?*anyopaque, u: ?*anyopaque) c_int;
extern fn EVP_PKEY_CTX_new_id(id: c_int, engine: ?*anyopaque) ?*EVP_PKEY_CTX;
extern fn EVP_PKEY_CTX_free(ctx: ?*EVP_PKEY_CTX) void;
extern fn EVP_PKEY_keygen_init(ctx: *EVP_PKEY_CTX) c_int;
extern fn EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: *EVP_PKEY_CTX, nid: c_int) c_int;
extern fn EVP_PKEY_keygen(ctx: *EVP_PKEY_CTX, ppkey: *?*EVP_PKEY) c_int;
extern fn EVP_PKEY_free(key: ?*EVP_PKEY) void;
extern fn EVP_PKEY_is_a(key: *const EVP_PKEY, name: [*:0]const u8) c_int;
extern fn EVP_PKEY_get_bits(key: *const EVP_PKEY) c_int;
extern fn EVP_PKEY_get_octet_string_param(key: *const EVP_PKEY, param: [*:0]const u8, buf: ?[*]u8, max_len: usize, out_len: *usize) c_int;
extern fn EVP_PKEY_get_raw_public_key(key: *const EVP_PKEY, out_pub: ?[*]u8, len: *usize) c_int;
extern fn EVP_PKEY_get_bn_param(key: *const EVP_PKEY, param: [*:0]const u8, bn: *?*BIGNUM) c_int;

extern fn EVP_MD_CTX_new() ?*EVP_MD_CTX;
extern fn EVP_MD_CTX_free(ctx: ?*EVP_MD_CTX) void;
extern fn EVP_DigestSignInit(ctx: *EVP_MD_CTX, pctx: ?*?*EVP_PKEY_CTX, md: ?*const EVP_MD, engine: ?*anyopaque, key: *EVP_PKEY) c_int;
extern fn EVP_DigestSign(ctx: *EVP_MD_CTX, sig: ?[*]u8, sig_len: *usize, tbs: ?*const anyopaque, tbs_len: usize) c_int;

extern fn d2i_ECDSA_SIG(sig: ?*?*ECDSA_SIG, in: *[*]const u8, len: c_long) ?*ECDSA_SIG;
extern fn ECDSA_SIG_get0(sig: *const ECDSA_SIG, pr: ?*?*const BIGNUM, ps: ?*?*const BIGNUM) void;
extern fn ECDSA_SIG_free(sig: ?*ECDSA_SIG) void;
extern fn BN_num_bits(bn: *const BIGNUM) c_int;
extern fn BN_bn2binpad(bn: *const BIGNUM, to: [*]u8, to_len: c_int) c_int;
extern fn BN_free(bn: ?*BIGNUM) void;

pub const Error = error{
    OpenSsl,
    BadPem,
    UnsupportedKey,
    SignatureFailed,
    KeyTooLarge,
} || std.mem.Allocator.Error;

pub const Algorithm = enum(u8) {
    rsasha256 = 8,
    ecdsap256sha256 = 13,
    ecdsap384sha384 = 14,
    ed25519 = 15,
};

pub fn version() []const u8 {
    return std.mem.span(OpenSSL_version(0));
}

/// OpenSSL object identifiers used for P-256 key generation.
const EVP_PKEY_EC: c_int = 408;
const NID_X9_62_prime256v1: c_int = 415;

/// Generates a fresh P-256 private key and returns it as PEM (PKCS#8).
/// Only libcrypto is used; no external `openssl` process is required.
pub fn generateP256Pem(allocator: std.mem.Allocator) Error![]u8 {
    const ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null) orelse return error.OpenSsl;
    defer EVP_PKEY_CTX_free(ctx);
    if (EVP_PKEY_keygen_init(ctx) <= 0) return error.OpenSsl;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) return error.OpenSsl;
    var pkey: ?*EVP_PKEY = null;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) return error.OpenSsl;
    defer EVP_PKEY_free(pkey);

    const bio = BIO_new(BIO_s_mem()) orelse return error.OpenSsl;
    defer _ = BIO_free(bio);
    if (PEM_write_bio_PrivateKey(bio, pkey.?, null, null, 0, null, null) != 1) return error.OpenSsl;
    var ptr: [*]u8 = undefined;
    // BIO_CTRL_INFO (3) returns the memory BIO's buffer and length.
    const len = BIO_ctrl(bio, 3, 0, @ptrCast(&ptr));
    if (len <= 0) return error.OpenSsl;
    return allocator.dupe(u8, ptr[0..@intCast(len)]);
}

pub fn digestSha256(data: []const u8, out: *[32]u8) Error!void {
    var len: c_uint = 0;
    if (EVP_Digest(data.ptr, data.len, out, &len, EVP_sha256(), null) != 1 or len != 32) return error.OpenSsl;
}

pub fn digestSha1(data: []const u8, out: *[20]u8) Error!void {
    var len: c_uint = 0;
    if (EVP_Digest(data.ptr, data.len, out, &len, EVP_sha1(), null) != 1 or len != 20) return error.OpenSsl;
}

pub fn digestSha384(data: []const u8, out: *[48]u8) Error!void {
    var len: c_uint = 0;
    if (EVP_Digest(data.ptr, data.len, out, &len, EVP_sha384(), null) != 1 or len != 48) return error.OpenSsl;
}

/// Computes HMAC with the named TSIG algorithm.  The output buffer must have
/// room for at least 64 bytes; the actual length is returned.
pub fn hmac(algorithm: []const u8, key: []const u8, data: []const u8, out: []u8) Error!usize {
    const md: ?*const EVP_MD =
        if (std.ascii.eqlIgnoreCase(algorithm, "hmac-sha1") or std.ascii.eqlIgnoreCase(algorithm, "hmac-sha1."))
            EVP_sha1()
        else if (std.ascii.eqlIgnoreCase(algorithm, "hmac-sha256") or std.ascii.eqlIgnoreCase(algorithm, "hmac-sha256."))
            EVP_sha256()
        else if (std.ascii.eqlIgnoreCase(algorithm, "hmac-sha384") or std.ascii.eqlIgnoreCase(algorithm, "hmac-sha384."))
            EVP_sha384()
        else if (std.ascii.eqlIgnoreCase(algorithm, "hmac-sha512") or std.ascii.eqlIgnoreCase(algorithm, "hmac-sha512."))
            EVP_sha512()
        else
            return error.UnsupportedKey;
    if (key.len > std.math.maxInt(c_int)) return error.KeyTooLarge;
    var len: c_uint = 0;
    const r = HMAC(md, key.ptr, @intCast(key.len), data.ptr, data.len, out.ptr, &len);
    if (r == null) return error.OpenSsl;
    return len;
}

pub const Key = struct {
    pkey: *EVP_PKEY,
    algorithm: Algorithm,
    bits: u16,
    /// DNSKEY public-key field (without flags/protocol/algorithm).
    public_key: []u8,

    pub fn deinit(self: *Key, allocator: std.mem.Allocator) void {
        EVP_PKEY_free(self.pkey);
        allocator.free(self.public_key);
        self.* = undefined;
    }

    /// Loads a PEM private key (PKCS#8, traditional EC/RSA, or OpenSSH-style
    /// PEM accepted by OpenSSL).
    pub fn loadPem(allocator: std.mem.Allocator, pem: []const u8) Error!Key {
        if (pem.len > std.math.maxInt(c_int)) return error.KeyTooLarge;
        const bio = BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return error.OpenSsl;
        defer _ = BIO_free(bio);
        const pkey = PEM_read_bio_PrivateKey(bio, null, null, null) orelse return error.BadPem;
        errdefer EVP_PKEY_free(pkey);

        var algorithm: Algorithm = undefined;
        var bits: u16 = 0;
        var public_key: []u8 = undefined;

        if (EVP_PKEY_is_a(pkey, "EC") == 1) {
            const b = EVP_PKEY_get_bits(pkey);
            if (b == 256) {
                algorithm = .ecdsap256sha256;
            } else if (b == 384) {
                algorithm = .ecdsap384sha384;
            } else {
                return error.UnsupportedKey;
            }
            bits = @intCast(b);
            var point_len: usize = 0;
            if (EVP_PKEY_get_octet_string_param(pkey, "pub", null, 0, &point_len) != 1) return error.OpenSsl;
            const point = try allocator.alloc(u8, point_len);
            defer allocator.free(point);
            if (EVP_PKEY_get_octet_string_param(pkey, "pub", point.ptr, point.len, &point_len) != 1) return error.OpenSsl;
            if (point_len < 3 or point[0] != 0x04) return error.UnsupportedKey;
            public_key = try allocator.dupe(u8, point[1..point_len]);
        } else if (EVP_PKEY_is_a(pkey, "ED25519") == 1) {
            algorithm = .ed25519;
            bits = 256;
            var n: usize = 0;
            if (EVP_PKEY_get_raw_public_key(pkey, null, &n) != 1 or n != 32) return error.UnsupportedKey;
            public_key = try allocator.alloc(u8, 32);
            errdefer allocator.free(public_key);
            if (EVP_PKEY_get_raw_public_key(pkey, public_key.ptr, &n) != 1 or n != 32) return error.UnsupportedKey;
        } else if (EVP_PKEY_is_a(pkey, "RSA") == 1) {
            algorithm = .rsasha256;
            const b = EVP_PKEY_get_bits(pkey);
            if (b < 1024) return error.UnsupportedKey;
            bits = @intCast(b);
            var n_bn: ?*BIGNUM = null;
            var e_bn: ?*BIGNUM = null;
            if (EVP_PKEY_get_bn_param(pkey, "n", &n_bn) != 1) return error.OpenSsl;
            defer BN_free(n_bn);
            if (EVP_PKEY_get_bn_param(pkey, "e", &e_bn) != 1) return error.OpenSsl;
            defer BN_free(e_bn);
            const n_bytes = @divTrunc(@as(usize, @intCast(BN_num_bits(n_bn.?))) + 7, 8);
            const e_bytes = @divTrunc(@as(usize, @intCast(BN_num_bits(e_bn.?))) + 7, 8);
            if (n_bytes > 4096 or e_bytes > 512) return error.UnsupportedKey;
            const exp_prefix: usize = if (e_bytes < 256) 1 else 3;
            public_key = try allocator.alloc(u8, exp_prefix + e_bytes + n_bytes);
            errdefer allocator.free(public_key);
            if (e_bytes < 256) {
                public_key[0] = @intCast(e_bytes);
            } else {
                public_key[0] = 0;
                public_key[1] = @intCast(e_bytes >> 8);
                public_key[2] = @intCast(e_bytes & 0xff);
            }
            if (BN_bn2binpad(e_bn.?, public_key.ptr + exp_prefix, @intCast(e_bytes)) <= 0) return error.OpenSsl;
            if (BN_bn2binpad(n_bn.?, public_key.ptr + exp_prefix + e_bytes, @intCast(n_bytes)) <= 0) return error.OpenSsl;
        } else {
            return error.UnsupportedKey;
        }

        return .{ .pkey = pkey, .algorithm = algorithm, .bits = bits, .public_key = public_key };
    }

    pub fn algorithmNumber(self: *const Key) u8 {
        return @backingInt(self.algorithm);
    }

    pub fn publicKey(self: *const Key) []const u8 {
        return self.public_key;
    }

    /// Signs `data` and returns the DNSSEC signature encoding.
    /// ECDSA signatures are converted from DER to the fixed-width r||s form
    /// required by RFC 6605; Ed25519 is already raw; RSA is PKCS#1 v1.5.
    pub fn sign(self: *const Key, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        var buf: [1024]u8 = undefined;
        const n = try self.signInto(data, &buf);
        return allocator.dupe(u8, buf[0..n]);
    }

    pub fn signInto(self: *const Key, data: []const u8, out: []u8) !usize {
        const md: ?*const EVP_MD = switch (self.algorithm) {
            .rsasha256 => EVP_sha256(),
            .ecdsap256sha256 => EVP_sha256(),
            .ecdsap384sha384 => EVP_sha384(),
            .ed25519 => null,
        };
        const ctx = EVP_MD_CTX_new() orelse return error.OpenSsl;
        defer EVP_MD_CTX_free(ctx);
        if (EVP_DigestSignInit(ctx, null, md, null, self.pkey) != 1) return error.OpenSsl;

        var der: [1024]u8 = undefined;
        var der_len: usize = der.len;
        if (EVP_DigestSign(ctx, &der, &der_len, data.ptr, data.len) != 1) return error.SignatureFailed;

        switch (self.algorithm) {
            .ecdsap256sha256, .ecdsap384sha384 => {
                const coord: usize = if (self.algorithm == .ecdsap256sha256) 32 else 48;
                if (out.len < coord * 2) return error.SignatureFailed;
                var p: [*]const u8 = @ptrCast(&der);
                const sig = d2i_ECDSA_SIG(null, &p, @intCast(der_len)) orelse return error.SignatureFailed;
                defer ECDSA_SIG_free(sig);
                var r: ?*const BIGNUM = null;
                var s: ?*const BIGNUM = null;
                ECDSA_SIG_get0(sig, &r, &s);
                if (r == null or s == null) return error.SignatureFailed;
                if (BN_bn2binpad(r.?, out.ptr, @intCast(coord)) <= 0) return error.SignatureFailed;
                if (BN_bn2binpad(s.?, out.ptr + coord, @intCast(coord)) <= 0) return error.SignatureFailed;
                return coord * 2;
            },
            .ed25519 => {
                if (der_len != 64 or out.len < 64) return error.SignatureFailed;
                @memcpy(out[0..64], der[0..64]);
                return 64;
            },
            .rsasha256 => {
                if (out.len < der_len) return error.SignatureFailed;
                @memcpy(out[0..der_len], der[0..der_len]);
                return der_len;
            },
        }
    }
};

/// Builds DNSKEY RDATA: flags (16), protocol (8, always 3), algorithm (8),
/// public key.
pub fn dnskeyRdata(allocator: std.mem.Allocator, flags: u16, key: *const Key) ![]u8 {
    const out = try allocator.alloc(u8, 4 + key.public_key.len);
    out[0] = @intCast(flags >> 8);
    out[1] = @intCast(flags & 0xff);
    out[2] = 3;
    out[3] = key.algorithmNumber();
    @memcpy(out[4..], key.public_key);
    return out;
}

/// RFC 4034 Appendix B key tag.
pub fn keyTag(dnskey_rdata: []const u8) u16 {
    var ac: u32 = 0;
    for (dnskey_rdata, 0..) |b, i| {
        ac += if (i & 1 == 0) @as(u32, b) << 8 else b;
    }
    ac += (ac >> 16) & 0xffff;
    return @intCast(ac & 0xffff);
}

/// Builds a DS RDATA with digest type 2 (SHA-256).  `owner` is the canonical
/// wire-format owner name (lowercase, uncompressed).
pub fn dsRdata(allocator: std.mem.Allocator, owner: []const u8, dnskey_rdata: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    const input = try allocator.alloc(u8, owner.len + dnskey_rdata.len);
    defer allocator.free(input);
    @memcpy(input[0..owner.len], owner);
    @memcpy(input[owner.len..], dnskey_rdata);
    try digestSha256(input, &digest);
    const out = try allocator.alloc(u8, 4 + 32);
    const tag = keyTag(dnskey_rdata);
    out[0] = @intCast(tag >> 8);
    out[1] = @intCast(tag & 0xff);
    out[2] = dnskey_rdata[3]; // algorithm
    out[3] = 2; // SHA-256
    @memcpy(out[4..], &digest);
    return out;
}

test "OpenSSL loads keys and signs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    inline for (.{ "testdata/test-ecdsa.pem", "testdata/test-ed25519.pem", "testdata/test-rsa.pem" }) |path| {
        const pem = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20));
        defer allocator.free(pem);
        var key = try Key.loadPem(allocator, pem);
        defer key.deinit(allocator);
        try std.testing.expect(key.public_key.len > 0);
        var sig_buf: [1024]u8 = undefined;
        const n = try key.signInto("hello dnssec", &sig_buf);
        try std.testing.expect(n > 0);
        const dnskey = try dnskeyRdata(allocator, 257, &key);
        defer allocator.free(dnskey);
        _ = keyTag(dnskey);
        const ds = try dsRdata(allocator, "\x07example\x03com\x00", dnskey);
        defer allocator.free(ds);
        try std.testing.expectEqual(@as(usize, 36), ds.len);
    }
}
