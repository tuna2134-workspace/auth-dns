//! auth-dns: an authoritative DNS server written in Zig.
//!
//! The public module is intentionally small; the individual subsystems are
//! re-exported for tests and for embedding.

pub const version = @import("version.zig").version;
pub const name = @import("dns/name.zig");
pub const types = @import("dns/types.zig");
pub const text = @import("dns/text.zig");
pub const rdata = @import("dns/rdata.zig");
pub const message = @import("dns/message.zig");
pub const edns = @import("dns/edns.zig");
pub const tsig = @import("dns/tsig.zig");
pub const lexer = @import("zone/lexer.zig");
pub const ast = @import("zone/ast.zig");
pub const parser = @import("zone/parser.zig");
pub const zone = @import("zone/zone.zig");
pub const sema = @import("zone/sema.zig");
pub const journal = @import("zone/journal.zig");
pub const transfer = @import("zone/transfer.zig");
pub const openssl = @import("dnssec/openssl.zig");
pub const dnssec_sign = @import("dnssec/sign.zig");
pub const queryset = @import("server/queryset.zig");
pub const query = @import("server/query.zig");
pub const acl = @import("server/acl.zig");
pub const server = @import("server/server.zig");
pub const config = @import("server/config.zig");

test {
    _ = name;
    _ = types;
    _ = text;
    _ = rdata;
    _ = message;
    _ = edns;
    _ = tsig;
    _ = lexer;
    _ = ast;
    _ = parser;
    _ = zone;
    _ = sema;
    _ = journal;
    _ = transfer;
    _ = openssl;
    _ = dnssec_sign;
    _ = queryset;
    _ = query;
    _ = acl;
    _ = server;
    _ = config;
}
