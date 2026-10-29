//! Zone file abstract syntax tree.
//!
//! The parser performs no name resolution and no TTL interpretation: it only
//! recognises record structure and directives.  The semantic analyser
//! (`sema.zig`) owns $ORIGIN/$TTL state, resolves relative names and converts
//! RDATA tokens to wire format.  This mirrors the lexer -> parser -> semantic
//! analysis pipeline of a conventional compiler.

const std = @import("std");
const text = @import("../dns/text.zig");

pub const Record = struct {
    /// null when the line began with whitespace and the owner is inherited
    /// from the previous record (RFC 1035 section 5.1).
    owner: ?text.Token,
    ttl: ?text.Token,
    class: ?text.Token,
    rtype: text.Token,
    rdata: []const text.Token,
    line: u32,
};

pub const Node = union(enum) {
    record: Record,
    origin: struct {
        value: text.Token,
        line: u32,
    },
    ttl: struct {
        value: text.Token,
        line: u32,
    },
    include: struct {
        path: text.Token,
        /// Optional origin for the included file; if null the current origin
        /// is inherited.
        origin: ?text.Token,
        line: u32,
    },
};

pub const Ast = struct {
    nodes: []Node,
    source_name: []const u8,
    source: []const u8,

    pub fn deinit(a: *Ast, allocator: std.mem.Allocator) void {
        allocator.free(a.nodes);
        allocator.free(a.source_name);
    }
};

test "ast node layout" {
    const n: Node = .{ .origin = .{ .value = .{ .text = "example.com." }, .line = 1 } };
    try std.testing.expect(n == .origin);
}
