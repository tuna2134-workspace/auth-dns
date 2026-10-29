//! Lexer for BIND9 master files (RFC 1035 section 5 plus the common BIND
//! extensions used in real zone files).
//!
//! The lexer is intentionally context-free: it emits words, quoted strings and
//! logical newlines.  Parenthesised continuations are folded here, so the
//! parser always sees one logical record per line.  Escapes are preserved
//! verbatim because names (`\.`) and character-strings (`\DDD`) interpret them
//! differently.

const std = @import("std");

pub const Kind = enum {
    word,
    quoted,
    newline,
    eof,
};

pub const Token = struct {
    kind: Kind,
    text: []const u8,
    line: u32,
    column: u32,
    /// True when this is the first token of a logical line and the line began
    /// with whitespace.  RFC 1035 section 5.1: such a line omits the owner.
    leading_ws: bool = false,
};

pub const Error = error{
    UnterminatedQuote,
    UnbalancedParen,
    UnexpectedRParen,
    UnexpectedEndOfFile,
};

pub const Lexer = struct {
    src: []const u8,
    pos: usize = 0,
    line: u32 = 1,
    column: u32 = 1,
    paren_depth: u32 = 0,
    at_line_start: bool = true,
    saw_indent: bool = false,
    pending_newline: bool = false,
    pending_line: u32 = 1,

    pub fn init(src: []const u8) Lexer {
        return .{ .src = src };
    }

    fn peek(l: *const Lexer) ?u8 {
        if (l.pos >= l.src.len) return null;
        return l.src[l.pos];
    }

    fn advance(l: *Lexer) void {
        if (l.pos >= l.src.len) return;
        if (l.src[l.pos] == '\n') {
            l.line += 1;
            l.column = 1;
        } else {
            l.column += 1;
        }
        l.pos += 1;
    }

    fn skipSpaces(l: *Lexer) void {
        while (l.peek()) |c| {
            switch (c) {
                ' ', '\t', '\r' => {
                    if (l.at_line_start) l.saw_indent = true;
                    l.advance();
                },
                else => return,
            }
        }
    }

    pub fn next(l: *Lexer) Error!Token {
        if (l.pending_newline) {
            l.pending_newline = false;
            l.at_line_start = true;
            l.saw_indent = false;
            return .{ .kind = .newline, .text = "", .line = l.pending_line, .column = 1 };
        }
        while (true) {
            l.skipSpaces();
            const c = l.peek() orelse {
                if (l.paren_depth != 0) return error.UnbalancedParen;
                return .{ .kind = .eof, .text = "", .line = l.line, .column = l.column };
            };
            switch (c) {
                '\n' => {
                    const line = l.line;
                    l.advance();
                    if (l.paren_depth != 0) {
                        // Newlines inside parentheses are just whitespace.
                        l.saw_indent = true;
                        continue;
                    }
                    l.at_line_start = true;
                    l.saw_indent = false;
                    return .{ .kind = .newline, .text = "", .line = line, .column = 1 };
                },
                ';' => {
                    while (l.peek()) |x| {
                        if (x == '\n') break;
                        l.advance();
                    }
                },
                '(' => {
                    l.paren_depth += 1;
                    l.advance();
                },
                ')' => {
                    if (l.paren_depth == 0) return error.UnexpectedRParen;
                    l.paren_depth -= 1;
                    l.advance();
                },
                '"' => return l.lexQuoted(),
                else => return l.lexWord(),
            }
        }
    }

    fn lexQuoted(l: *Lexer) Error!Token {
        const line = l.line;
        const col = l.column;
        const leading = l.at_line_start and l.saw_indent;
        l.advance(); // opening quote
        const start = l.pos;
        var end = start;
        while (true) {
            const c = l.peek() orelse {
                l.pending_newline = false;
                return error.UnterminatedQuote;
            };
            if (c == '"') {
                end = l.pos;
                l.advance();
                break;
            }
            if (c == '\n') return error.UnterminatedQuote;
            if (c == '\\') {
                l.advance();
                if (l.peek() == null) return error.UnterminatedQuote;
                l.advance();
                continue;
            }
            l.advance();
        }
        l.at_line_start = false;
        l.saw_indent = false;
        return .{ .kind = .quoted, .text = l.src[start..end], .line = line, .column = col, .leading_ws = leading };
    }

    fn lexWord(l: *Lexer) Token {
        const line = l.line;
        const col = l.column;
        const leading = l.at_line_start and l.saw_indent;
        const start = l.pos;
        while (l.peek()) |c| {
            switch (c) {
                ' ', '\t', '\r', '\n', ';', '(', ')', '"' => break,
                '\\' => {
                    l.advance();
                    const e = l.peek() orelse break;
                    if (e == '\n') {
                        // Backslash-newline is a line continuation.
                        l.advance();
                        continue;
                    }
                    l.advance();
                    if (e >= '0' and e <= '9') {
                        // Consume up to two more decimal digits so \DDD stays
                        // inside the token even if the third digit is a
                        // delimiter.
                        var n: usize = 1;
                        while (n < 3) : (n += 1) {
                            const d = l.peek() orelse break;
                            if (d < '0' or d > '9') break;
                            l.advance();
                        }
                    }
                },
                else => l.advance(),
            }
        }
        l.at_line_start = false;
        l.saw_indent = false;
        return .{ .kind = .word, .text = l.src[start..l.pos], .line = line, .column = col, .leading_ws = leading };
    }
};

pub const Iterator = struct {
    lexer: Lexer,

    pub fn init(src: []const u8) Iterator {
        return .{ .lexer = Lexer.init(src) };
    }

    pub fn next(it: *Iterator) Error!Token {
        return it.lexer.next();
    }
};

test "tokenizes records, comments and quotes" {
    const src =
        \\$TTL 3600
        \\@ IN SOA ns1.example.com. admin.example.com. (
        \\  2024010101 ; serial
        \\  1h 15m 1w 5m )
        \\www 300 IN A 192.0.2.1
        \\    IN TXT "hello world" ; trailing
        \\mail IN MX 10 "mail server"
        \\
    ;
    var it = Iterator.init(src);
    var toks: std.ArrayList(Token) = .empty;
    defer toks.deinit(std.testing.allocator);
    while (true) {
        const t = try it.next();
        try toks.append(std.testing.allocator, t);
        if (t.kind == .eof) break;
    }
    var words: usize = 0;
    var newlines: usize = 0;
    var quoted: usize = 0;
    for (toks.items) |t| {
        switch (t.kind) {
            .word => words += 1,
            .quoted => quoted += 1,
            .newline => newlines += 1,
            .eof => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 2), quoted);
    try std.testing.expect(newlines >= 4);
    try std.testing.expect(words >= 20);
}

test "owner omission marks leading whitespace" {
    const src = "www A 192.0.2.1\n    A 192.0.2.2\n";
    var it = Iterator.init(src);
    const first = try it.next();
    try std.testing.expect(!first.leading_ws);
    _ = try it.next(); // A
    _ = try it.next(); // ip
    _ = try it.next(); // newline
    const second = try it.next();
    try std.testing.expect(second.leading_ws);
}

test "escaped delimiters stay in words" {
    const src = "a\\ b\\;c \\046 x\n";
    var it = Iterator.init(src);
    const t = try it.next();
    try std.testing.expectEqualStrings("a\\ b\\;c", t.text);
    const t2 = try it.next();
    try std.testing.expectEqualStrings("\\046", t2.text);
}

test "unterminated quote" {
    var it = Iterator.init("x \"abc\n");
    _ = try it.next();
    try std.testing.expectError(error.UnterminatedQuote, it.next());
}
