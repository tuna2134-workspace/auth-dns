# Core RFC compliance notes (authoritative-only DNS server)

Scope: server-side obligations for an authoritative-only implementation. Resolver/cache-only rules
(e.g. negative caching, trust ranking) are cited only where they constrain a server's response.
Sources: RFC 1035, 1034, 2181, 2308, 4343, 3597, 4592, 1101, 1183, 1876 (RFC Editor). RFC 2782 (SRV)
is not in the local set and is cited for SRV format, compression, and target rules only.

## 1. Compliance checklist

### Header, flags, opcode, rcode
1. Header is 12 octets; copy the query ID verbatim into the response (`RFC 1035 §4.1.1`).
2. Set QR=1 and copy OPCODE into the response; only QUERY(0) is mandatory, IQUERY(1)/STATUS(2) are optional, and opcodes 3–15 are reserved -> RCODE 4 (NOTIMP) (`RFC 1035 §4.1.1`, `RFC 1034 §3.7`).
3. AA=1 only when the server is authoritative for the zone containing QNAME (including NXDOMAIN/NODATA); AA=0 for referrals, out-of-zone data, and QCLASS=*; AA corresponds to QNAME or the first owner in the answer (`RFC 1035 §4.1.1`, `RFC 2181 §6.1, §6.2`, `RFC 1034 §3.7.1`).
4. Copy RD from the query; set RA=0 (no recursion offered); Z must be 0; TC only per rules 76 and 78 (`RFC 1035 §4.1.1`, `RFC 1034 §4.3.1`).
5. RCODE values: 0 NOERROR, 1 FORMERR, 2 SERVFAIL (internal error/CNAME loop only), 3 NXDOMAIN only for authoritative names, 4 NOTIMP, 5 REFUSED; never NXDOMAIN for a name outside the served zones (`RFC 1035 §4.1.1`, `RFC 2308 §2.1`).
6. QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT must exactly match the bytes present; never count records that were omitted (`RFC 1035 §4.1.1`).
7. Standard queries carry QDCOUNT=1; treat QDCOUNT=0 or >1 as FORMERR (de facto interop, `RFC 1035 §4.1.2` "usually 1").
8. Echo the question section unchanged: QNAME, QTYPE, QCLASS; do not lowercase QNAME (`RFC 1035 §4.1.2`, `RFC 4343 §4.1`).
9. Unknown QTYPE at an existing name -> NODATA (NOERROR + SOA), not NOTIMP; meta QTYPEs MAILA/MAILB -> NOTIMP; ANY(255) returns every RRset at the name; AXFR(252) only over TCP and only if implemented (`RFC 1035 §3.2.3, §4.2.1`, `RFC 1034 §3.7.1`, `RFC 3597 §3`).
10. QCLASS must match a served zone's class; class is part of an RR's identity and records of different classes are never merged; QCLASS=* can never be authoritative (AA=0); an unsupported class gets REFUSED, not NXDOMAIN (`RFC 2181 §5`, `RFC 1034 §3.7.1`, `RFC 1035 §6.2`).

### Question section
11. Question is QNAME/QTYPE/QCLASS; a compressed QNAME in the query must be accepted even though most clients do not send one (`RFC 1035 §4.1.2, §4.1.4`).
12. QTYPE/QCLASS are 16-bit supersets of TYPE/CLASS; preserve numeric values for unknown mnemonics (`RFC 1035 §3.2.3, §3.2.5`).

### RR wire format
13. RR = NAME, TYPE(16), CLASS(16), TTL(32), RDLENGTH(16), RDATA; bound-check every field and RDLENGTH against the message, reject truncated records (`RFC 1035 §4.1.3`).
14. TTL is a 32-bit field but valid values are 0..2147483647; on receive, a TTL with the MSB set is treated as 0; never emit a TTL > 2^31-1; TTL 0 means "do not cache" (`RFC 2181 §8`, `RFC 1035 §3.2.1`).
15. Every RR in one RRSet has the same TTL; normalize at load (lowest TTL is safe) or reject the zone; never emit mixed TTLs (`RFC 2181 §5.2`).
16. Suppress exact duplicate RRs (same owner/class/type/RDATA); include each RRSet at most once per message, except AXFR's first/last SOA (`RFC 2181 §5, §5.5`).
17. Owner names are always eligible for compression; RDATA names only for the RFC 1035 well-known types; RDLENGTH counts the compressed form (`RFC 1035 §4.1.4`, `RFC 3597 §4`).
18. Do not decrement TTLs when serving authoritative data; serve the zone TTL (the TTL limit applies to caches) (`RFC 1034 §3.6`).

### Names, compression, limits
19. Label length 1..63 octets; a zero-length label is only the root terminator; a name is at most 255 octets on the wire including length octets and the root zero; presentation form is at most 253 characters excluding the final dot (`RFC 1035 §3.1`, `RFC 2181 §11`).
20. Label first two bits: 00 = normal label, 11 = compression pointer, 01/10 are reserved -> FORMERR (`RFC 1035 §4.1.4`).
21. Pointer offset is 14 bits from the start of the message; it must point to a prior occurrence at a label boundary; reject forward, self, and mid-label pointers and detect pointer loops (`RFC 1035 §4.1.4`).
22. A decompressed name must terminate and stay <=255 octets; a pointer chain must terminate inside the message (`RFC 1035 §3.1, §4.1.4`).
23. Compression may match names case-insensitively, which can change output case; to preserve QNAME case, only compress against byte-identical prior names (`RFC 4343 §4.1`).
24. Never compress RDATA of unknown or class-specific types; for RP, AFSDB, RT, SIG, PX, NXT, NAPTR, SRV, SHOULD decompress on receive but do not compress on send (`RFC 3597 §4`; for SRV also `RFC 2782` "The format of the SRV RR").
25. A pointer may point to another pointer; all pointer targets must be validated, not just the first (`RFC 1035 §4.1.4`).

### Case handling (RFC 4343)
26. Fold only ASCII A–Z (0x41–0x5A) against a–z (0x61–0x7A); all other octets compare exactly; 0xDD and 0xFD do not match; no Latin-1/Unicode folding (`RFC 4343 §3`).
27. Label case insensitivity is class-independent; do not make it depend on CLASS (`RFC 4343 §3.3`).
28. Preserve case on output; for an existing node the first-loaded case may be retained, and §4.2 even permits mixed case, but emitting one consistent case per name is safer (`RFC 4343 §4.1, §4.2`, `RFC 1035 §2.3.3`).
29. Labels are arbitrary octets: do not enforce hostname/LDH syntax or reject binary labels; only the length limits apply (`RFC 2181 §11`, `RFC 1034 §3.5` is advisory only).
30. Presentation output must escape 0x2E and every octet outside 0x21–0x7E, using `\X` or `\DDD` (`RFC 4343 §2.1`).

### Master file format
31. Line-oriented; spaces/tabs delimit; `;` starts a comment outside quotes; blank lines are allowed; parentheses suspend line termination (`RFC 1035 §5.1`).
32. A line beginning with blank/tab omits the owner: use the last stated owner, which persists across blank and comment lines (`RFC 1035 §5.1`).
33. Both `[TTL] [class] type` and `[class] [TTL] type` are valid; omitted class defaults to the last explicit class, omitted TTL to the current `$TTL` value (else the last explicit TTL); the type mnemonic is last and type/class mnemonics are disjoint (`RFC 1035 §5.1`, `RFC 2308 §4`).
34. `$TTL <n>` sets the default TTL for following RRs that omit one; do not use SOA MINIMUM as the default (`RFC 2308 §4`).
35. `$ORIGIN` resets the origin; names ending in `.` are absolute; relative names append the origin; a relative name with no origin is a load error; a free-standing `@` denotes the origin (`RFC 1035 §5.1`).
36. `$INCLUDE <file> [origin]`: the optional origin applies to the included file; the parent file's origin is unchanged after the include; relative names inside resolve against the include's origin (`RFC 1035 §5.1`).
37. A quoted character-string may contain spaces, `;`, parentheses, and even CRLF; `\"` quotes a quote; the quotes are delimiters, not data (`RFC 1035 §5.1`).
38. Escapes: `\X` quotes X; `\DDD` with exactly three decimal digits yields that octet; four digits yield the 3-digit octet plus a literal fourth digit; one or two digits are undefined — reject or define a documented policy (`RFC 1035 §5.1`, `RFC 4343 §2.1`).
39. TTL is a decimal integer in RFC syntax; unit suffixes such as `1h` are an extension and must be rejected or explicitly documented (`RFC 1035 §5.1`).
40. Load checks: exactly one SOA at the apex; all RRs the same class; required glue present; no data outside the zone except glue; any error suppresses the entire zone load (`RFC 1035 §5.2`).
41. The apex must own SOA and NS; CNAME cannot coexist with other data; a CNAME at the apex is therefore invalid (`RFC 2181 §6.1, §10.1`, `RFC 1035 §3.3.13`).
42. Suppress duplicate RRs; reject or normalize RRSet TTL mismatches; reject unknown `$DIRECTIVE`s and malformed entries (`RFC 2181 §5, §5.2`, `RFC 1035 §5.2`).
43. If class is omitted and no class has been stated, use a configured default; every loaded RR must end up in the same class (`RFC 1035 §5.2`).

### SOA/NS/CNAME/MX/TXT/PTR/SRV and related types
44. SOA: MNAME is the primary master host (not the zone name); RNAME is a mailbox with `\.` escaping; SERIAL is 32-bit compared with sequence arithmetic; REFRESH/RETRY/EXPIRE are served verbatim (`RFC 1035 §3.3.13`, `RFC 2181 §7.3`).
45. SOA MINIMUM is no longer a floor on all TTLs or the default TTL; its defined use is now the negative-response TTL input; the SOA's own TTL need not be 0 (`RFC 2308 §4`, `RFC 2181 §7.2`).
46. The apex NS RRset is mandatory; delegation NS belongs to the child; the parent ignores non-NS data at the cut except glue and must not set AA at the cut (`RFC 2181 §6.1, §6.2`, `RFC 1035 §3.3.11`).
47. NS and MX targets must not be aliases; additional-section processing adds address records only, never chases a CNAME (`RFC 2181 §10.3`).
48. CNAME: at most one per owner and no other data (DNSSEC SIG/NXT/KEY excepted); QTYPE=CNAME or ANY returns only the CNAME; otherwise chase in-zone and place the chain in order (`RFC 1034 §3.6.2`, `RFC 2181 §10.1`, `RFC 2308 §1`).
49. CNAME loops must terminate: reject the zone at load or return SERVFAIL; never loop or emit an unbounded chain (`RFC 1034 §3.6.2`).
50. MX: 16-bit PREFERENCE, lower is preferred; EXCHANGE is a domain name; add A records for EXCHANGE when authoritative (`RFC 1035 §3.3.9`, `RFC 2181 §10.3`).
51. TXT: one or more character-strings, each a length octet plus <=255 data octets; binary; preserve string boundaries exactly; never join or split on output; zero-string RDATA is invalid (`RFC 1035 §3.3, §3.3.14`).
52. PTR: no special processing; multiple PTR RRs at one name are allowed; the value should be a canonical name, not an alias; a PTR lookup may itself traverse a CNAME, but PTR RDATA must not be an alias (`RFC 1035 §3.3.12`, `RFC 2181 §10.2`).
53. SRV: owner is `_Service._Proto.Name`; RDATA is priority/weight/port/target; target must not be an alias; target `.` means the service is decidedly unavailable; do not compress the target; return the whole RRset; address records in additional are optional (`RFC 2782` "The format of the SRV RR", `RFC 4592 §4.5`, `RFC 2181 §5.1`).
54. LOC: 16-octet RDATA; VERSION must be 0; master text is `d1 [m1 [s1]] N|S d2 [m2 [s2]] E|W alt [siz [hp [vp]]]` with siz/hp/vp defaulting to 1m/10000m/10m; if VERSION != 0 make no assumptions and do not parse as version 0 — generic `\#` treatment is appropriate (`RFC 1876 §2, §3`, `RFC 3597 §5`).
55. AFSDB (subtype+hostname) causes A additional; RP (mbox-dname+txt-dname, `.` allowed) causes no additional by default; X25/ISDN (character-string(s)) cause none; RT (preference+intermediate-host) causes A/X25/ISDN additional (`RFC 1183 §1, §2.2, §3.1–§3.3`).
56. RFC 1101 host-zero names are ordinary names: an A RR there carries a netmask and a PTR may sit at the same name; serve them as data, do not validate network semantics or synthesize anything (`RFC 1101 §4, §4.1–§4.4`).

### Negative answers (RFC 2308)
57. NXDOMAIN iff QNAME (after any CNAME chasing) does not exist; an empty non-terminal exists and yields NODATA; a name at or below a delegation yields a referral, not NXDOMAIN (`RFC 2308 §2.1, §2.2`, `RFC 4592 §2.2.3`).
58. NODATA = NOERROR + empty answer (or only a CNAME chain) + SOA in authority; omit NS from authority (TYPE 2 is the recommended form) (`RFC 2308 §2.2, §2.2.1`).
59. An authoritative NXDOMAIN or NODATA MUST include the containing zone's SOA in the authority section and MUST set AA=1 (`RFC 2308 §3, §2.1.1`, `RFC 1035 §4.1.1`).
60. The SOA TTL in a negative response is min(SOA TTL, SOA MINIMUM); not the maximum/floor; clamp the result to 2^31-1; do not decrement it when serving (`RFC 2308 §3, §5`, `RFC 2181 §8`).
61. CNAME + NXDOMAIN: put the CNAME chain in the answer and RCODE 3 only if the final target is in a zone this server serves; an out-of-zone target gives NOERROR with the CNAME chain only (`RFC 2308 §2.1`, `RFC 1034 §3.6.2`).
62. Referral: NOERROR, empty answer, NS in authority, glue in additional, AA=0, no SOA (`RFC 1034 §4.3.2` step 3b, `RFC 2181 §6.1`).

### Wildcards (RFC 4592)
63. A wildcard owner has leftmost label exactly `0x01 0x2a`; `the*`, `**`, `a*b` are ordinary labels, not wildcards (`RFC 4592 §2.1.1, §2.1.2`).
64. Closest encloser = the longest existing ancestor of QNAME; source of synthesis = `*.<closest encloser>`; there is at most one source and no alternate search (`RFC 4592 §3.3.1`).
65. Wildcards do not apply when QNAME exists, when any name between the wildcard and QNAME exists (including an empty non-terminal), below a delegation, or to the wildcard owner itself or its subdomains; `*.example.` matches neither `example.` nor `a.*.example.` (`RFC 1034 §4.3.3`, `RFC 4592 §2.2, §2.2.1`).
66. A synthesized RR's owner is QNAME; a wildcard CNAME is copied with owner QNAME and the query restarts at its target; wildcard NS is undefined/discouraged; wildcard DNAME should be rejected at load (`RFC 1034 §4.3.2` step 3c, `RFC 4592 §3.3.3, §4.2, §4.4`).
67. Source exists but has no QTYPE -> NODATA; source is an empty non-terminal -> NODATA (NOERROR, empty answer); source does not exist -> NXDOMAIN (`RFC 4592 §2.2.1, §3.3.1, §4.9`).
68. A wildcard SOA denotes an apex and can never be a source of synthesis; reject an SOA below the configured apex (`RFC 4592 §4.1`).

### Unknown RR types and \# syntax (RFC 3597)
69. Master text: `TYPE####` and `CLASS####`; generic RDATA is `\# <len> <hex...>`; zero length is exactly `\# 0`; `<len>` must equal the number of hex octets; hex is whitespace-separated even-length words (`RFC 3597 §5`).
70. Unknown RDATA is opaque: store and transmit byte-for-byte; never compress it; never interpret embedded bytes as names/pointers; equality is bitwise; unknown types cause no additional processing (`RFC 3597 §3, §4, §6, §8`).
71. A known type written in `\#` form is still a known type for compression/canonicalization rules (`RFC 3597 §5`).
72. Unknown class numbers are preserved numerically; if no zone exists in that class, REFUSED rather than NXDOMAIN (`RFC 3597 §5`, `RFC 1035 §4.1.1`).

### Additional-section processing
73. Defined additional processing: NS -> A of NSDNAME; MX -> A of EXCHANGE; AFSDB -> A; RT -> A/X25/ISDN; SRV -> A optional; SOA, CNAME, PTR, TXT and unknown types -> none (`RFC 1035 §3.3.9, §3.3.11–§3.3.14`, `RFC 1183 §1, §3.3`, `RFC 3597 §8`).
74. Never put CNAMEs in additional and never chase an alias to find addresses; additional data must come from authoritative data or glue, not a cache (`RFC 2181 §10.3, §5.4.1, §6.1`).
75. Do not repeat an RRSet across answer/authority/additional; duplicate records may be omitted (`RFC 1035 §6.2`, `RFC 2181 §5.5`).
76. Additional data is optional: if it does not fit, omit the whole RRSet and leave TC=0; if a required RRSet does not fit, set TC=1 (`RFC 2181 §9, §5.1`).
77. For NS targets, add authoritative address data when it exists; add glue only for in-bailiwick targets below the cut; never invent out-of-zone addresses or leak another zone's data (`RFC 1035 §3.3.11, §5.2`, `RFC 2181 §6.1`).

### Transport and transfer
78. UDP without EDNS is limited to 512 octets; truncate from the end, never mid-RR, keep counts consistent, set TC=1 (`RFC 1035 §4.2.1, §6.2`).
79. TCP messages carry a 2-octet length prefix; support multiple queries per connection and do not block or close prematurely (`RFC 1035 §4.2.2`).
80. Send the reply from the query's destination IP address and to the query's source port (`RFC 2181 §4.1, §4.2`).
81. AXFR is TCP-only; if unimplemented return NOTIMP or REFUSED, and if implemented the SOA is first and last with the same TTL (`RFC 1035 §4.2.1`, `RFC 2181 §5.5`).

### Additional cross-checks
82. If a zone fails to load or has expired, answer as if the server does not possess the zone (REFUSED, SERVFAIL, or a referral as appropriate); never return authoritative NXDOMAIN from a zone that is not loaded (`RFC 1035 §6.3`).
83. NULL (TYPE 10) is not allowed in master files; reject it at load, even though the wire format is defined (`RFC 1035 §3.3.10`).
84. SRV's `Name` is not the owner: `_foo._udp.*.example.` is not a wildcard domain name; only a leftmost `*` label makes a wildcard (`RFC 4592 §4.5, §2.1.1`).

## 2. Interoperability pitfalls and exact expected behavior

1. **AA on negatives**: authoritative NXDOMAIN and NODATA must have AA=1; a referral must have AA=0 even for QTYPE=NS at the child apex. Some resolvers loop/SERVFAIL if AA is clear on NXDOMAIN (`RFC 2308 §2.1.1`, `RFC 2181 §6.2`).
2. **RA out of habit**: authoritative-only servers must return RA=0; RD is copied but must not trigger recursion (`RFC 1035 §4.1.1`, `RFC 1034 §4.3.1`).
3. **TC misuse**: a response that omits only additional data must have TC=0; TC=1 is only for a required RRSet that cannot fit. A partial RRSet is allowed only with TC=1, but never a partial RR (`RFC 2181 §9, §5.1`).
4. **Question case**: echo QNAME with the exact octets received. If compression matches case-insensitively, the echoed case can silently change; prefer byte-identical compression targets (`RFC 4343 §4.1`).
5. **ENT is not NXDOMAIN**: `ent.example.` with only `deep.ent.example.` present exists; `ent.example. A` is NODATA, not NXDOMAIN. `x.ent.example. A` is NXDOMAIN (`RFC 4592 §2.2.3`).
6. **Wildcard NODATA**: if `*.example.` exists but lacks the QTYPE, the answer is NOERROR + SOA, not NXDOMAIN. If the source of synthesis is an ENT, same result (`RFC 4592 §2.2.1, §4.9`).
7. **Wildcard scope**: `*.example.` does not cover `example.` itself, `a.b.example.` when `b.example.` exists, or anything below a delegation (`RFC 4592 §2.2.1`).
8. **Negative TTL**: use min(SOA TTL, MINIMUM). The old RFC 1035 "max(RR TTL, MINIMUM)" floor is deprecated; using it breaks negative caching (`RFC 2308 §3, §4`, `RFC 1035 §3.3.13`).
9. **SOA placement**: negative SOA goes in authority, never additional; TYPE 2 NODATA means SOA only, no NS (`RFC 2181 §7.1`, `RFC 2308 §2.2.1`).
10. **Out-of-zone QNAME**: REFUSED with AA=0, not NXDOMAIN; RCODE 3 is only meaningful from an authoritative server (`RFC 1035 §4.1.1`).
11. **Below a cut**: always a referral (NS authority, AA=0), even if the parent has no data for the name and even if a wildcard would otherwise match (`RFC 1034 §4.3.2` step 3b).
12. **CNAME exclusivity**: a CNAME owner must not serve A/TXT/MX/etc.; ANY and CNAME queries return only the CNAME (`RFC 2181 §10.1`, `RFC 1034 §3.6.2`).
13. **Additional aliases**: if an MX/NS target is a CNAME, add no address record and do not follow it; the target is already misconfigured (`RFC 2181 §10.3`).
14. **Unknown QTYPE**: at an existing name return NODATA with SOA; NOTIMP is for unimplemented operations, not for absent data (`RFC 1035 §4.1.1`, `RFC 2308 §2.2`, `RFC 3597 §3`).
15. **Unknown RDATA**: bytes that look like `0xC0` pointers are data; never decompress, re-encode, case-fold, or append additional records (`RFC 3597 §3, §4, §8`).
16. **255/253 off-by-one**: the wire limit is 255 octets including the root zero; the same name is at most 253 presentation characters. Do not reject a legal 255-octet wire name or accept 256 (`RFC 1035 §3.1`).
17. **Pointer direction**: pointers must target a prior occurrence; forward/self pointers and loops must be rejected as FORMERR, not followed (`RFC 1035 §4.1.4`).
18. **TTL edge**: a received TTL >= 2^31 is treated as 0; never emit such a value; TTL 0 is legal and means no caching (`RFC 2181 §8`).
19. **Escape digit count**: `\12` is not a valid escape; `\012` is one octet 0x0A; `\0123` is the two octets `0x0A 0x33` (`RFC 4343 §2.1`).
20. **TXT limits**: each character-string is at most 255 data octets; overlong text must be split by the zone author, never truncated by the server; `"one" "two"` stays two strings (`RFC 1035 §3.3, §3.3.14`).
21. **High-bit case**: `0xDD` and `0xFD` are distinct labels; only ASCII letters fold (`RFC 4343 §3`).
22. **Wildcard QCLASS**: never set AA for QCLASS=*, even if the server has data in one class; it cannot know all classes (`RFC 1034 §3.7.1`, `RFC 1035 §6.2`).
23. **Opcode echo**: unsupported opcodes return NOTIMP with the query's opcode echoed, not a QUERY-shaped answer (`RFC 1035 §4.1.1`).
24. **Malformed input**: zero/multiple questions, truncated header/question, or bad RDLENGTH -> FORMERR; echo ID and any parseable question, never crash (`RFC 1035 §4.1.1, §4.1.2`).
25. **TCP framing**: on TCP the 2-octet length prefix is mandatory and a DNS message cannot exceed 65535 octets; do not write a bare message to the stream (`RFC 1035 §4.2.2`).
26. **LOC version**: VERSION != 0 must not be interpreted with the version-0 layout; serve it as opaque or via `\#` (`RFC 1876 §2`, `RFC 3597 §5`).
27. **SRV target `.`**: means "service not available", not the root server; do not add an A record for it and do not compress it (`RFC 2782` "The format of the SRV RR").
28. **Master owner state**: a leading-blank record after a blank/comment line still belongs to the last stated owner; resetting owner state on blank lines misloads zones (`RFC 1035 §5.1`).
29. **$INCLUDE leakage**: an include's `$ORIGIN` must not change the parent origin, and its relative names must not be resolved against the parent (`RFC 1035 §5.1`).
30. **Duplicate RRsets**: the same RRset must not appear twice (e.g. MX answer plus MX in additional); this breaks strict clients and inflates messages (`RFC 2181 §5.5`).

## 3. Concrete test vectors and edge cases

Fixture `example.` (TTL 3600 unless shown; SOA MINIMUM 300):

```zone
$ORIGIN example.
@       3600 IN SOA ns1.example. hostmaster.example. ( 2024010101 7200 3600 1209600 300 )
@       3600 IN NS  ns1.example.
@       3600 IN NS  ns2.example.
@       3600 IN MX  10 mail.example.
@       3600 IN TXT "v=spf1 -all"
ns1     3600 IN A   192.0.2.1
ns2     3600 IN A   192.0.2.2
mail    3600 IN A   192.0.2.3
www     3600 IN A   192.0.2.10
alias   3600 IN CNAME www.example.
*.wild  3600 IN A   192.0.2.20
*.wild  3600 IN MX  10 mail.example.
deep.ent.wild 3600 IN A 192.0.2.21
sub     3600 IN NS  ns.sub.example.
ns.sub  3600 IN A   192.0.2.30
txt2    3600 IN TXT "one" "two"
unk     3600 IN TYPE65280 \# 4 deadbeef
loc     3600 IN LOC 42 21 54 N 71 06 18 W -24m 30m
_sip._tcp 3600 IN SRV 0 1 5060 sip.example.
sip     3600 IN A   192.0.2.40
```

| # | Query / input | Expected exact behavior |
|---|---|---|
| 1 | `www.example. A` | AA=1, AN=1, A 192.0.2.10, TTL 3600; no additional. |
| 2 | `alias.example. A` | AN=2 in order: CNAME alias->www, A www; AA=1; CNAME not repeated in additional. |
| 3 | `alias.example. CNAME` and `alias.example. ANY` | Each returns exactly the CNAME, AN=1. |
| 4 | `www.example. CNAME` | NOERROR, AN=0, SOA in authority with TTL 300, AA=1, no NS. |
| 5 | `absent.example. A` | NXDOMAIN, AA=1, SOA in authority with TTL 300, no NS. |
| 6 | `ent.wild.example. A` and `ent.wild.example. ANY` | Both NOERROR, AN=0, SOA in authority (ENT exists), not NXDOMAIN. |
| 7 | `deep.ent.wild.example. A` | A 192.0.2.21. |
| 8 | `x.wild.example. A` | Synthesized owner `x.wild.example.`, A 192.0.2.20. |
| 9 | `a.b.wild.example. A` | Synthesized A 192.0.2.20 (closest encloser `wild.example.`). |
| 10 | `x.wild.example. TXT` | NOERROR, AN=0, SOA (source exists, no TXT). |
| 11 | `wild.example. A` | NOERROR, AN=0, SOA; wildcard does not match its owner. |
| 12 | `*.wild.example. A` | Exact match: owner `*.wild.example.`, A 192.0.2.20, not synthesized. |
| 13 | `a.*.wild.example. A` | NXDOMAIN (`*.wild` exists, but no `*.*.wild` source). |
| 14 | `deep.ent.wild.example. TXT` | NODATA; exact name exists, wildcard blocked. |
| 15 | `x.wild.example. MX` | MX 10 mail + additional A 192.0.2.3. |
| 16 | `sub.example. A` and `x.sub.example. A` | Both: NOERROR, AA=0, NS authority, glue A ns.sub in additional, no SOA, empty answer. |
| 17 | `example. SOA` / `NS` / `MX` | AA=1; SOA alone; NS + A ns1/ns2 additional; MX + A mail additional. |
| 18 | `txt2.example. TXT` | RDLENGTH 8, RDATA `03 6f 6e 65 03 74 77 6f`; two strings preserved. |
| 19 | `unk.example. TYPE65280` | RDLENGTH 4, RDATA `de ad be ef`; no compression; `unk.example. A` -> NODATA. |
| 20 | `loc.example. LOC` | 16 bytes `00 31 14 11 89 17 2d d0 70 be 15 f0 00 98 8d 20` (version 0, size 30m, hp 10000m, vp 10m, lat 42 21 54 N, lon 71 06 18 W, alt -24m). |
| 21 | `_sip._tcp.example. SRV` | SRV 0 1 5060 sip.example.; target uncompressed; A sip in additional optional; QTYPE=A there -> NODATA. |
| 22 | `example. ANY` over UDP/TCP | All apex RRsets, AA=1; large result may set TC over UDP but must be complete over TCP. |
| 23 | `www.example. CH` | REFUSED, AA=0; no IN data leaked. `QCLASS=*` -> never AA. |
| 24 | opcode 5, QDCOUNT=0, QDCOUNT=2 | NOTIMP (opcode 5 echoed); FORMERR; FORMERR; ID echoed in all. |
| 25 | QNAME 255 octets (`63.63.63.61` labels) vs 256; label 64 | 255 valid (NXDOMAIN in fixture); 256 and 64 -> FORMERR. |
| 26 | QNAME `ExAmPlE.` | Question echoed byte-identically; answer owners may use zone case; no downcasing. |
| 27 | Compressed QNAME pointer; forward/self pointer; pointer loop | Valid backward pointer accepted; forward/self/loop -> FORMERR, bounded CPU. |
| 28 | Large TXT RRset over UDP, then TCP | UDP: TC=1, question intact, no partial RR; TCP: full answer with 2-octet length prefix. |
| 29 | SOA TTL=100, MINIMUM=300 (variant) | Negative SOA TTL = 100; with TTL=3600, MINIMUM=300 -> 300. |
| 30 | `TYPE1 \# 4 7f000001` in zone | Served as A 127.0.0.1, RDLENGTH 4; `\# 3 deadbe` -> load error. |
| 31 | `a\.b.example.` owner; TXT `"a\;b"` | Owner is one label `a.b` (wire `03 61 2e 62`); TXT data is `a;b`, not a comment. |
| 32 | Blank line + leading-blank RR; `$TTL 60`; TTL-less RR | Owner stays the last stated owner; TTL 60 applied to following TTL-less records. |
| 33 | `$INCLUDE sub.zone other.example.` | Relative names in `sub.zone` use `other.example.`; parent origin `example.` restored afterward. |
| 34 | CNAME loop `a->b->a`; CNAME plus A at one owner | No hang; SERVFAIL or load-time rejection; CNAME+A zone rejected, never serve both. |
| 35 | MX target `alias.example.`; duplicate MX RR; duplicate A | No additional A for alias; duplicate suppressed; RRset appears once. |
| 36 | LOC version 1 via `\# 16 01...`; TXT string 256 bytes | Version-1 LOC served opaquely, not parsed; 256-byte string -> load error, never truncated. |
| 37 | `example. MX` with many in-zone exchanges, over 512 UDP | Answer complete; additional omitted entirely (not partially); TC=0. |
| 38 | Wildcard CNAME variant `*.cn.example. CNAME target.example.`, query `x.cn.example. A` | Synthesized CNAME owner `x.cn.example.`, then target A if in zone; out-of-zone target -> CNAME only, NOERROR, AA=1. |
| 39 | Master TTL 2147483648; same RRset with TTL 60 and 3600 | Load error or clamp to 0 (never emit an MSB-set TTL); mismatched RRset rejected or normalized to 60. |
| 40 | Query with RD=1 and ID=0x1234 | Response ID=0x1234, QR=1, RD=1, RA=0; no recursion attempted. |
