# Security notes: EDNS(0), TSIG, DNSSEC, ANY (authoritative server)

Sources: RFC 6891, 8945, 4033/4034/4035, 8482, 3597, 5936 (AXFR). Algorithm companions (RFC
5702 alg 8, RFC 6605 alg 13, RFC 8080 alg 15) are external to the original RFC 1035 update set, so those rows are marked `[ext]`. Section
numbers refer to the RFC named in the heading. Notation: ‖ = concatenation, all integers network order.

## 1. EDNS(0) — RFC 6891

**OPT wire format (§6.1.2):** `NAME=0x00` (root, never compressed) | `TYPE=41` | `CLASS=u16 payload size` |
`TTL=u32` (see below) | `RDLEN=u16` | `RDATA=(OPTION-CODE u16 | OPTION-LENGTH u16 | OPTION-DATA)+`. Options are
in **no defined order**; RDATA may be empty. OPT carries no data and **MUST NOT** be cached or stored (§6.1.1).

**Placement/multiplicity (§6.1.1):** MAY be anywhere in the additional section but must be the only OPT.
**≥2 OPT in a query → FORMERR (RCODE=1)**. OPT never appears in answer/authority. Placement freedom does not
override "TSIG last", so the order is `… , OPT, TSIG`; a non-final TSIG is a TSIG error (§2), not an EDNS one.

**TTL word (§6.1.3):** `| EXTENDED-RCODE (31..24) | VERSION (23..16) | DO (15) | Z (14..0) |`. Full RCODE =
`(EXTENDED-RCODE << 4) | header.RCODE`; EXTENDED-RCODE=0 means a plain 0..15 RCODE. BADVERS(16) ⇒ header RCODE 0,
EXTENDED-RCODE 1. VERSION=0 here. **DO** = DNSSEC OK (§6.1.4); **Z** sent as 0, ignored on receipt. Never echo the
query's TTL word: our response carries our own ext-RCODE/VERSION, DO=0, Z=0.

**Version negotiation / BADVERS (§6.1.3):** if `VERSION > 0`, reply **BADVERS (16)** with one OPT carrying our
VERSION (0) and no data; the format MUST stay within the request's VERSION, and the advertised VERSION SHOULD be
our highest. A malformed option → **FORMERR *with* an OPT** (§7), which proves we do implement EDNS.

**Payload sizes (§6.2.3, §6.2.4, §6.2.5, §7):**
- No OPT in query ⇒ no EDNS for this transaction ⇒ **512**-byte limit and the response **MUST NOT** carry an OPT.
- OPT present ⇒ limit `max(512, CLASS)`; **anything below 512 MUST be treated as 512**. That value is the
  largest UDP payload the peer can reassemble (PMTU may be smaller) and MUST NOT outlive the transaction.
- Response OPT CLASS = **our** receive capability: RFC 6891 §6.2.5 suggests 4096; RFC 4035 §3 requires ≥1220 and
  SHOULD 4000. Advertise 1232 (IPv6-safe), accept up to 4096.
- TCP: no EDNS sizing; limit is the 2-octet prefix ⇒ **65535** (RFC 1035 §4.2.2).

**Response size limit:**
```
limit = tcp ? 65535 : min(cfg.max_udp, q.has_opt ? max(512, q.opt_class) : 512)
```
The limit is the **whole** message (header + question + answer + authority + additional). Reserve the OPT
(`11 + RDLEN`) and, for signed queries, the TSIG (`len(owner) + 10 + RDLEN`) *before* packing answers.

**Truncation (§7, RFC 1035 §6.2):** truncate from the end forward (additional → authority → answer), never split an
RRset or separate it from its RRSIG (RFC 4035 §3.1.1). Minimal truncated response = **header + question + OPT**;
never send an OPT-less TC reply to an OPT-bearing query. With DNSSEC, a missing RRSIG on an answer/authority
RRset ⇒ TC, while dropped additional RRSIGs ⇒ no TC (4035 §3.1.1). TCP is never truncated; AXFR chunks at ≤65535.

**Unknown options (§6.1.2):** unknown OPTION-CODEs MUST be **ignored**, never FORMERR'd and never echoed.

**OPT in AXFR (RFC 5936 §2.1.5, §2.2.5):** client MAY send exactly one OPT; only EXTENDED-RCODE is meaningful
for AXFR. Server SHOULD put one OPT in the **first** response and MAY in later ones; TSIG (if any) last in
every message. No TC and no 512 limit, but each message needs its own OPT/TSIG budget.

## 2. TSIG — RFC 8945

**RR format (§4.1, §4.2)** — type 250, meta-RR, never cached, MAC discarded after use:
```
NAME       key name (domain name; canonical/lowercase in the digest)
TYPE       u16 = 250
CLASS      u16 = ANY (255)      MUST
TTL        u32 = 0              MUST
RDLENGTH   u16
RDATA:
  Algorithm Name  domain name, MUST NOT be compressed (RFC 3597)
  Time Signed     u48 (6 octets) secs since 1970-01-01 UTC, no leap seconds
  Fudge           u16 seconds of permitted skew
  MAC Size        u16 octets of MAC present
  MAC             MAC Size octets
  Original ID     u16, ID of the original request
  Error           u16, 0 in requests; extended RCODE in responses
  Other Len       u16 octets of Other Data
  Other Data      Other Len octets (6 = server time for BADTIME; else empty)
```
Sizing: `hmac-sha256.` alg name = 13 octets ⇒ `RDLENGTH = 29 + MAC Size` (61 for a full 32-octet MAC);
`hmac-sha1.` = 11 octets ⇒ `RDLENGTH = 27 + MAC Size`. Whole RR = `len(owner) + 10 + RDLENGTH`.

**MAC input — request (§5.1, §4.3):** `DNS message (complete, TSIG absent, ARCOUNT NOT yet incremented)` ‖
`TSIG variables`, with no separators or padding. **Variables (§4.3.3, Table 2), exactly this order:**
`NAME (canonical)` | `CLASS (2)` | `TTL (4)` | `Algorithm Name (canonical)` | `Time Signed (6)` | `Fudge (2)` |
`Error (2)` | `Other Len (2)` | `Other Data`. Excluded: RDLENGTH, MAC Size, MAC, Original ID (the last is
already substituted into the header ID).

**MAC input — response (§5.3, §4.3.1):** `Request MAC (u16 MAC Size ‖ MAC exactly as transmitted, i.e. truncated
if the request was)` ‖ `DNS message (response; TSIG removed, ARCOUNT decremented, header ID := TSIG Original ID
if they differ)` ‖ `TSIG variables (response)`. Then append TSIG last, ARCOUNT++. The request MAC is omitted only
for the unsigned error cases (see the table below).

**Multi-message AXFR / TCP (§5.3.1):** TSIG MUST be on every message we send; clients tolerate up to 99 unsigned
messages in between but must see the first and last. Message 1 uses the normal response digest; messages 2..n
digest `Prior MAC (u16 len ‖ bytes)` ‖ `every message since the last TSIG, in order, incl. the current one (TSIG
removed, ARCOUNT adjusted)` ‖ `Time Signed (6)` ‖ `Fudge (2)`. **Only the timers** are hashed for later messages —
no key name/class/TTL/alg/error/other-data — Time Signed non-decreasing; a verification failure closes the conn.

**Checks in order (§5.2):** key → MAC → time → truncation policy. Multiple TSIGs, TSIG not last, or an
unparseable TSIG ⇒ **drop + FORMERR (RCODE 1)**.

| Condition | RCODE | TSIG Error | Signed? |
|---|---|---|---|
| key/algorithm unknown or unimplemented | 9 NOTAUTH | 17 BADKEY | **no** (§5.2.1, §5.3.2) |
| MAC mismatch | 9 NOTAUTH | 16 BADSIG | **no** (§5.2.2) |
| MAC Size > hash output, or < max(10, hash/2) | 1 FORMERR | — | no (§5.2.2.1) |
| now outside Time Signed ± Fudge | 9 NOTAUTH | 18 BADTIME | **yes**, same key (§5.2.3) |
| MAC valid but shorter than local policy | 9 NOTAUTH | 22 BADTRUNC | **yes** (§5.2.4) |
| misplaced / duplicated / unparseable TSIG | 1 FORMERR | — | no (§5.2) |

BADTIME (§5.2.3): Time Signed = **client's** time, Fudge = client's fudge, Other Len = 6, Other Data = **server's**
48-bit time, signed with the request's key so the client can verify it. Cache the newest Time Signed and reject
older ones (replay protection), but beware UDP reordering. Note `16` = BADSIG in TSIG Error, BADVERS as a RCODE.

**Truncation policy (§5.2.2.1, §7):** truncation means leading octets, whole octets only. Reject MAC Size >
output and MAC Size < `max(10, hash_len/2)` (except the zero-length MACs of unsigned error replies). Compare only
the truncated prefix of our HMAC. Policy SHOULD accept less truncation up to full length, and a **reply MAC
SHOULD be at least as long as the request MAC**. MUST implement HMAC-SHA1 and HMAC-SHA256 (SHA-256 RECOMMENDED,
MD5 MUST NOT be used); SHA-1 truncated to 96 bits SHOULD be supported (§6).

**TSIG + size limit (§5.3):** if TSIG cannot fit, send **header + question + TSIG only**, TC=1, RCODE=0. Never drop
the TSIG or sign a partial RRset; never sign an unsigned request (TKEY exception) or with another key.

**Signed vs unsigned errors (§5.3.2):** key/MAC failures ⇒ **MAC Size 0, empty MAC** (unverifiable by the client);
time/truncation failures ⇒ signed, including the request MAC only if it validated.

## 3. DNSSEC authoritative signing — RFC 4033/4034/4035

**Wire formats (RFC 4034):**
```
DNSKEY (48)  u16 Flags | u8 Protocol(=3) | u8 Algorithm | Public Key
             Flags bit7 = Zone Key, bit15 = SEP; other bits MUST be 0; Protocol != 3 ⇒ key invalid (§2.1)
RRSIG  (46)  u16 Type Covered | u8 Algorithm | u8 Labels | u32 Orig TTL | u32 Expiration |
             u32 Inception | u16 Key Tag | Signer's Name (uncompressed) | Signature
             RRSIG TTL == covered RRset TTL (§3); RRSIGs are not an RRset (4035 §2.2)
NSEC   (47)  Next Domain Name (uncompressed, never wildcard-expanded) | Type Bit Maps
             TTL SHOULD equal SOA MINIMUM (§4); last NSEC's next name = apex (§4.1.1)
DS     (43)  u16 Key Tag | u8 Algorithm | u8 Digest Type | Digest = H(canonical owner ‖ DNSKEY RDATA) (§5.1.4)
```
**Algorithms 8/13/15 `[ext]`:**

| Alg | Name | Public key | Signature |
|---|---|---|---|
| 8 | RSASHA256 (RFC 5702) | RFC 3110: u8 exp-len (or 0x00+u16), exponent, modulus | PKCS#1 v1.5 over SHA-256, modulus-length |
| 13 | ECDSAP256SHA256 (RFC 6605) | 64 octets X‖Y, no 0x04 prefix | 64 octets fixed-width r‖s, **not DER** |
| 15 | ED25519 (RFC 8080) | 32 octets | 64 octets, pure Ed25519 over the raw signed data (no prehash) |
Digest types: 1=SHA-1, 2=SHA-256 (RFC 4509), 4=SHA-384. Use type 2 for 8/13/15. With OpenSSL, alg 13 needs
DER→fixed `r‖s` conversion (`ECDSA_SIG`, `BN_bn2binpad`) and alg 15 needs `EVP_DigestSignInit(pkey,NULL,NULL,…)`.

**Key tag (App. B):** `ac = Σ (i even ? b<<8 : b)` over the DNSKEY RDATA, then `ac += (ac>>16)&0xFFFF`, `tag = ac &
0xFFFF`. Similar to, but **not**, the IP ones-complement checksum — don't reuse a checksum helper. Alg 1 (RSA/MD5)
is the exception (low 24 bits of the modulus). Tags are not unique: be ready to try several matching DNSKEYs.

**Canonical name order (§6.1):** compare labels from the rightmost (most significant) label leftward, each as
a lowercased left-justified unsigned octet string, prefix-shorter first:
`example < a.example < yljkjljk.a.example < Z.a.example < z.example < \001.z.example < *.z.example < \200.z.example`.

**Canonical RR form (§6.2) / RRset order (§6.3):** `owner | type(2) | class(2) | OrigTTL(4) | RDLEN(2) | RDATA`
with every name fully expanded (no compression), owner lowercased, RDATA names lowercased for NS, MD, MF, CNAME,
SOA, MB, MG, MR, PTR, HINFO, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6, RRSIG, NSEC,
TTL = RRSIG Original TTL, wildcard owner literal. Sort RRs within an RRset by canonical RDATA as an unsigned
octet string; duplicates are a protocol error (de-duplicate).

**Signed data (4034 §3.1.8.1, 4035 §5.3.2):** `RRSIG_RDATA (Signature excluded, Signer's Name canonical)` ‖ every
RR in canonical order. Labels rebuilds the owner: equal ⇒ fqdn, fewer ⇒ `*.` + the rightmost `labels` labels,
more ⇒ invalid RRSIG.

**Labels / wildcards (§3.1.3, 4035 §2.2, §5.3.4):** counts neither the root label nor a leftmost `*`:
`www.example.com.`→3, `*.example.com.`→2, root→0. A wildcard answer carries the **expanded** owner but the RRSIG
exactly as signed (Labels = the wildcard's count), plus the NSEC proving no closer match (4035 §3.1.3.3). Never
re-sign per QNAME.

**NSEC chain (4034 §4.1, 4035 §2.3):**
1. Chain members = every owner name with authoritative data **or** a delegation-point NS RRset. Glue-only
   names are excluded (4034 §4.1.1/§4.1.2). Wildcard owner names are ordinary members, literal `*` (§4.1.3).
2. **Empty non-terminals get no NSEC** — a name that only parents other names has no RRset, and the signer MUST
   NOT create NSEC/RRSIG for nodes that were not an RRset owner (4035 §2.3); ENTs are covered by the span of the
   preceding NSEC.
3. Canonical sort; `Next Domain Name` = next member, wrapping to the apex.
4. Bitmap = every type at the owner **plus RRSIG and NSEC** (4035 §2.3); pseudo-types (OPT 41, TKEY 249, TSIG 250,
   ANY 255) MUST be clear (§4.1.2); no empty windows, no trailing zero octets. Encoding `(window u8 | length u8
   1..32 | octets)+`, windows ascending, bit 0 = MSB, type = window*256+bit; e.g. A, MX, RRSIG, NSEC, TYPE1234 →
   `00 06 40 01 00 00 00 03` then `04 1b` + 26 zero octets + `20`.
5. At a delegation (parent side) set NS, DS (if present), RRSIG, NSEC; clear glue A/AAAA and types below the
   cut (4035 §2.3). NSEC TTL SHOULD be the SOA MINIMUM, and NSEC RRs are signed like any other RRset.

**Denial of existence (4035 §3.1.3):**

| Case | Answer | Authority (DO=1) |
|---|---|---|
| NODATA (name exists, type doesn't) | empty, RCODE 0 | NSEC at QNAME + RRSIG (§3.1.3.1) |
| NXDOMAIN | empty, RCODE 3 | NSEC covering QNAME **and** NSEC covering `*.<closest encloser>`; include once if one NSEC proves both (§3.1.3.2) |
| Wildcard answer | expanded RRset + RRSIGs | NSEC proving no closer match (§3.1.3.3) |
| Wildcard NODATA | empty | NSEC at the wildcard owner (type absent) + NSEC proving no closer match (§3.1.3.4) |
| Referral, DS present | — | NS, then DS + RRSIG (§3.1.4) |
| Referral, no DS | — | NS, then NSEC proving no DS + RRSIG; NS **before** NSEC (§3.1.4) |
| DS query at cut, we serve only the child | authoritative NODATA (§3.1.4.1) | NSEC at apex + RRSIG |
Covering NSEC = the chain member `M` immediately preceding the missing name `N` in canonical order (§3.1.3.5);
for the wildcard proof the missing name is `*.<closest encloser>`, the closest encloser being the deepest existing
ancestor of QNAME. Add the SOA in authority for negative caching (RFC 2308). Quirk: an **ENT** query is answered
as **NXDOMAIN** with the covering NSEC — 4035 §3.1.3.2 explicitly includes that case, as no NSEC can live at the
ENT itself.

**DO-bit gating (4035 §3, §3.1.1, §3.1.2):** no OPT or DO=0 ⇒ treat RRSIG/DNSKEY/NSEC as ordinary types: add
nothing automatically, answer only explicit queries, never attach RRSIGs. DO=1 + signed zone ⇒ RRSIGs for answer
and authority RRsets, NSEC per the table above, DS or DS-denying NSEC in referrals, and the apex DNSKEY MAY be
added to the additional section of an apex SOA/NS answer at lowest priority (never a TC reason). Explicit
QTYPE=RRSIG/NSEC/DNSKEY/DS queries are answered regardless of DO (RRSIG sets are not RRsets and QTYPE=RRSIG
behavior is unspecified — pick one policy; RFC 8482 §7).

**AD / CD (§3, §3.1.6):** AD in a query is ignored; a response MUST NOT set AD unless every answer/authority RRset
is authentic, the zone arrived by secure means, **and** it is explicitly configured — default 0. CD: §3 says copy,
§3.1.6 says an authoritative server SHOULD clear it ⇒ we **clear** (§3.2.2's MUST-copy is for recursive servers);
we never validate while answering.

**Delegation / glue / DS (4035 §2.2, §2.4, §2.6, §3.1.4, §3.1.5):** delegation NS RRsets and glue address RRsets
in the parent MUST NOT be signed; no NSEC/RRSIG for glue-only names. Parent and child each have their own NSEC at
a cut (the child's apex NSEC has the SOA bit, the parent's never does). DS lives only in the parent, MUST be
signed, MUST NOT appear at an apex, SHOULD share the delegating NS TTL, and must reference a DNSKEY with the Zone
Key flag (4034 §5.2). AXFR is unchanged: DS travels with the parent's transfer, NSEC/RRSIG with the zone that is
authoritative for them — never strip DNSSEC records from an AXFR (§3.1.5).

## 4. RFC 8482 — minimal ANY

For `QTYPE=ANY`, QCLASS=IN, existing QNAME; otherwise standard algorithms apply (ANY for a nonexistent name is a
normal NXDOMAIN). Modes (§4): (a) one RRset/small subset, (b) synthesized HINFO, (c) best-guess subset (often
CNAME, MX, A, AAAA).
* **Subset (§4.1):** MAY return a single RRset, SHOULD keep the subset small to limit amplification; nothing
  signals that the answer is incomplete. **Do not set TC** (§7: SHOULD NOT) — TC claims truncation and pushes
  clients to retry over TCP for a complete answer.
* **HINFO (§4.2):** only if **no CNAME** exists at QNAME; one HINFO, CPU = `RFC8482`, OS = empty, operator-chosen
  TTL. It masks any real HINFO at that name (§6), so avoid it in zones that publish HINFO.
* **DO bit (§4.1–4.3):** DO=1 + signed zone ⇒ a valid RRSIG over the answer RRsets (or the authority, if the
  answer is empty) **MUST** be present; DO=0 ⇒ omit it. HINFO synthesis needs **online signing** per QNAME — an
  offline-signed zone should prefer subset mode, which reuses existing RRSIGs.
* Transport-specific behavior is allowed (§4.4); RRSIG queries are out of scope (§7).

## 5. Compliance checklist

**EDNS(0)** — OPT with NAME=0 only (§6.1.2) · exactly one OPT, additional section only, ≥2 ⇒ FORMERR (§6.1.1) ·
OPT precedes TSIG, TSIG still last · RCODE split/joined as `ext<<4 | hdr` (§6.1.3) · VERSION>0 ⇒ BADVERS(16)
with our VERSION and no data · no OPT in query ⇒ no OPT out and a 512 limit (§7) · `max(512, CLASS)` floor plus
our own cap (§6.2.3–6.2.5) · unknown options ignored, not echoed (§6.1.2) · malformed OPT ⇒ FORMERR **with** an
OPT (§7) · truncated EDNS reply keeps the OPT · Z=0 out, ignored in (§6.1.4) · AXFR: OPT in the first response,
TSIG last (RFC 5936 §2.2.5).

**TSIG** — type 250, CLASS ANY, TTL 0, Original ID = request ID (§4.2) · digest order `[req MAC] ‖ msg(no TSIG,
ARCOUNT−1, ID:=OriginalID) ‖ variables` (§4.3) · variables order NAME, CLASS, TTL, ALG, TimeSigned, Fudge, Error,
OtherLen, OtherData · canonical (lowercase, uncompressed) key/alg names · check key→MAC→time→truncation (§5.2) ·
u48 time with ±Fudge (§5.2.3) · BADKEY/BADSIG unsigned, BADTIME/BADTRUNC signed (§5.2.1–5.2.4, §5.3.2) · BADTIME
echoes the client time and puts the server time in 6-byte Other Data · MAC floor `max(10, hash/2)`, oversize ⇒
FORMERR (§5.2.2.1) · reply MAC ≥ request MAC (§7) · TSIG cannot fit ⇒ question + TSIG + TC=1, RCODE 0 (§5.3) ·
AXFR prior-MAC chaining with timers only, every message signed (§5.3.1) · SHA-256 and SHA-1 implemented, MD5
refused (§6).

**DNSSEC** — DNSKEY Protocol=3, reserved flag bits 0, Zone Key bit enforced (4034 §2.1) · RRSIG TTL == RRset
TTL == Original TTL, Signer's Name uncompressed (§3, §3.1.7) · serial-number arithmetic for
inception/expiration (§3.1.5) · key tag per App. B (not the IP checksum) · canonical name order + RR form +
RDATA sort before signing (§6.1–6.3) · ECDSA 64-byte fixed `r‖s`, not DER · Labels excludes root and `*`;
wildcard answers reuse the original RRSIG (§3.1.3) · NSEC at every authoritative name and delegation, none for
glue-only names or ENTs (4035 §2.3) · bitmap contains RRSIG+NSEC, excludes pseudo-types, no trailing zeros
(§4.1.2) · NSEC TTL = SOA MINIMUM · NXDOMAIN ⇒ QNAME + wildcard proofs (§3.1.3.2) · NODATA ⇒ NSEC at QNAME
(§3.1.3.1) · wildcard NODATA ⇒ two proofs (§3.1.3.4) · referral NS before DS-or-NSEC, NSEC proves absent DS
(§3.1.4) · delegation NS and glue never signed (4035 §2.2) · DO=0 ⇒ no automatic DNSSEC records (4035 §3) ·
missing RRSIG on an answer/authority RRset ⇒ TC (§3.1.1) · AD=0 by default, CD cleared (§3.1.6).

**ANY (8482)** — documented mode, no TC (§4, §7) · DO=1 + signed ⇒ valid RRSIG in answer or authority (§4.1,
§4.2) · HINFO mode skipped when a CNAME exists at QNAME (§4.2).

## 6. Test commands

```sh
S=127.0.0.1; P=5353; Z=example.com
dig @$S -p $P +norec $Z SOA +dnssec                    # OPT in reply, DO=1, RRSIG present
dig @$S -p $P +norec $Z SOA +noedns                    # no OPT in reply, 512 limit
dig @$S -p $P +norec $Z SOA +edns=1                    # expect status: BADVERS, version 0
dig @$S -p $P +norec $Z DNSKEY +bufsize=512 +ignore    # tc flag, no TCP retry
dig @$S -p $P +norec +dnssec $Z NOSUCH A               # NXDOMAIN + NSEC(QNAME) + NSEC(wildcard)
dig @$S -p $P +norec +dnssec $Z A                      # NODATA at apex -> NSEC at apex
dig @$S -p $P +norec +dnssec sub.$Z A                  # referral: NS, then DS|NSEC, all with RRSIG
dig @$S -p $P +norec +dnssec $Z ANY                    # minimal ANY: RRSIG present, no tc
dig @$S -p $P +norec $Z ANY                            # same with DO=0: no RRSIGs
dig @$S -p $P +norec +dnssec '*.wild.'$Z A             # wildcard: expanded owner, Labels check
dig @$S -p $P -y hmac-sha256:axfr-key.:<b64secret> $Z AXFR            # signed, TSIG last
dig @$S -p $P -y hmac-sha256:axfr-key.:<wrongsecret> $Z AXFR +tcp     # NOTAUTH / BADSIG
dig @$S -p $P -y hmac-sha1:axfr-key.:<b64secret> $Z AXFR +tcp         # SHA-1 still accepted
# MAC by hand (assemble tsig_input.bin first), and RRSIG verification of signed_data.bin
openssl dgst -sha256 -mac HMAC -macopt hexkey:$KEY_HEX -binary < tsig_input.bin | xxd
openssl pkeyutl -verify -pubin -inkey ed25519.pem -rawin -in signed_data.bin -sigfile sig.raw   # alg 15
openssl dgst -sha256 -verify ecdsa.pem -signature sig.der signed_data.bin                       # alg 13 (DER!)
# key tag + DS digest (RFC 4034 App. B / §5.1.4), pub.b64 = the DNSKEY public key field
python3 -c "import hashlib,struct,base64,sys;p=base64.b64decode(sys.argv[1]);r=struct.pack('!HBB',257,3,13)+p;a=sum((b<<8) if i%2==0 else b for i,b in enumerate(r));a+=(a>>16)&0xFFFF;print(a&0xFFFF, hashlib.sha256(b'\x07example\x03com\x00'+r).hexdigest().upper())" "$(dig @$S -p $P +short $Z DNSKEY | awk '{print $4}')"
dnssec-verify -o $Z $Z.zone   # end-to-end signer check, if BIND tools exist
```
Multiple OPT must yield FORMERR; dig has no switch for it, so inject raw bytes:
```python
import socket, struct
q = b'\x07example\x03com\x00'
h = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 2)            # ARCOUNT = 2
opt = b'\x00' + struct.pack('!HHIH', 41, 1232, 0, 0)              # two identical OPT RRs
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(h + q + struct.pack('!HH', 1, 1) + opt + opt, ('127.0.0.1', 5353))
print('RCODE', struct.unpack('!H', s.recv(4096)[2:4])[0] & 0xF)  # expect 1 = FORMERR
```
**Ambiguities resolved:** CD cleared on authoritative replies (4035 §3 vs §3.1.6) · FORMERR for multiple OPT
still carries one OPT · ENT ⇒ NXDOMAIN + covering NSEC (§3.1.3.2), not NODATA · ANY uses subset mode unless
online signing exists · advertise 1232, accept up to 4096.
