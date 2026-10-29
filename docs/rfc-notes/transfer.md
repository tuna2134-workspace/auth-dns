# Zone Transfer and NOTIFY — RFC notes for an authoritative server (server side)

Sources: **RFC 5936** (AXFR), **rfc1995** (IXFR), **rfc1982** (serial arithmetic),
**rfc1996** (NOTIFY), **rfc7766** (DNS over TCP), **rfc1035** §4.2.2/§6.3 (framing, mid-transfer
change), **rfc8945** §5.3.1 (TSIG over multi-message answers), **rfc6604** (see §0). Numbers are RFC
section numbers, not file lines.

## 0. Caveat: RFC 6604 is not a TCP document

RFC 6604 is *"xNAME RCODE Clarification"*: nothing about the 2-octet length prefix, pipelining,
connection reuse, or idle timeouts — those are **RFC 7766** (obsoletes RFC 5966). 6604 bears on this
work only in §2.1, restating RFC 1035's AA rule (AA reflects authority for the zone of the *first* owner
name in the answer), and §3, which fixes RCODE from the *final* cycle of an xNAME chain. Neither is
transfer-specific: an AXFR/IXFR response is not a redirected query. Do not cite 6604 as a transport source.

## 1. AXFR over TCP (RFC 5936)

**1.1 Session shape (§2).** "An AXFR session consists of an AXFR query message and the sequence of AXFR
response messages returned for it." TCP only — "the definition of AXFR is restricted to TCP". The response
is "a series (which could be a series of length 1) of DNS messages" (§2.2). A connection is **not**
dedicated to one session (§4: "the assumption that a TCP connection is dedicated to a single AXFR session
is incorrect"), so responses must be demultiplexable by message ID.

**1.2 First/last SOA (§2.2, normative).** "the first message MUST begin with the SOA resource record of the
zone, and the last message MUST conclude with the same SOA resource record. Intermediate messages MUST NOT
contain the SOA resource record." So the apex SOA appears exactly twice — first RR of the first message,
last RR of the last — never in the middle. Non-SOA order is free ("clients MUST accept any ordering and
grouping of the non-SOA RRs"), "Each RR SHOULD be transmitted only once", and clients ignore duplicates.
Snapshot semantics (RFC 1035 §6.3): a master should "continue to send the old version if possible", must
"never send part of one version and part of another", and otherwise "reset the connection" ⇒ pin one
version per session.

**1.3 Question section (§2.2.2; §2.2.1 QDCOUNT).** "In the first response message, this section MUST be
copied from the query. In subsequent messages, this section MAY be copied from the query, or it MAY be
empty." QDCOUNT "MUST be 1 in the first message; MUST be 0 or 1 in all following messages; MUST be 1 if
RCODE indicates an error". Simplest compliant choice: copy the question into every message.

**1.4 Framing and max size (§2; RFC 1035 §4.2.2).** Every message is preceded by a 2-octet big-endian
length excluding the prefix, giving "a limit of 65535 octets. This limit is not changed by EDNS0" (§2).
Pack "up to the largest number that will fit within a DNS message" (§2.2); TC is meaningless here (§1.6).
Legacy single-RR-per-message clients exist: §2.2/§7.1 allow a per-client **configuration** switch ("the
default SHOULD be to use multiple records per message"); there is "no standard way to automatically detect
such clients".

**1.5 ID handling (§2.2.1 note a).** "New DNS servers MUST set this field to the value of the AXFR query ID
in each AXFR response message for the session." Not just the first — *each*. That is what lets a client
keep other queries in flight and lets the server interleave sessions.

**1.6 Header bits (§2.2.1).** QR=1, OPCODE=0, NSCOUNT "MUST be 0", ARCOUNT = Additional RRs present,
ANCOUNT = Answer RRs. TC "MUST be 0 (Not truncated)"; §2: "the TC (truncation) bit is never set by an AXFR
server nor considered/read by an AXFR client." AA: "If the RCODE is 0 (no error), then the AA bit MUST be
1. For any other value of RCODE, the AA bit MUST be set according to the rules for that error code. If in
doubt, it is RECOMMENDED that it be set to 1." RD: copy request or 0; RA: 0; Z/AD/CD: 0.

**1.7 Empty zone / only an SOA.** Not named in the RFC but follows from §2.2 (series may have length 1 and
must both begin and end with the same SOA): **one message, ANCOUNT=2, both RRs the identical SOA**. Never a
zero-answer AXFR, never the SOA once.

**1.8 UDP AXFR.** §4.2: "this document does not update RFC 1035 in this respect: AXFR sessions over UDP
transport are not defined." RFC 5936 defines **no** UDP response for QTYPE=252; policy is local (drop, or
error/TC so a prober retries over TCP). Never serve zone data over UDP.

**1.9 Errors and aborts (§2.2, §2.3, §4.1.2).** On failure "the AXFR server sends a single DNS message ...
with the response code set to the appropriate value ... Such a message terminates the AXFR session; it MUST
contain a copy of the Question section from the AXFR query ... but the inclusion of the terminating SOA
resource record is not necessary"; it may first send several good messages. Not authoritative ⇒ "the server
SHOULD set the value to NotAuth(9)" (§2.2.1 note e); malformed query/bad OPT ⇒ FormErr(1); policy denial has
no RFC-mandated RCODE (REFUSED(5) is practice — §5 only says implementations SHOULD be able to restrict
AXFR). "An isolated request for a zone not on the AXFR server SHOULD receive a response with the appropriate
response code and not see the connection broken" (§4.1.2); aborts are for abuse only (§2.3). On peer close
"the AXFR server MUST cancel all AXFR sessions in place", and RFC 7766 §6.2.4 forbids sending the remaining
responses.

**1.10 TSIG.** §2.1.5 allows one TSIG (or SIG(0)) in the query Additional section; §2.2.5: if the server
supports the method "it MUST place the corresponding resource record into the AXFR response message(s),
according to the rules specified for that method." RFC 8945 §5.3.1: "The TSIG MUST be included on all DNS
messages in the response. For backward compatibility, a client that receives DNS messages and verifies TSIG
MUST accept up to 99 intermediary messages without a TSIG and MUST verify that both the first and last
message contain a TSIG." Digest for messages 2..n = Prior MAC (running) + all messages since the last TSIG +
TSIG Timers only. TSIG failure ⇒ close the connection; §5/§6 recommend TSIG/SIG(0) for authorization.

**1.11 Zone contents (§3, brief).** Cut-point NS (§3.2), glue (§3.3) and occluded names (§3.5) MUST all be
included as registered with the zone; compression SHOULD be case-preserving (§3.4), RDATA per RFC 3597 §4.

## 2. IXFR (RFC 1995) and serial arithmetic (RFC 1982)

**2.1 Request (§3).** "The IXFR query packet format is the same as that of a normal DNS query, but with the
query type being IXFR and the authority section containing the SOA record of client's version of the zone."
QTYPE=IXFR=251, QDCOUNT=1, ANCOUNT=0, NSCOUNT=1. Only the client SOA's serial matters. No SOA in authority
⇒ RFC silent; treat as unknown version and take the full-zone path (§6 forbids erroring).

**2.2 Up-to-date (§2).** "If an IXFR query with the same or newer version number than that of the server is
received, it is replied to with a single SOA record of the server's current version, just as in AXFR." One
answer RR, the current SOA.

**2.3 Incremental (§4).** "one or more difference sequences is returned. The list of difference sequences is
preceded and followed by a copy of the server's current version of the SOA."
- "The first RR of the deleted RRs is the older SOA RR and the first RR of the added RRs is the newer SOA
  RR." "The sequences of differential information are ordered oldest first newest last."
- "RRs in the incremental transfer messages may be partial" — ship only the changed RR of an RRset; "Modification
  of an RR is performed first by removing the original RR and then adding the modified one."
- "An incremental response ... begins with two SOA RRs, the server's current SOA followed by the SOA of the
  client's version which is about to be replaced."
- Over TCP the stream may span messages; keep the current SOA first and last, question/ID as §1.3/§1.5.

RFC 1995 §7 example, client serial 1 → server serial 3 (verbatim Answer section):

```
JAIN.AD.JP.         IN SOA serial=3     <- server's current SOA (prefix)
JAIN.AD.JP.         IN SOA serial=1     <- client's version, start of deleted RRs
NEZU.JAIN.AD.JP.    IN A   133.69.136.5 <- deleted
JAIN.AD.JP.         IN SOA serial=2     <- newer SOA, start of added RRs
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.4 <- added
JAIN-BB.JAIN.AD.JP. IN A   192.41.197.2
JAIN.AD.JP.         IN SOA serial=2     <- next delta: deletion begins with old SOA
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.4 <- deleted
JAIN.AD.JP.         IN SOA serial=3
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.3 <- added
JAIN.AD.JP.         IN SOA serial=3     <- server's current SOA (suffix)
```

**2.4 Fallback to full zone (§4, §6).** "If incremental zone transfer is not available, the entire zone is
returned. The first and the last RR of the response is the SOA record of the zone. I.e. the behavior is the
same as an AXFR response except the query type is IXFR." §6: "IXFR servers ... should not flag an error even
if it receives a client's IXFR request with a unknown version number and should, instead, attempt to perform
a full zone transfer." ⇒ An IXFR answer is (a) one SOA, (b) deltas bracketed by the current SOA, or (c) a
full zone bracketed by the current SOA.

**2.5 UDP and TC (§2).** "If an IXFR query is via UDP, the IXFR server may attempt to reply using UDP if the
entire response can be contained in a single DNS packet. If the UDP reply does not fit, the query is
responded to with a single SOA record of the server's current version to inform the client that a TCP query
should be initiated." This is **not** a TC mechanism — §7's final example shows Answer = one SOA, no TC, and
RFC 5936 §2 separately forbids TC on AXFR. Do not depend on TC for IXFR; the single-SOA answer is the signal
(setting TC too is common practice but unspecified). §2 also asks for UDP checksums.

**2.6 Serial arithmetic (RFC 1982, SERIAL_BITS=32).** §7: the serial is a 32-bit unsigned value and "the
maximum defined increment is 2147483647 (2^31 - 1)"; §3.1: `s' = (s + n) mod 2^32` for `n` in `[0 .. 2^31-1]`.
§3.2: `s1 < s2` iff `s1 != s2` and `(i1 < i2 and i2-i1 < 2^31) or (i1 > i2 and i1-i2 > 2^31)`; `s1 > s2` iff
`s1 != s2` and `(i1 < i2 and i2-i1 > 2^31) or (i1 > i2 and i1-i2 < 2^31)`. Exact-half differences (`2^31`)
are **undefined** — "s1 is neither greater than, nor less than, s2" — so never emit them and pick any
behaviour if seen. Must wrap, not saturate: `(i32)(s_client - s_server) < 0` ⇒ client older.

**2.7 Journal (derived; 1995 never uses the word).** §2 sets persistence order: "When a zone has been
updated, it should be saved in stable storage before the new version is used to respond to IXFR (or AXFR)
queries." §5 purging: "Information about older versions should be purged if the total length of an IXFR
response would be longer than that of an AXFR response"; "Information older than the SOA expire period may
also be purged." §6 condensation is optional and undetectable by clients. Minimum: per-delta `{from_serial,
to_serial, deleted[], added[]}` with SOAs in the lists, contiguous, retrievable by from_serial; purge whole
tail ranges, never leave holes.

**2.8 Is the client's serial covered?** With `s_c` = client serial, `s_s` = current: (1) `s_c == s_s` → single
current SOA; (2) `s_c > s_s` → the same single-SOA answer ("the same or newer version number than that of
the server", §2), never AXFR; (3) `s_c < s_s` with a contiguous journal chain `s_c`→`s_s` → incremental,
oldest delta first, bracketed by `s_s`; (4) `s_c < s_s` but a delta missing/purged → full zone in IXFR shape
(§2.4). Never answer 1–4 with an error.

## 3. TCP transport (RFC 7766; framing from RFC 1035 §4.2.2)

- **Required (§5).** "Authoritative server implementations MUST support TCP so that they do not limit the
  size of responses to what fits in a single UDP packet"; "all recursive and authoritative servers MUST send
  responses using the same transport as the query arrived on. In the case of TCP, this MUST also be the same
  connection."
- **Length prefix (§8).** "The message is prefixed with a two byte length field which gives the message
  length, excluding the two byte length field" (max 65535); pass prefix and message "to the TCP layer at the
  same time".
- **Partial reads (§8).** "DNS servers MUST NOT close a connection simply because the first 'read' from the
  TCP layer does not contain the entire DNS message, and servers SHOULD apply the connection timeouts as
  specified in Section 6.2.3." Accumulate until the frame is complete, including a length field split across
  reads; a zero length prefix is malformed ⇒ close.
- **Reuse (§6.2.1).** "both clients and servers SHOULD support connection reuse by sending multiple queries
  and responses over a single persistent TCP connection"; clients "MUST NOT reuse the DNS Message ID of an
  in-flight query". AXFR side (5936 §4.1.2): "An AXFR server MUST be able to handle multiple AXFR sessions on
  a single TCP connection, as well as to handle other query/response transactions over it."
- **Pipelining (§6.2.1.1).** "DNS servers ... MUST expect to receive pipelined queries. The server SHOULD
  process TCP queries concurrently ... SHOULD answer all pipelined queries, even if they are received in
  quick succession." Keep reading while an AXFR streams.
- **Ordering (§7).** "Authoritative servers and recursive resolvers are RECOMMENDED to support the preparing
  of responses in parallel and sending them out of order" — in-order is legal too, but IDs must be right
  either way, since clients match on Message ID (+ QNAME/QCLASS/QTYPE when a question is present).
- **Idle timeouts (§6.2.3).** "it is RECOMMENDED that the default server application-level idle period be on
  the order of seconds"; a few seconds "is advisable ... to support those clients that expect the SOA and
  AXFR request sequence to be made on a single connection"; "servers SHOULD reset the idle timeout on the
  receipt of a full DNS message, rather than on receipt of any part of a DNS message" (slow-read defence).
  RFC 1035 §4.2.2's ~2-minute figure is superseded.
- **Limits and teardown (§6.2.2, §6.2.4).** "servers MAY impose limits on the number of concurrent TCP
  connections being handled for any particular client IP address or subnet ... SHOULD be much looser than
  the client guidelines"; clients normally close idle connections, and responses buffered for a closed
  session are discarded, never retried.

## 4. NOTIFY (RFC 1996) — enough to decide

Request: opcode **NOTIFY (4)**, QR=0, QDCOUNT=1, QNAME=zone, QCLASS=zone class, QTYPE=SOA ("The only
defined NOTIFY event at this time is that the SOA RR has changed"), flags AA, RCODE=NOERROR (§4.5). "Fields
not otherwise described herein are to be filled with binary zero (0), and implementations must ignore all
messages for which this is not the case" (§3.2). AUCOUNT/ADCOUNT should be 0, but implementations "must
ignore these sections, but not the entire message, if AUCOUNT>0 and/or ADCOUNT>0" (§3.9). Response (§4.7):
same ID, opcode NOTIFY, QR AA, NOERROR, QDCOUNT=1, same QNAME/QCLASS/QTYPE — "identical to the NOTIFY
request, except that the QR bit is also set. The query ID of the response must be the same as was received
in the request." Transport: UDP unless TCP is warranted (§3.4), retried (defaults 60 s, 5 retransmissions),
response clears the retry queue (§3.3, §3.6).

**If we receive NOTIFY** (only meaningful once we consume zones as a secondary; a primary-only server is
never in a Notify Set): accept only from a configured master — "If a slave receives a NOTIFY request from a
host that is not a known master for the zone containing the QNAME, it should ignore the request and produce
an error message in its operations log" (§3.10); treat QTYPE=SOA as REFRESH expiry (§3.11), querying **that**
master for the SOA and transferring if the serial advanced; suppress duplicates for the same
<QNAME,QCLASS,QTYPE> until the triggered transaction completes (§4.4); NOTIMP if unimplemented (§3.12). An
answer section is an untrusted hint — "In no case shall the answer section of a NOTIFY request be used to
update a slave's local data" (§3.8).

**Decision.** NOTIFY is small (parse opcode 4, authorize by master address, echo the question with QR|AA,
enqueue a refresh) but useless while this server is primary-only. Order: AXFR + TCP framing → IXFR →
NOTIFY when the secondary role lands; meanwhile return NOTIMP (RCODE 4), not FORMERR.

## 5. Compliance checklist and tests

`127.0.0.1:5300`, zone `example.test` (serial 3), journal holds serial 1, `nosuch.test` unconfigured.
Wire-level rows use this harness; `tcpdump -i lo -n -X 'tcp port 5300'` shows the prefixes.

```python
# wire.py NAME [--split-prefix|--split-msg|--idle]  — dumps one AXFR message stream
import socket, struct, sys, time
name, mode = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
q = struct.pack("!HHHHHH", 0x1234, 0, 1, 0, 0, 0)
q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) + b"\0" + struct.pack("!HH", 252, 1)
m = struct.pack("!H", len(q)) + q
s = socket.create_connection(("127.0.0.1", 5300))
if mode == "--split-prefix": s.sendall(m[:1]); time.sleep(1); s.sendall(m[1:])
elif mode == "--split-msg":  s.sendall(m[:12]); time.sleep(1); s.sendall(m[12:])
else: s.sendall(m)
while h := s.recv(2):
    n = struct.unpack("!H", h)[0]; b = b""
    while len(b) < n: b += s.recv(n - len(b))
    i, f, qd, an, ns, ar = struct.unpack("!HHHHHH", b[:12])
    print(f"id={i} aa={(f>>10)&1} tc={(f>>9)&1} qd={qd} an={an} ns={ns} ar={ar} len={n}")
```

| # | Requirement (source) | Test |
|---|---|---|
| 1 | AXFR over TCP only; UDP undefined (5936 §4.2) | `dig @127.0.0.1 -p 5300 +notcp AXFR example.test` → no zone data |
| 2 | First RR apex SOA, last RR same SOA, none between (5936 §2.2) | `dig @127.0.0.1 -p 5300 AXFR example.test +noall +answer \| sed -n '1p;$p'` |
| 3 | Each non-SOA RR once (5936 §2.2) | `dig ... AXFR example.test +noall +answer \| sort \| uniq -d` → empty |
| 4 | Question copied first, 0 or 1 later (5936 §2.2.2) | `wire.py example.test` → qd=1 then 0/1 |
| 5 | Same ID in every message (5936 §2.2.1 note a) | `dig +qid=4660 @127.0.0.1 -p 5300 AXFR example.test` → all ids 4660 |
| 6 | AA=1 when RCODE=0 (5936 §2.2.1 note b) | `dig @127.0.0.1 -p 5300 AXFR example.test +noall +comments \| grep -m1 flags` → `qr aa` |
| 7 | TC=0, NSCOUNT=0, ARCOUNT accurate (5936 §2.2.1) | `wire.py example.test` → tc=0 ns=0 |
| 8 | Multi-message ≤65535; single-RR mode config-only (5936 §2, §7.1) | `wire.py` on a multi-MB zone → several lines, max len 65535; with the flag an=1, SOA still first/last |
| 9 | SOA-only zone ⇒ one message, SOA twice (5936 §2.2) | `dig @127.0.0.1 -p 5300 AXFR empty.test +noall +answer \| grep -c SOA` → 2 |
| 10 | Not authoritative ⇒ NotAuth(9), conn kept (5936 §2.2.1e, §4.1.2) | `dig +tcp ... AXFR nosuch.test` → NOTAUTH; next query on that conn works |
| 11 | Error = one message, question copied, session ends (5936 §2.2) | `wire.py nosuch.test` → exactly 1 line, qd=1 |
| 12 | Glue, cut-point NS, occluded names included (5936 §3.2–3.5) | `dig ... AXFR example.test +noall +answer \| grep -cE ' (NS\|A\|AAAA)\s'` vs zone file |
| 13 | IXFR deltas, current SOA prefix and suffix (1995 §3/§4) | `dig @127.0.0.1 -p 5300 ixfr=1 example.test +noall +answer` → 3, 1, dels/adds, 3 |
| 14 | Same-or-newer client serial ⇒ single SOA (1995 §2; 1982 §3.2) | `ixfr=3` → 1 RR; `ixfr=4` → 1 RR (not AXFR) |
| 15 | Unknown/purged serial ⇒ full zone, RCODE 0 (1995 §4/§6) | `dig ... ixfr=999 example.test +noall +answer \| grep -c SOA` → 2 |
| 16 | IXFR UDP: fits ⇒ normal, else one SOA, no TC reliance (1995 §2) | `dig @127.0.0.1 -p 5300 +notcp ixfr=1 example.test` |
| 17 | Deltas oldest-first, deletion before addition (1995 §4) | `dig ... ixfr=1 +noall +answer` → SOA serials ascend, old SOA first |
| 18 | 2-octet prefix, prefix+message one write (1035 §4.2.2; 7766 §8) | `tcpdump -i lo -n -X 'tcp port 5300'` during `dig +tcp` |
| 19 | Split prefix and split message tolerated (7766 §8) | `wire.py example.test --split-prefix` and `--split-msg` |
| 20 | Multiple queries per connection (7766 §6.2.1) | `dig +keepopen @127.0.0.1 -p 5300 example.test A example.test SOA` |
| 21 | Pipelining answered, order free (7766 §6.2.1.1, §7) | two queries back-to-back before any read |
| 22 | Idle close in seconds; timer resets on full message (7766 §6.2.3) | `wire.py example.test --idle`, time the close; slow-read must not extend it |
| 23 | Per-IP cap enforced, no crash; reply on same 4-tuple (7766 §6.2.2, §5) | N+1 parallel `dig +tcp` under tcpdump |
| 24 | NOTIFY from master answered, else NOTIMP (1996 §3.12/§4.7) | `dig @127.0.0.1 -p 5300 +opcode=4 example.test SOA` → NOTIMP or `qr aa` echo, same ID |
| 25 | NOTIFY from non-master ignored + logged (1996 §3.10) | same NOTIFY from a second loopback address → silence, log line |
| 26 | TSIG verifies per message; bad key ⇒ unsigned error then close (8945 §5.3.1/§5.3.2) | `dig -y hmac-sha256:xfr:BASE64 ... AXFR`, then a wrong key → BADSIG, no data |
| 27 | AXFR access control, default not open (5936 §5) | AXFR from a non-permitted source → REFUSED |
