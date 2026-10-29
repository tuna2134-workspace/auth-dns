#!/usr/bin/env bash
# End-to-end tests using the same tools an operator would use:
# dig, delv and dnssec-verify.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PORT="${PORT:-15353}"
TMP="$(mktemp -d)"
PID=""
cleanup() {
    if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT

export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$ROOT/.zig-global-cache}"
zig build

cp examples/example.com.zone "$TMP/zone"
cat > "$TMP/auth-dns.conf" <<CONF
options {
    listen 127.0.0.1 port $PORT;
    directory "$TMP";
    max-udp-size 1232;
};
key "xfr.example.com" {
    algorithm hmac-sha256;
    secret "c2VjcmV0MTIzNDU2Nzg5MA==";
};
zone "example.com" {
    type primary;
    file "zone";
    journal "zone.jnl";
    allow-transfer { key "xfr.example.com"; };
    dnssec-key "$ROOT/testdata/test-ecdsa.pem";
    dnssec-flags 257;
};
CONF

fail() { echo "FAIL: $*" >&2; echo "--- server log ---" >&2; cat "$TMP/server.log" >&2 || true; exit 1; }
pass() { echo "PASS: $*"; }

./zig-out/bin/auth-dns serve -c "$TMP/auth-dns.conf" > "$TMP/server.log" 2>&1 &
PID=$!
for _ in $(seq 1 50); do
    if dig @127.0.0.1 -p "$PORT" example.com SOA +time=1 +tries=1 +short >/dev/null 2>&1; then break; fi
    sleep 0.1
done
dig @127.0.0.1 -p "$PORT" example.com SOA +time=1 +tries=1 +short >/dev/null 2>&1 || fail "server did not start"

# --- basic authoritative answers -------------------------------------------
A=$(dig @127.0.0.1 -p "$PORT" www.example.com A +noall +answer +time=2 +tries=1)
echo "$A" | grep -q '192.0.2.1' || fail "A record"
pass "A record"

NX=$(dig @127.0.0.1 -p "$PORT" missing.example.com A +noall +comments +authority +time=2 +tries=1)
echo "$NX" | grep -q 'status: NXDOMAIN' || fail "NXDOMAIN status"
echo "$NX" | grep -q 'SOA' || fail "NXDOMAIN SOA"
pass "NXDOMAIN + SOA"

W=$(dig @127.0.0.1 -p "$PORT" x.wild.example.com A +noall +answer +time=2 +tries=1)
echo "$W" | grep -q '192.0.2.99' || fail "wildcard"
pass "wildcard synthesis"

R=$(dig @127.0.0.1 -p "$PORT" x.sub.example.com A +noall +comments +authority +time=2 +tries=1)
echo "$R" | grep -q 'NS.*sub.example.com' || fail "referral NS"
echo "$R" | grep -q 'flags: qr rd' || fail "referral must not be AA"
pass "delegation referral"

C=$(dig @127.0.0.1 -p "$PORT" alias.example.com A +noall +answer +time=2 +tries=1)
echo "$C" | grep -q 'CNAME' || fail "CNAME"
echo "$C" | grep -q '192.0.2.1' || fail "CNAME target"
pass "CNAME chain"

# --- AXFR / IXFR ------------------------------------------------------------
AXFR=$(dig @127.0.0.1 -p "$PORT" -y hmac-sha256:xfr.example.com:c2VjcmV0MTIzNDU2Nzg5MA== \
    example.com AXFR +time=5 +tries=1 +noall +answer)
[[ $(echo "$AXFR" | grep -c 'IN[[:space:]]*SOA') -eq 2 ]] || fail "AXFR SOA first/last"
pass "AXFR"

# TSIG-protected transfer.
TSIG_AXFR=$(dig @127.0.0.1 -p "$PORT" -y hmac-sha256:xfr.example.com:c2VjcmV0MTIzNDU2Nzg5MA== \
    example.com AXFR +time=5 +tries=1 +noall +answer)
[[ $(echo "$TSIG_AXFR" | wc -l) -gt 10 ]] || fail "TSIG AXFR"
pass "TSIG AXFR"

NO_TSIG=$(dig @127.0.0.1 -p "$PORT" example.com AXFR +time=2 +tries=1 +noall +comments 2>&1 || true)
echo "$NO_TSIG" | grep -q 'REFUSED' || fail "ACL must refuse unsigned AXFR"
pass "AXFR ACL"

# --- DNSSEC ----------------------------------------------------------------
DNSSEC_A=$(dig @127.0.0.1 -p "$PORT" +dnssec www.example.com A +noall +answer +time=2 +tries=1)
echo "$DNSSEC_A" | grep -q 'RRSIG.*A' || fail "A RRSIG"
pass "DNSSEC RRSIG on A"

dig @127.0.0.1 -p "$PORT" +dnssec +noall +answer example.com DNSKEY +time=2 +tries=1 > "$TMP/dnskey"
python3 - "$TMP/dnskey" "$TMP/anchor.conf" <<'PY'
import re, sys
lines = open(sys.argv[1]).read().splitlines()
line = [l for l in lines if 'DNSKEY' in l and re.search(r'\s257\s', l)][0]
parts = line.split()
key = ''.join(parts[7:])
open(sys.argv[2], 'w').write(f'trust-anchors {{ example.com. static-key 257 3 13 "{key}"; }};\n')
PY
delv -a "$TMP/anchor.conf" +root=example.com @127.0.0.1 -p "$PORT" www.example.com A 2>&1 | grep -q 'fully validated' \
    || fail "delv A validation"
pass "delv validates A"

delv -a "$TMP/anchor.conf" +root=example.com @127.0.0.1 -p "$PORT" missing.example.com A 2>&1 | grep -q 'fully validated' \
    || fail "delv NXDOMAIN validation"
pass "delv validates NXDOMAIN"

delv -a "$TMP/anchor.conf" +root=example.com @127.0.0.1 -p "$PORT" www.example.com MX 2>&1 | grep -q 'fully validated' \
    || fail "delv NODATA validation"
pass "delv validates NODATA"

delv -a "$TMP/anchor.conf" +root=example.com @127.0.0.1 -p "$PORT" x.wild.example.com A 2>&1 | grep -q 'fully validated' \
    || fail "delv wildcard validation"
pass "delv validates wildcard"

delv -a "$TMP/anchor.conf" +root=example.com @127.0.0.1 -p "$PORT" x.wild.example.com MX 2>&1 | grep -q 'fully validated' \
    || fail "delv wildcard NODATA validation"
pass "delv validates wildcard NODATA"

delv -a "$TMP/anchor.conf" +root=example.com @127.0.0.1 -p "$PORT" x.cn.example.com A 2>&1 | grep -q 'fully validated' \
    || fail "delv wildcard CNAME validation"
pass "delv validates wildcard CNAME"

dig @127.0.0.1 -p "$PORT" -y hmac-sha256:xfr.example.com:c2VjcmV0MTIzNDU2Nzg5MA== \
    example.com AXFR +time=5 +tries=1 +noall +answer > "$TMP/signed.zone"
dnssec-verify -o example.com "$TMP/signed.zone" > "$TMP/verify.log" 2>&1 || { cat "$TMP/verify.log"; fail "dnssec-verify"; }
pass "dnssec-verify"

# --- IXFR after a SIGHUP reload -------------------------------------------
NEW_ZONE="$TMP/zone.new"
sed -e 's/2024010101/2024010102/' \
    -e 's/^www     IN A    192.0.2.1/www     IN A    192.0.2.2/' \
    examples/example.com.zone > "$NEW_ZONE"
echo 'ixfr-new IN A 192.0.2.200' >> "$NEW_ZONE"
cp "$NEW_ZONE" "$TMP/zone"
kill -HUP "$PID"
sleep 2.2
IXFR=$(dig @127.0.0.1 -p "$PORT" -y hmac-sha256:xfr.example.com:c2VjcmV0MTIzNDU2Nzg5MA== \
    example.com IXFR=2024010101 +time=5 +tries=1 +noall +answer)
echo "$IXFR" | grep -q '2024010101' || fail "IXFR old SOA"
echo "$IXFR" | grep -q '2024010102' || fail "IXFR new SOA"
echo "$IXFR" | grep -q '192.0.2.200' || fail "IXFR addition"
echo "$IXFR" | grep -q '192.0.2.2' || fail "IXFR modification"
pass "IXFR after reload"

echo
echo "all integration tests passed"
