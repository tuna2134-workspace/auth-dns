#!/usr/bin/env bash
# Advanced feature tests: NSEC3, dynamic update, secondary/NOTIFY/IXFR,
# SVCB, TCP idle timeout, rate limiting and signed BADTIME.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TMP="$(mktemp -d "$ROOT/.advanced-test.XXXXXX")"
PIDS=()
LAST_PID=""
cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
    rm -rf "$TMP"
}
trap cleanup EXIT

export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$ROOT/.zig-global-cache}"
zig build

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
wait_port() {
    local port="$1"
    for _ in $(seq 1 50); do
        dig @127.0.0.1 -p "$port" example.com SOA +short +time=1 +tries=1 >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    return 1
}
start() { # port zone extra...
    local port="$1" zone="$2"; shift 2
    ./zig-out/bin/auth-dns serve -l "127.0.0.1:$port" -z "example.com=$zone" "$@" > "$TMP/server-$port.log" 2>&1 &
    LAST_PID=$!
    PIDS+=($LAST_PID)
    wait_port "$port" || { cat "$TMP/server-$port.log" >&2; fail "server on $port did not start"; }
}

# --- NSEC3 -----------------------------------------------------------------
cp examples/example.com.zone "$TMP/nsec3.zone"
start 15400 "$TMP/nsec3.zone" --allow-transfer any \
    --dnssec-key testdata/test-ecdsa.pem --dnssec-nsec3 --dnssec-nsec3-salt aabbccdd
dig @127.0.0.1 -p 15400 +dnssec +noall +answer example.com DNSKEY > "$TMP/dnskey"
python3 - "$TMP/dnskey" "$TMP/anchor" <<'PY'
import re, sys
line=[l for l in open(sys.argv[1]) if 'DNSKEY' in l and re.search(r'\s257\s',l)][0]
p=line.split(); key=''.join(p[7:]); open(sys.argv[2],'w').write(f'trust-anchors {{ example.com. static-key 257 3 13 "{key}"; }};\n')
PY
for q in "www.example.com A" "missing.example.com A" "www.example.com MX" "x.wild.example.com A"; do
    timeout 6 delv -a "$TMP/anchor" +root=example.com @127.0.0.1 -p 15400 $q 2>&1 | grep -q 'fully validated' \
        || fail "NSEC3 delv $q"
done
dig @127.0.0.1 -p 15400 example.com AXFR +time=5 +tries=1 +noall +answer > "$TMP/nsec3.signed"
dnssec-verify -o example.com "$TMP/nsec3.signed" >/dev/null 2>&1 || fail "NSEC3 dnssec-verify"
pass "NSEC3 signing, denial and validation"
kill "$LAST_PID" 2>/dev/null || true

# --- Dynamic Update (signed) ----------------------------------------------
cp examples/example.com.zone "$TMP/update.zone"
start 15401 "$TMP/update.zone" --allow-transfer any --allow-update 127.0.0.1 \
    --dnssec-key testdata/test-ecdsa.pem
cat > "$TMP/nsupdate" <<'UPD'
server 127.0.0.1 15401
zone example.com.
update add dyn.example.com. 60 IN A 192.0.2.123
send
UPD
nsupdate "$TMP/nsupdate" || fail "dynamic update add"
[[ "$(dig @127.0.0.1 -p 15401 +short dyn.example.com A +time=2 +tries=1)" == "192.0.2.123" ]] \
    || fail "dynamic update A"
dig @127.0.0.1 -p 15401 +dnssec +noall +answer dyn.example.com A +time=2 +tries=1 | grep -q RRSIG \
    || fail "dynamic update RRSIG"
dig @127.0.0.1 -p 15401 example.com AXFR +time=5 +tries=1 +noall +answer > "$TMP/update.signed"
dnssec-verify -o example.com "$TMP/update.signed" >/dev/null 2>&1 || fail "dynamic update dnssec-verify"
dig @127.0.0.1 -p 15401 example.com SOA +short +time=2 +tries=1 | grep -q '2024010102' \
    || fail "dynamic update serial"
pass "signed dynamic update, serial bump and re-sign"
kill "$LAST_PID" 2>/dev/null || true

# Restart from the updated file: the update must be persistent.
start 15401 "$TMP/update.zone" --allow-transfer any --dnssec-key testdata/test-ecdsa.pem
[[ "$(dig @127.0.0.1 -p 15401 +short dyn.example.com A +time=2 +tries=1)" == "192.0.2.123" ]] \
    || fail "dynamic update persistence"
pass "dynamic update persistence after restart"
kill "$LAST_PID" 2>/dev/null || true

# --- Primary / secondary, NOTIFY, IXFR ------------------------------------
mkdir -p "$TMP/sec"
cat > "$TMP/sec/primary.zone" <<'ZONE'
$TTL 60
$ORIGIN example.com.
@ SOA ns1 hostmaster ( 200 5 60 60 5 )
@ NS ns1
ns1 A 192.0.2.53
www A 192.0.2.1
ZONE
cat > "$TMP/sec/primary.conf" <<CONF
options { listen 127.0.0.1 port 15402; directory "$TMP/sec"; };
zone "example.com" {
    type primary; file "primary.zone"; allow-transfer { any; };
    also-notify 127.0.0.1:15403;
};
CONF
cat > "$TMP/sec/secondary.conf" <<CONF
options { listen 127.0.0.1 port 15403; directory "$TMP/sec"; };
zone "example.com" {
    type secondary; file "secondary.zone"; primary 127.0.0.1:15402;
    allow-notify { 127.0.0.1; }; allow-transfer { none; };
};
CONF
./zig-out/bin/auth-dns serve -c "$TMP/sec/primary.conf" > "$TMP/sec/primary.log" 2>&1 &
PRIMARY_PID=$!; PIDS+=($PRIMARY_PID)
wait_port 15402 || fail "primary did not start"
./zig-out/bin/auth-dns serve -c "$TMP/sec/secondary.conf" > "$TMP/sec/secondary.log" 2>&1 &
SECONDARY_PID=$!; PIDS+=($SECONDARY_PID)
wait_port 15403 || {
    cat "$TMP/sec/secondary.log" >&2
    fail "secondary did not start"
}
for _ in $(seq 1 40); do
    [[ "$(dig @127.0.0.1 -p 15403 +short example.com SOA +time=1 +tries=1 | awk '{print $3}')" == "200" ]] && break
    sleep 0.2
done
cat > "$TMP/sec/primary.zone" <<'ZONE'
$TTL 60
$ORIGIN example.com.
@ SOA ns1 hostmaster ( 201 5 60 60 5 )
@ NS ns1
ns1 A 192.0.2.53
www A 192.0.2.2
ZONE
kill -HUP "$PRIMARY_PID"
for _ in $(seq 1 40); do
    [[ "$(dig @127.0.0.1 -p 15403 +short example.com SOA +time=1 +tries=1 | awk '{print $3}')" == "201" ]] && break
    sleep 0.2
done
[[ "$(dig @127.0.0.1 -p 15403 +short www.example.com A +time=1 +tries=1)" == "192.0.2.2" ]] \
    || fail "secondary NOTIFY/IXFR"
grep -q "transfer ixfr example.com" "$TMP/sec/primary.log" || fail "secondary did not use IXFR"
pass "secondary AXFR -> NOTIFY -> IXFR"
kill "${PIDS[-1]}" "${PIDS[-2]}" 2>/dev/null || true
unset 'PIDS[-1]' 'PIDS[-2]'

# --- SVCB / HTTPS ----------------------------------------------------------
cat > "$TMP/svcb.zone" <<'ZONE'
$TTL 60
$ORIGIN example.com.
@ SOA ns1 hostmaster ( 1 1h 15m 1w 5m )
@ NS ns1
ns1 A 192.0.2.53
svc HTTPS 1 . alpn=h2,h3 port=443 ipv4hint=192.0.2.1
ZONE
start 15404 "$TMP/svcb.zone" --allow-transfer any
dig @127.0.0.1 -p 15404 svc.example.com HTTPS +time=2 +tries=1 +noall +answer | grep -q 'alpn="h2,h3"' \
    || fail "SVCB/HTTPS presentation"
pass "SVCB/HTTPS text format"
kill "$LAST_PID" 2>/dev/null || true

# --- TCP idle timeout / rate limit ----------------------------------------
start 15405 "$TMP/svcb.zone" --allow-transfer any --tcp-idle 1 --max-tcp-connections 1 --rate-limit 1:1
python3 - <<'PY' || exit 1
import socket, time, struct
# Connection limit: one held connection means the second is closed.
first=socket.create_connection(('127.0.0.1',15405),2); time.sleep(0.2)
second=socket.create_connection(('127.0.0.1',15405),2); second.settimeout(2)
assert second.recv(1)==b'', 'second TCP connection was not limited'
first.close(); time.sleep(0.2)
# Idle timeout.
s=socket.create_connection(('127.0.0.1',15405),2); s.settimeout(3); t=time.time()
assert s.recv(1)==b'', 'idle connection not closed'
print('idle timeout', round(time.time()-t,2))
s.close(); second.close()
# Rate limit: one response out of three rapid queries.
def q(i):
    nm=b'\x03svc\x07example\x03com\x00'
    return struct.pack('>HHHHHH',i,0x0100,1,0,0,0)+nm+struct.pack('>HH',64,1)
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(0.4); ok=0
for i in range(3):
    u.sendto(q(i),('127.0.0.1',15405))
    try: u.recvfrom(4096); ok+=1
    except Exception: pass
assert ok==1, f'expected 1 rate-limited response, got {ok}'
print('rate limit',ok)
PY
pass "TCP idle timeout and per-source rate limit"
kill "$LAST_PID" 2>/dev/null || true

# --- TSIG BADTIME ----------------------------------------------------------
start 15406 "$TMP/svcb.zone" --allow-transfer any --tsig xfr.example.com:hmac-sha256:c2VjcmV0MTIzNDU2Nzg5MA==
python3 - <<'PY' || exit 1
import struct, socket, hmac, hashlib, time
def wn(s):
    return b''.join(bytes([len(x)])+x.encode() for x in s.rstrip('.').split('.'))+b'\0'
key=wn('xfr.example.com'); alg=wn('hmac-sha256.'); secret=b'secret1234567890'
qid=0x4242; q=wn('www.example.com')
msg=struct.pack('>HHHHHH',qid,0x0100,1,0,0,0)+q+struct.pack('>HH',1,1)
ts=int(time.time())-3600; fudge=300
vars=key+struct.pack('>HI',255,0)+alg+ts.to_bytes(6,'big')+struct.pack('>HHH',fudge,0,0)
mac=hmac.new(secret,msg+vars,hashlib.sha256).digest()
rdata=alg+ts.to_bytes(6,'big')+struct.pack('>HH',fudge,len(mac))+mac+struct.pack('>HHH',qid,0,0)
pkt=msg+key+struct.pack('>HHIH',250,255,0,len(rdata))+rdata
pkt=pkt[:10]+struct.pack('>H',1)+pkt[12:]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(pkt,('127.0.0.1',15406)); resp,_=s.recvfrom(4096)
assert resp[3]&0xf==9, 'BADTIME must be NOTAUTH'
off=12
while resp[off]!=0: off+=1+resp[off]
off+=5
assert resp[off:off+len(key)]==key
p=off+len(key); rtype=struct.unpack('>H',resp[p:p+2])[0]; assert rtype==250
rdlen=struct.unpack('>H',resp[p+8:p+10])[0]; body=resp[p+10:p+10+rdlen]
o=0
while body[o]!=0: o+=1+body[o]
o+=1; rts=int.from_bytes(body[o:o+6],'big'); o+=6
rfudge,rmaclen=struct.unpack('>HH',body[o:o+4]); o+=4
rmac=body[o:o+rmaclen]; o+=rmaclen
rorig,err,olen=struct.unpack('>HHH',body[o:o+6]); o+=6
other=body[o:o+olen]
assert err==18 and rts==ts and olen==6, 'BADTIME fields'
unsigned=bytearray(resp[:off]); unsigned[10:12]=struct.pack('>H',0)
vars2=key+struct.pack('>HI',255,0)+alg+rts.to_bytes(6,'big')+struct.pack('>HHH',rfudge,err,olen)+other
calc=hmac.new(secret,struct.pack('>H',len(mac))+mac+bytes(unsigned)+vars2,hashlib.sha256).digest()
assert calc==rmac, 'BADTIME response MAC'
print('signed BADTIME verified')
PY
pass "signed BADTIME and replay path"
kill "$LAST_PID" 2>/dev/null || true

echo "advanced tests passed"
