#!/usr/bin/env bash
# Interoperability test: auth-dns (primary) -> NSD (secondary) over
# AXFR and IXFR, with and without TSIG.
#
# Requires Docker.  The NSD image is built from integration/nsd/Dockerfile.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PORT="${PORT:-15353}"
NSD_PORT="${NSD_PORT:-15370}"
SECRET="c2VjcmV0MTIzNDU2Nzg5MA=="
SECRET_RAW="secret1234567890"
IMAGE="auth-dns-nsd"
TMP=""
SERVER_PID=""
CNAME=""

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
    if [[ -n "$CNAME" ]]; then docker rm -f "$CNAME" >/dev/null 2>&1 || true; fi
    if [[ -n "$TMP" && -d "$TMP" ]]; then
        docker run --rm -v "$TMP:/t" alpine:3.20 sh -c 'rm -rf /t/*' >/dev/null 2>&1 || true
        rm -rf "$TMP" 2>/dev/null || true
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    [[ -f "$TMP/server.log" ]] && { echo "--- auth-dns log ---" >&2; cat "$TMP/server.log" >&2; }
    [[ -f "$TMP/db/nsd.log" ]] && { echo "--- nsd log ---" >&2; cat "$TMP/db/nsd.log" >&2; }
    [[ -n "$CNAME" ]] && docker logs "$CNAME" >&2 2>&1 || true
    exit 1
}

export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$ROOT/.zig-global-cache}"
zig build

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE ..."
    DOCKER_CONFIG="${DOCKER_CONFIG:-$ROOT/.docker}" DOCKER_BUILDKIT=0 \
        docker build -t "$IMAGE" integration/nsd >/dev/null
fi

wait_serial() {
    local want="$1" serial=""
    for _ in $(seq 1 60); do
        serial="$(dig @127.0.0.1 -p "$NSD_PORT" +short example.com SOA +time=1 +tries=1 2>/dev/null | awk '{print $3}')"
        [[ "$serial" == "$want" ]] && return 0
        sleep 0.25
    done
    return 1
}

write_zone() {
    local serial="$1" www="$2"
    cat > "$TMP/primary.zone" <<ZONE
\$TTL 60
\$ORIGIN example.com.
@ SOA ns1.example.com. hostmaster.example.com. ( $serial 5 5 60 5 )
@ NS ns1.example.com.
ns1 A 192.0.2.53
www A $www
old A 192.0.2.9
ZONE
}

write_zone_updated() {
    cat > "$TMP/primary.zone" <<ZONE
\$TTL 60
\$ORIGIN example.com.
@ SOA ns1.example.com. hostmaster.example.com. ( 101 5 5 60 5 )
@ NS ns1.example.com.
ns1 A 192.0.2.53
www A 192.0.2.2
new A 192.0.2.10
ZONE
}

run_case() {
    local mode="$1" # nokey | tsig
    TMP="$(mktemp -d "$ROOT/.nsd-test.XXXXXX")"
    mkdir -p "$TMP/config" "$TMP/db" "$TMP/zones" "$TMP/server-db"
    chmod 777 "$TMP/db" "$TMP/zones"
    CNAME="nsd-interop-$$-$mode"
    write_zone 100 192.0.2.1

    local server_args=(serve -l "0.0.0.0:$PORT" -z "example.com=$TMP/primary.zone"
        --journal-dir "$TMP/server-db")
    local key_block="" request_key="NOKEY"
    if [[ "$mode" == "tsig" ]]; then
        server_args+=(--allow-transfer "key:xfr.example.com"
            --tsig "xfr.example.com:hmac-sha256:$SECRET")
        key_block=$'key:\n    name: "xfr.example.com"\n    algorithm: hmac-sha256\n    secret: "'"$SECRET"$'"\n'
        request_key="xfr.example.com"
    else
        server_args+=(--allow-transfer any)
    fi

    cat > "$TMP/config/nsd.conf" <<CONF
server:
    ip-address: 127.0.0.1
    port: $NSD_PORT
    do-ip4: yes
    do-ip6: no
    database: ""
    pidfile: "/db/nsd.pid"
    logfile: "/db/nsd.log"
    verbosity: 3
    username: ""
    zonesdir: "/zones"
    xfrdfile: "/db/xfrd.state"
    xfrdir: "/db"

remote-control:
    control-enable: no

$key_block
zone:
    name: "example.com"
    zonefile: "example.com.zone"
    request-xfr: 127.0.0.1@$PORT $request_key
CONF

    docker rm -f "$CNAME" >/dev/null 2>&1 || true
    ./zig-out/bin/auth-dns "${server_args[@]}" > "$TMP/server.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 40); do
        dig @127.0.0.1 -p "$PORT" example.com SOA +short +time=1 +tries=1 >/dev/null 2>&1 && break
        kill -0 "$SERVER_PID" 2>/dev/null || fail "auth-dns exited"
        sleep 0.2
    done
    dig @127.0.0.1 -p "$PORT" example.com SOA +short +time=1 +tries=1 >/dev/null 2>&1 || fail "auth-dns did not start"

    docker run -d --name "$CNAME" --network host \
        -v "$TMP/config:/config:ro" -v "$TMP/db:/db" -v "$TMP/zones:/zones" \
        "$IMAGE" >/dev/null
    wait_serial 100 || fail "$mode: initial AXFR did not arrive"
    [[ "$(dig @127.0.0.1 -p "$NSD_PORT" +short www.example.com A +time=2 +tries=1)" == "192.0.2.1" ]] \
        || fail "$mode: initial A record"

    write_zone_updated
    kill -HUP "$SERVER_PID"
    sleep 1
    wait_serial 101 || fail "$mode: IXFR did not arrive"
    [[ "$(dig @127.0.0.1 -p "$NSD_PORT" +short www.example.com A +time=2 +tries=1)" == "192.0.2.2" ]] \
        || fail "$mode: updated A record"
    [[ "$(dig @127.0.0.1 -p "$NSD_PORT" +short new.example.com A +time=2 +tries=1)" == "192.0.2.10" ]] \
        || fail "$mode: added record"
    dig @127.0.0.1 -p "$NSD_PORT" old.example.com A +time=2 +tries=1 +noall +comments 2>/dev/null \
        | grep -q NXDOMAIN || fail "$mode: deleted record still present"

    grep -q "transfer ixfr example.com" "$TMP/server.log" || fail "$mode: server did not serve IXFR"
    if [[ "$mode" == "tsig" ]]; then
        grep -q "key=xfr.example.com" "$TMP/server.log" || fail "tsig: transfer was not TSIG-authenticated"
    fi
    echo "PASS: $mode AXFR -> serial 100, IXFR -> serial 101"

    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    docker rm -f "$CNAME" >/dev/null 2>&1 || true
    CNAME=""
    docker run --rm -v "$TMP:/t" alpine:3.20 sh -c 'rm -rf /t/*' >/dev/null 2>&1 || true
    rm -rf "$TMP"
    TMP=""
}

run_case nokey
run_case tsig
echo "NSD interoperability tests passed"
