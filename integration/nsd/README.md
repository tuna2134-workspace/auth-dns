# NSD interoperability test

`scripts/nsd-interop-test.sh` runs this test automatically.  It starts NSD
4.9.1 in a Docker container as a secondary and auth-dns as the primary.

- Initial AXFR: NSD receives serial 100.
- Edit the primary zone, `SIGHUP` auth-dns: auth-dns reloads serial 101 and
  creates a journal delta.
- NSD refreshes (SOA refresh = 5 s) and requests IXFR; the test verifies the
  changed, added and deleted records in NSD.
- The same sequence is repeated with a TSIG `hmac-sha256` key.

Run:

```sh
./scripts/nsd-interop-test.sh
```

Requirements: Docker with host networking and permission to build images.
The NSD image is built from `Dockerfile` on first use.
