# Test-only DNSSEC keys

These private keys are used by the unit and integration tests:

- `test-ecdsa.pem` — ECDSA P-256 (algorithm 13)
- `test-ed25519.pem` — Ed25519 (algorithm 15)
- `test-rsa.pem` — RSA 2048 (algorithm 8)

They are **public test material**. Never use them for a real zone.
Generate production keys with:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out keys/example.com.pem
```
