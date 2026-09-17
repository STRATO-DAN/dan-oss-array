# Benchmarks

Crypto-core throughput for `@strato-dan/array`, measured with `make bench` — Node standard library
only, single-threaded, no LAN and no dependencies required.

**Reproduce:** `make bench` (or `node scripts/bench.mjs`). Numbers are inherently machine- and
Node-version-dependent; re-run locally for figures that mean anything on your hardware.

## What is measured

- **scrypt passphrase KDF** (`passphraseKey`, `N=16384, r=8, p=1`) — the deliberately-slow per-session
  key derivation, run once on each side of a handshake.
- **AES-256-GCM seal/open** (`sealCapsule`/`openCapsule`) — the per-payload symmetric cost, with the
  session key pre-derived so the cipher is measured on its own, over a 4 KiB (realistic `.env`-sized)
  payload.

## Results

Machine: Apple Silicon (arm64), macOS. Node v22.23.1.

| Measurement | Result |
|---|---|
| scrypt passphrase KDF (N=16384) | ~20.3 ms/derivation · ~49 derivations/sec |
| AES-256-GCM seal (4 KiB payload) | ~301,800 ops/sec · ~1,179 MB/s |
| AES-256-GCM open (4 KiB payload) | ~472,300 ops/sec · ~1,845 MB/s |

Literal output from one local run:

```
[DAN] ARRAY — crypto throughput (Node stdlib only, single-threaded)

node v22.23.1 · darwin/arm64

1. scrypt passphrase KDF (N=16384, r=8, p=1 — the per-session key derivation)
   20 derivations in 406.01 ms
   20.30 ms/derivation  ·  49.26 derivations/sec

2. AES-256-GCM seal/open (4096-byte payload, key pre-derived)
   seal: 301,771 ops/sec  ·  1,178.79 MB/s
   open: 472,285 ops/sec  ·  1,844.86 MB/s
```

## How to read these

The scrypt KDF is the intentional bottleneck: at ~20 ms per derivation it is fast enough to be
unnoticeable for one transfer, yet slow enough that offline guessing against a captured session is
expensive — which is the entire point of a password-hardening KDF. The symmetric cipher is orders of
magnitude faster, so for the small payloads this tool moves (a `.env` file), the transfer cost is
dominated by the network handshake and the one-time KDF, never the encryption itself.
