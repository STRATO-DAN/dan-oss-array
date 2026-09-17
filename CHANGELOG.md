# Changelog

All notable changes to `@strato-dan/array` are documented here.
This project uses [semantic versioning](https://semver.org/).

## [0.4.0] — 2026-09-17

Cross-cutting polish. Purely additive — no change to existing routes, the wire format, or the
crypto. Still zero runtime dependencies (Node standard library only).

### Added

- **Launcher flags (hand-rolled, no dependency).** `dan-oss-array` now accepts `--version` (prints
  the version, exit 0), `--help` (usage, environment variables including `DAN_OSS_ARRAY_PORT`, and
  the exit-code contract, exit 0), and `--json` (prints the startup banner as one JSON object
  `{url,port,mode,encryption}` for scripting/CI). The human-readable banner remains the default and
  is unchanged.
- **Honest startup-failure exit codes.** A startup failure (e.g. the port is already in use,
  `EADDRINUSE`) now prints a single line to stderr and exits non-zero (`1`) instead of dumping a raw
  stack trace. An unknown flag exits `2`. The `0`/`1`/`2` contract is documented in `--help` and the
  README.
- **`Makefile` with `make help`.** `make test` (full suite), `make attack` (runs only the existing
  adversarial/security suites and shows they reject), `make demo` (reproducible crypto-core
  seal/open plus wrong-passphrase and tamper failures — no LAN needed), and `make bench` (scrypt KDF
  time and AES-256-GCM seal/open throughput — no LAN needed). Every test invocation pins
  `--test-concurrency=1`.
- **`BENCHMARKS.md`** with real `make bench` numbers, a reproduce command, and a machine note.

### Changed

- `src/server.js` `listen()` now rejects its promise on a bind error (previously the server's
  `error` event was unhandled and crashed the process). The success path is unchanged.
- README gains a "Scriptable & CI" note, a "Try the attacks: `make attack`" pointer, and a link to
  `BENCHMARKS.md`.

## [0.3.0] — 2026-09-17

### ⚠️ Breaking — update BOTH ends

The handshake key derivation changed, so a 0.3.0 peer cannot complete a transfer with a 0.2.x peer.
Upgrade the sender and the receiver together. The at-rest payload format (`encrypt`/`decrypt`) is
unchanged and stays byte-compatible.

### Security

- **Per-session passphrase-KDF salt (was a public per-room constant).** The passphrase key mixed into
  the session key was derived with `scrypt(passphrase, roomHash)`. `roomHash` is broadcast on the LAN in
  every announce packet, so that salt was a public constant and the derived key was identical across
  every session in a room — letting an offline guessing effort be amortised across all of them. The salt
  is now bound to the per-session handshake transcript (the exchanged ephemeral public keys), so it is
  unique per handshake. Both sides already share the transcript, so both still derive the same key.
- **Exactly-one-peer contract enforced atomically.** The sharer claimed the single-serve slot *after*
  writing the sealed capsule, so two peers that both proved the passphrase at the same instant could each
  receive it. The claim now happens synchronously, immediately before the capsule is written, so only one
  connection is ever served even under a simultaneous-authenticated-peer race.
- **Domain-separated session subkeys.** A single session key was used both as the AES-GCM capsule key and
  as the HMAC key for the handshake confirmation MAC. These are now two independent keys derived via
  distinct HKDF `info` labels, so the confirmation MAC (which travels in the clear during the handshake)
  shares no key material with the capsule cipher.
- **Cross-origin (CSRF) guard on the local UI server.** The loopback HTTP API already refused a
  non-loopback `Host` (DNS-rebinding guard); it now also refuses any request carrying a browser `Origin`
  that isn't loopback, so a cross-origin web page cannot drive the local share/receive API. A same-origin
  request from the UI (loopback or no `Origin`) and non-browser clients are unaffected. Denial-of-service
  via raw LAN broadcast remains out of scope per `SECURITY.md`.

### Robustness

- **The receiver survives a spoofing announcer.** It used to commit to the *first* matching discovery
  announcement, so a LAN host that won the discovery race with a bogus announcement reliably failed the
  whole transfer. The receiver now keeps listening and tries each distinct announcer in turn until one
  completes or the window closes. Discovery itself remains unauthenticated — a DoS-adjacent residual that
  `SECURITY.md` de-scopes; this makes the transfer *survive* a spoofer rather than claiming to prevent one
  from announcing.

### Performance

- **Payload encryption no longer blocks the event loop.** `encrypt`/`decrypt` derived their key with the
  synchronous `scryptSync`, freezing Node's single event-loop thread for the derivation's full duration
  (the handshake path was already moved async in 0.2.1). They now use async `scrypt` on the libuv
  threadpool. `encrypt`/`decrypt` are therefore async (they return Promises); the wire format is unchanged.

### Tests

- Test files now run sequentially (`--test-concurrency=1`): the discovery and integration suites share
  one fixed UDP discovery port, so running the files in parallel could let their listeners steal each
  other's packets. Added regression coverage for each fix above, including a new `test/server.test.mjs`.

## [0.2.1] — 2026-09-17

### Security
- **Pre-auth handshake DoS hardening.** The authenticated handshake derives an expensive scrypt key
  (N=16384) for every inbound peer *before* that peer can prove the passphrase. That derivation was
  synchronous (`scryptSync`), so a peer that merely connected blocked Node's single event-loop thread for
  its full duration — an unauthenticated peer could stall the whole process without any valid passphrase.
  The derivation is now **async** (`crypto.scrypt`, on the libuv threadpool), so one handshake no longer
  freezes other sockets and timers. In addition, each inbound handshake now has a **hard deadline** (a peer
  that connects then stalls is dropped and the sharer keeps listening), **concurrent handshakes are capped**
  so a connection flood can't pile up unbounded pre-auth work, and `stop()` cancels the pending timeout
  cleanly instead of leaving it running.

## [0.2.0] — 2026-09-16

### Security
- Authenticated transport: ephemeral X25519 + receiver-proves-passphrase-first, one sealed capsule keyed
  by a session key bound to both the key agreement and the passphrase, and length-/total-capped framed
  reads. Replaces v1's "hand the blob to the first TCP peer" behaviour.
