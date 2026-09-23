# Changelog

All notable changes to `@strato-dan/array` are documented here.
This project uses [semantic versioning](https://semver.org/).

## [0.5.2] — 2026-09-23

### Security

- **Room-code enumeration hardened.** `roomHash` (broadcast in every UDP announce, by necessity —
  peers need it to find each other before any secret exists) is an unsalted, truncated SHA-256 of
  the room code. A short code is cheap to brute-force back from that public hash: a 4-character
  code was recoverable in ~2,300 tries / 3ms. This alone never exposes the transfer payload — the
  passphrase-derived scrypt session key still guards that — but it hands a passive LAN listener the
  exact room to target with their online guessing budget instead of guessing blind. Minimum
  room-code length raised 4 → 10 characters, and `validateShareBody` now rejects a passphrase equal
  to the room code (a reused string collapsed the two independent secrets into one enumerable
  value, since the room code's hash is public but the passphrase is not).

### Fixed

- **CORRECTION to 0.5.0's "Device-fingerprint binding on the handshake (F01)" entry below.** That
  entry claimed a receiver/sharer fingerprint was bound into the handshake to prevent LAN device
  impersonation. It never was: `deviceFingerprint()` was defined and documented, but had zero
  callers anywhere in `src`/`test`/`bin`/`public` — dead code since it was added, and the 0.5.0
  changelog entry describing it as live handshake binding was inaccurate. Removed the unused
  function rather than retroactively wiring it in: doing so now would be a breaking wire-protocol
  change (older and newer peers would fail to interoperate) for a property that was always
  honestly weak on its own — the fingerprint is self-asserted, non-secret metadata, not a
  cryptographic proof of device identity, so an active impersonator could simply claim any
  fingerprint. No real security property regresses: the handshake's actual authentication (X25519
  ephemeral key agreement + scrypt passphrase-derived session key + receiver-proves-first ordering)
  never depended on this function, and F02's per-room attempt-rate budget is unaffected.

## [0.5.1] — 2026-09-19

### Fixed

- **Transfer lifetime coupled to client disconnect.** `shareEnv`/`receiveEnv` accept an
  `AbortSignal`; abort stops the TCP listener, the UDP announcer, and in-flight fetches at
  once instead of running to timeout after the browser goes away (`Findings 06/07`). Also
  makes announcer/listener `stop()` idempotent (a double-stop threw
  `ERR_SOCKET_DGRAM_NOT_RUNNING` and masked real outcomes).

## [0.5.0] — 2026-09-19

### Security

- **Device-fingerprint binding on the handshake (F01).** A receiver/sharer fingerprint derived from
  hostname+OS+arch, so a peer on the same LAN can't silently impersonate a different device
  mid-session. Not identity/PKI — a binding label, stated honestly as such. Also fixes a real
  runtime bug: the fingerprint helper used `require()` in an ESM module, which threw on every share.
- **Per-room passphrase attempt-rate budget (F02).** 50 attempts / 2-minute window on both sharer
  and receiver, so offline passphrase guessing can't exceed the "few hundred guesses" bound the
  design already claims.
- **Strict same-origin check.** `isAllowedOrigin` now requires an exact match against the request's
  own Host. An opaque/`null` Origin, previously allowed, is now rejected; cross-site
  `Sec-Fetch-Site` is refused explicitly.
- **Security response headers** on every response: `Cache-Control: no-store`,
  `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options: DENY`, and a real CSP
  (`script-src 'self'`).
- **Content-type gate.** A POST to `/api/*` without `application/json` is refused (415) before
  touching the body — closes the simple-request CSRF class (`text/plain`, form-urlencoded,
  multipart can't reach these routes).
- **Announcer fan-out cap (FINDING 11).** Capped at 8 distinct announcers per receive — each
  attempt costs a real scrypt derivation + socket; beyond that, fail closed at timeout instead of
  unbounded churn against a flooding LAN.

### Added

- Auto-clearing received secrets (5 minutes after a successful receive) plus a manual "Clear
  visible secrets" button and an unload handler. Documented honestly: clears the DOM, not browser
  memory/downloads, and doesn't cancel an in-flight transfer.
- `public/favicon.svg` (was missing, 404 on every page load).

### Fixed

- Honest copy: the trust-model note no longer implies device identity is verified (passphrase
  knowledge is what's actually checked), and the share-session note no longer implies closing the
  tab stops an in-flight transfer.

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
