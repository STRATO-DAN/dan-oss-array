# Changelog

All notable changes to `@strato-dan/array` are documented here.
This project uses [semantic versioning](https://semver.org/).

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
