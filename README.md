<div align="center">

<img src="assets/dan-mark.svg" alt="[DAN] ARRAY" width="84" height="84">

# [DAN] ARRAY

**P2P `.env` sync over your LAN — no central server to leak, breach, or go down.**

[![CI](https://github.com/STRATO-DAN/dan-oss-array/actions/workflows/ci.yml/badge.svg)](https://github.com/STRATO-DAN/dan-oss-array/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@strato-dan/array.svg)](https://www.npmjs.com/package/@strato-dan/array)
[![runtime deps](https://img.shields.io/badge/runtime%20deps-0-2e9e56.svg)](#dependencies)
[![status](https://img.shields.io/badge/status-experimental-b5750a.svg)](#honest-limits)
[![license](https://img.shields.io/badge/license-MIT-informational.svg)](LICENSE)

</div>

> **⚡ Zero install · zero runtime dependencies.** `npx @strato-dan/array` runs it — pure Node standard
> library (Node ≥ 18), nothing to install. Full breakdown under [Dependencies](#dependencies).

P2P `.env` sync. No central server.

A real peer-to-peer tool for handing a `.env` file to a teammate (or another machine you own) on
the same network — no server in the middle to leak, get breached, or go down.

> ⚠️ **Experimental — trusted / private networks only.** `[DAN] ARRAY` is experimental. Use it only
> on trusted, private networks you control (your own LAN or Wi-Fi) — **not** for real production
> secrets over shared or public Wi-Fi.

## Use

```bash
npx @strato-dan/array
```

Opens at `http://127.0.0.1:4873` (loopback only — the UI, not the transfer, is local-only).

**On the sending machine:** paste your `.env` contents, pick a room code and a passphrase (share
these two out of band — Slack, in person, a call — never over the same channel as the file
itself), click **Broadcast & wait for peer**.

**On the receiving machine:** enter the same room code and passphrase, click **Listen for peer**.

## How it actually works

```
1. Sender encrypts the .env text locally (AES-256-GCM, key derived from the passphrase via scrypt)
2. Sender broadcasts a UDP announcement on the local network: "a room with this hash exists,
   connect to me on this port" — the room code itself never goes on the wire, only its hash
3. Receiver, listening for that same hash, connects DIRECTLY to the sender over TCP
4. The two run an authenticated handshake: a fresh X25519 key agreement whose session key is bound to
   BOTH the exchange AND the passphrase, and the receiver proves the passphrase before anything is
   sent. The sender refuses a peer that can't prove it and keeps waiting for the right one.
5. Sender hands over ONE sealed capsule (the credential, encrypted under that session key), then
   closes — one authenticated peer, one transfer, no relay
6. Receiver opens the capsule and decrypts locally with the passphrase
```

No cloud service, no relay server, no account. If both machines are on the same LAN/Wi-Fi network,
they find each other directly.

## Honest limits

- **Experimental — trusted networks only.** This tool is experimental and intended for trusted,
  private networks (your own LAN / Wi-Fi). Do not use it to move real production secrets over shared
  or public Wi-Fi.
- **Same network only.** UDP broadcast discovery works within one LAN/Wi-Fi broadcast domain. It
  does not cross the public internet or a NAT boundary — that would need a relay, which is exactly
  the central point of failure this tool exists to avoid.
- **The passphrase still matters.** The transfer now rides an ephemeral X25519 session key bound to
  the passphrase, so a captured session can't be opened without the ephemeral secret — but a weak
  passphrase is still a weak passphrase. scrypt makes brute-forcing expensive, not impossible; use a
  real shared secret, not `password123`.
- **The receiver is authenticated (v0.2).** The sender no longer streams the blob to the first peer
  that connects — the peer must prove the passphrase (bound to a fresh key agreement) before the
  sealed capsule is sent, and an unproven peer is refused while the sender waits for the right one. A
  racing LAN host can no longer steal the ciphertext or deny the real receiver. Honest residual: an
  *active* impostor that lures a receiver and wins its discovery race obtains one transcript MAC it
  can attack offline against the passphrase (scrypt-hardened) — it yields a passphrase guess, never a
  past session's payload. For higher assurance, use the advanced tier.
- **This secures the wire, not the endpoints.** It removes the central-server leak risk — it does
  not protect either machine from its own compromise.
- Nothing is ever written to disk by this tool. The `.env` text lives in the browser tab and the
  Node process's memory only, for the life of the transfer.

## Basic tier vs. the advanced tier

This is the **open-source basic tier**: generic AES-256-GCM encryption, P2P discovery, no central
server. `[DAN] ARRAY (advanced)` replaces the generic cipher with DAN's own proprietary encryption
architecture (`[DAN] ENCRYPTED MODULE`) and lives exclusively inside `[DAN] MEMORY SMASH` — it is
not, and will not be, part of this repository.

## When to use this

- **Best fit**: handing a `.env` file, API key, or small secret to a teammate (or your own other
  machine) on the same LAN/Wi-Fi, right now, without emailing it, pasting it in chat, or standing
  up any kind of server or account to do it.
- **Best fit**: you want the transfer itself encrypted end-to-end with no middleman that could
  leak or get breached, and you're comfortable sharing the room code/passphrase out of band.

**Honest flip side**: if the two machines aren't on the same network segment — different offices,
different Wi-Fi, one on a VPN the other isn't — this doesn't work and isn't trying to; see "Same
network only" above. It also isn't a general file-sharing tool: it moves one block of text
(typically `.env` contents), not files or directories, and nothing is retried or queued — both
sides need to be running within the timeout window of each other.

## Validation

Everything below was run locally before this README shipped — no mocked output.

**Tests.** Node's own built-in test runner, zero dependencies, no `npm install` required:

```bash
npm test
```

The suite exercises the crypto round-trip, the wrong-passphrase and tampered-ciphertext failures,
the room-code hashing, and a real end-to-end run where an in-process sender and receiver find each
other over UDP and transfer over TCP. Most recent run: **10 tests, 10 passed, 0 failed.**

## Examples

[`examples/share-and-receive.mjs`](examples/share-and-receive.mjs) runs a real sender and receiver
concurrently using `shareEnv`/`receiveEnv` directly — real UDP discovery, real TCP transfer, real
encryption — and then demonstrates the honest wrong-passphrase failure:

```bash
node examples/share-and-receive.mjs
```

Real output from a local run (the room code is randomized each run, so that line will differ, and
the peer address will be whatever local IP your machine has):

```
Room: example-a37e9214
Starting sender and receiver concurrently — real UDP discovery, real TCP transfer...

Sender result: { ok: true, peerAddress: '::ffff:192.168.1.7' }
Receiver result: { ok: true, envText: '63 chars', fromAddress: '192.168.1.7' }

Received text matches what was sent: true

Now trying with a WRONG passphrase — should fail loudly, not decrypt garbage:
Failed as expected: Could not decrypt the received data — wrong passphrase, or the payload was corrupted in transit.
```

## Dependencies

**Runtime dependencies: none.** Pure Node standard library — nothing to install, no relay to run.

| | |
|---|---|
| **Runtime dependencies** | **0** — Node standard library only (`dgram`, `net`, `crypto`, `http`) |
| **Install to run** | none — `npx @strato-dan/array` |
| **Install to test** | none — `npm test` uses Node's built-in test runner |
| **Node** | ≥ 18 |
| **Dev-only** | `husky` — pulled in only if you clone to contribute; never needed to use the tool |

The UDP discovery and TCP transfer are Node's own `dgram`/`net`; the crypto is Node's own
`crypto`. There is no dependency tree to resolve and nothing phones home.

## Project contents

Every file below is the **basic (open-source) tier only** — there is no advanced/encrypted-tier
code anywhere in this repository; see the section above for that boundary.

| Path | What it is |
|---|---|
| `bin/dan-oss-array.js` | The real CLI entry point — starts the local UI server. |
| `src/server.js` | The loopback-only HTTP server serving the sender/receiver UI. |
| `src/crypto.js` | Generic AES-256-GCM encrypt/decrypt + scrypt key derivation. Basic tier only. |
| `src/discovery.js` | Real UDP broadcast announce/listen — room-code-hash based peer discovery. |
| `src/peer.js` | The real one-shot TCP listener/connect used for the actual file transfer. |
| `src/sync.js` | `shareEnv`/`receiveEnv` — orchestrates discovery + transfer + crypto together. |
| `public/` | The plain HTML/CSS/vanilla-JS sender/receiver UI. |
| `examples/` | Runnable example code using the library functions directly, no UI. |
| `test/` | Real unit + integration tests (`npm test`) — crypto round-trips and a real UDP+TCP sender/receiver run. |

## FAQ

**Can I send more than one file, or a whole directory?** Not yet — `shareEnv`/`receiveEnv` moves
one block of text (typically a `.env` file's contents). Multi-file transfer is a real possible
future addition, not built here.

**What happens if the receiver isn't listening yet when the sender starts broadcasting?**
`startAnnouncing` keeps re-broadcasting on an interval until a peer connects or the sender's own
timeout elapses — order doesn't matter, but both sides do need to start within the timeout window
of each other (120s sender / 30s receiver by default).

**Does this work across Wi-Fi and Ethernet on the same LAN?** Yes, as long as both interfaces are
on the same broadcast domain — UDP broadcast discovery doesn't care about the physical link type,
only the network segment.

**Can it cross a NAT or the public internet?** No — see "Honest limits" above. That would require
a relay server, which is exactly the single point of failure this tool exists to avoid.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
for how to file an issue or submit a PR. Maintainers may use AI tools to help review
contributions — please don't include personal information in an issue, PR, or commit beyond
what's needed to describe the change.

## Releasing

See [RELEASING.md](RELEASING.md) —
the same version-bump/tag/publish process applies to every DAN-OSS tool, this one included.

## License

MIT (code) — see `LICENSE`. The "DAN" name and logo are trademarked — see `TRADEMARK.md`.

---

**[DAN] MEMORY SMASH** — the full codebase-memory engine, and the home of `[DAN] ARRAY`'s advanced
encrypted tier — is coming soon.
