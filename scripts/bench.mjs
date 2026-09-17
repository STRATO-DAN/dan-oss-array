// Reproducible crypto-throughput benchmark — no LAN, no sockets, no dependencies, < ~15s.
// Measures the two costs that dominate a real transfer, both from src/crypto.js:
//   1. the scrypt passphrase KDF (N=16384) — deliberately slow, run once per session
//   2. AES-256-GCM seal/open — the per-payload symmetric cost
// Run: `make bench` or `node scripts/bench.mjs`.
import crypto from "node:crypto";
import { performance } from "node:perf_hooks";
import { passphraseKey, sealCapsule, openCapsule } from "../src/crypto.js";

function fmt(n, digits = 2) {
  return n.toLocaleString("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

console.log("[DAN] ARRAY — crypto throughput (Node stdlib only, single-threaded)\n");
console.log(`node ${process.version} · ${process.platform}/${process.arch}\n`);

// ── 1. scrypt passphrase KDF ────────────────────────────────────────────────────────────────────
// This is the per-session cost paid once on each side of a handshake. It is meant to be slow, so a
// small iteration count gives a stable per-derivation number without dragging the whole bench out.
{
  const passphrase = "correct horse battery staple";
  const roomCode = "bench-room";
  const transcript = crypto.randomBytes(64);
  const iters = 20;
  // warm-up (JIT + first-call allocation), not counted
  passphraseKey(passphrase, roomCode, transcript);
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) passphraseKey(passphrase, roomCode, transcript);
  const elapsedMs = performance.now() - t0;
  const perMs = elapsedMs / iters;
  console.log("1. scrypt passphrase KDF (N=16384, r=8, p=1 — the per-session key derivation)");
  console.log(`   ${iters} derivations in ${fmt(elapsedMs)} ms`);
  console.log(`   ${fmt(perMs)} ms/derivation  ·  ${fmt(1000 / perMs)} derivations/sec\n`);
}

// ── 2. AES-256-GCM seal/open ──────────────────────────────────────────────────────────────────────
// Derive one raw session key up front (excluded from timing) so this measures the symmetric cipher
// alone, not scrypt. Payload is 4 KiB — a realistic .env-sized secret.
{
  const key = crypto.randomBytes(32);
  const payload = crypto.randomBytes(4096);
  const payloadMB = payload.length / (1024 * 1024);
  const iters = 20000;

  // warm-up
  openCapsule(key, sealCapsule(key, payload));

  const tSeal0 = performance.now();
  let last;
  for (let i = 0; i < iters; i++) last = sealCapsule(key, payload);
  const sealMs = performance.now() - tSeal0;

  const capsule = last;
  const tOpen0 = performance.now();
  for (let i = 0; i < iters; i++) openCapsule(key, capsule);
  const openMs = performance.now() - tOpen0;

  const sealOps = iters / (sealMs / 1000);
  const openOps = iters / (openMs / 1000);
  console.log(`2. AES-256-GCM seal/open (${payload.length}-byte payload, key pre-derived)`);
  console.log(`   seal: ${fmt(sealOps, 0)} ops/sec  ·  ${fmt(sealOps * payloadMB)} MB/s`);
  console.log(`   open: ${fmt(openOps, 0)} ops/sec  ·  ${fmt(openOps * payloadMB)} MB/s`);
}
