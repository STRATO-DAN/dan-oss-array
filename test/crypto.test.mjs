// Real tests against the real crypto primitives — no mocked cipher, real AES-256-GCM round-trips.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { encrypt, decrypt, roomHash, passphraseKey, deriveSessionKeys } from "../src/crypto.js";

test("encrypt then decrypt with the same passphrase round-trips the real plaintext exactly", async () => {
  const plaintext = "API_KEY=demo-only\nDB_URL=postgres://localhost/example\n";
  const blob = await encrypt(plaintext, "correct horse battery staple");
  assert.equal(await decrypt(blob, "correct horse battery staple"), plaintext);
});

test("a wrong passphrase fails to decrypt rather than returning garbage", async () => {
  const blob = await encrypt("secret text", "the real passphrase");
  await assert.rejects(decrypt(blob, "the wrong passphrase"));
});

test("a tampered ciphertext fails to decrypt — GCM's own auth tag catches it", async () => {
  const blob = await encrypt("secret text", "a real passphrase");
  const tampered = Buffer.from(blob);
  tampered[tampered.length - 1] ^= 0xff; // flip the last real ciphertext byte
  await assert.rejects(decrypt(tampered, "a real passphrase"));
});

test("a too-short payload fails honestly instead of reading out-of-bounds", async () => {
  await assert.rejects(decrypt(Buffer.from("short"), "any passphrase"), /too short/);
});

test("two real encryptions of the same plaintext produce different ciphertext (real random salt/iv)", async () => {
  const a = await encrypt("same text", "same passphrase");
  const b = await encrypt("same text", "same passphrase");
  assert.notEqual(a.toString("hex"), b.toString("hex"));
  // both still decrypt to the same real plaintext
  assert.equal(await decrypt(a, "same passphrase"), "same text");
  assert.equal(await decrypt(b, "same passphrase"), "same text");
});

test("roomHash is deterministic for the same room code and differs for a different one", () => {
  assert.equal(roomHash("my-room"), roomHash("my-room"));
  assert.notEqual(roomHash("my-room"), roomHash("other-room"));
  assert.equal(roomHash("my-room").length, 16);
});

test("roomHash never returns the real room code itself, only a real hash of it", () => {
  const hash = roomHash("a-secret-room-code");
  assert.doesNotMatch(hash, /a-secret-room-code/);
});

// A7 — the payload key derivation now runs on the async (libuv threadpool) scrypt path so it never
// blocks Node's single event-loop thread. encrypt/decrypt are therefore async and return Promises.
test("A7: encrypt/decrypt run on the async, non-blocking scrypt path (they return Promises)", async () => {
  const p = encrypt("x", "a passphrase for you");
  assert.equal(typeof p.then, "function", "encrypt is async — scrypt runs on the threadpool, not the event loop");
  const blob = await p;
  const d = decrypt(blob, "a passphrase for you");
  assert.equal(typeof d.then, "function", "decrypt is async too");
  assert.equal(await d, "x");
});

// A4 — the passphrase-KDF salt is now PER-SESSION (folds in the handshake transcript), not the public,
// broadcast, per-room-constant roomHash. Different sessions (transcripts) must derive different keys, so
// a captured capsule can't be attacked with a key amortised across every session in the room.
test("A4: the passphrase-KDF salt is per-session — same passphrase+room yields DIFFERENT keys per transcript", () => {
  const passphrase = "the shared secret";
  const roomCode = "room-salt";
  const transcriptA = crypto.randomBytes(64); // stand-in for the exchanged ephemeral public keys
  const transcriptB = crypto.randomBytes(64);

  const kA = passphraseKey(passphrase, roomCode, transcriptA);
  const kB = passphraseKey(passphrase, roomCode, transcriptB);
  const kPublicConstant = passphraseKey(passphrase, roomCode); // the old public-constant-salt form

  assert.equal(kA.length, 32);
  assert.notDeepEqual(kA, kB, "two different sessions must not share a passphrase key");
  assert.notDeepEqual(kA, kPublicConstant, "the per-session key must differ from the old public-constant-salt key");
  // Determinism: both peers deriving with the SAME transcript get the SAME key (interop).
  assert.deepEqual(passphraseKey(passphrase, roomCode, transcriptA), kA);
});

// A6 — the session key is no longer reused as both the AES-GCM key and the HMAC key. Two distinct HKDF
// info labels derive independent subkeys, so the confirmation MAC (sent in the clear during the
// handshake) shares no key material with the capsule cipher.
test("A6: session subkeys are domain-separated — the capsule-enc key and the confirm-MAC key are distinct", () => {
  const ikm = crypto.randomBytes(64); // stand-in for the ECDH secret || passphrase key
  const transcript = crypto.randomBytes(80);

  const { kEnc, kMac } = deriveSessionKeys(ikm, transcript);
  assert.equal(kEnc.length, 32);
  assert.equal(kMac.length, 32);
  assert.notDeepEqual(kEnc, kMac, "the capsule key and the confirm-MAC key must not be the same key");
  // Deterministic: both peers derive the same pair from the same IKM+transcript (interop).
  const again = deriveSessionKeys(ikm, transcript);
  assert.deepEqual(again.kEnc, kEnc);
  assert.deepEqual(again.kMac, kMac);
});
