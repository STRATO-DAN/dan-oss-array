// Real tests against the real crypto primitives — no mocked cipher, real AES-256-GCM round-trips.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encrypt, decrypt, roomHash } from "../src/crypto.js";

test("encrypt then decrypt with the same passphrase round-trips the real plaintext exactly", () => {
  const plaintext = "API_KEY=demo-only\nDB_URL=postgres://localhost/example\n";
  const blob = encrypt(plaintext, "correct horse battery staple");
  assert.equal(decrypt(blob, "correct horse battery staple"), plaintext);
});

test("a wrong passphrase fails to decrypt rather than returning garbage", () => {
  const blob = encrypt("secret text", "the real passphrase");
  assert.throws(() => decrypt(blob, "the wrong passphrase"));
});

test("a tampered ciphertext fails to decrypt — GCM's own auth tag catches it", () => {
  const blob = encrypt("secret text", "a real passphrase");
  const tampered = Buffer.from(blob);
  tampered[tampered.length - 1] ^= 0xff; // flip the last real ciphertext byte
  assert.throws(() => decrypt(tampered, "a real passphrase"));
});

test("a too-short payload fails honestly instead of reading out-of-bounds", () => {
  assert.throws(() => decrypt(Buffer.from("short"), "any passphrase"), /too short/);
});

test("two real encryptions of the same plaintext produce different ciphertext (real random salt/iv)", () => {
  const a = encrypt("same text", "same passphrase");
  const b = encrypt("same text", "same passphrase");
  assert.notEqual(a.toString("hex"), b.toString("hex"));
  // both still decrypt to the same real plaintext
  assert.equal(decrypt(a, "same passphrase"), "same text");
  assert.equal(decrypt(b, "same passphrase"), "same text");
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
