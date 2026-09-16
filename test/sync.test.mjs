// Real integration test — a real sender and receiver, real UDP broadcast discovery, real TCP
// transfer, on the actual network stack (loopback), not mocked sockets.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { shareEnv, receiveEnv } from "../src/sync.js";

test("a real sender and receiver find each other and transfer the exact real plaintext", async () => {
  const roomCode = `test-${crypto.randomBytes(4).toString("hex")}`;
  const passphrase = "a real shared passphrase";
  const envText = "API_KEY=demo-only\nDB_URL=postgres://localhost/example\n";

  const [sendResult, receiveResult] = await Promise.all([
    shareEnv({ envText, roomCode, passphrase }),
    receiveEnv({ roomCode, passphrase }),
  ]);

  assert.equal(sendResult.ok, true);
  assert.equal(receiveResult.ok, true);
  assert.equal(receiveResult.envText, envText);
});

test("a real receiver with the wrong passphrase fails honestly, not with garbage text", async () => {
  const roomCode = `test-${crypto.randomBytes(4).toString("hex")}`;
  // The sharer now REFUSES a peer that can't prove the passphrase and keeps listening (it never blindly
  // hands the capsule to a racer) — so give it a short window and swallow its timeout while we assert the
  // receiver fails with an honest decrypt error. Same intent as before, stronger behaviour underneath.
  const share = shareEnv({ envText: "secret", roomCode, passphrase: "the real one", timeoutMs: 3000 }).catch(() => {});
  await assert.rejects(receiveEnv({ roomCode, passphrase: "the wrong one" }), /decrypt/i);
  await share;
});

test("receiveEnv times out honestly when no real peer ever announces", async () => {
  const roomCode = `test-nobody-${crypto.randomBytes(4).toString("hex")}`;
  await assert.rejects(
    receiveEnv({ roomCode, passphrase: "irrelevant", timeoutMs: 300 }),
    /No matching .* peer found/
  );
});
