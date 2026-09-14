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
  await assert.rejects(
    Promise.all([
      shareEnv({ envText: "secret", roomCode, passphrase: "the real one" }),
      receiveEnv({ roomCode, passphrase: "the wrong one" }),
    ]),
    /decrypt/i
  );
});

test("receiveEnv times out honestly when no real peer ever announces", async () => {
  const roomCode = `test-nobody-${crypto.randomBytes(4).toString("hex")}`;
  await assert.rejects(
    receiveEnv({ roomCode, passphrase: "irrelevant", timeoutMs: 300 }),
    /No matching .* peer found/
  );
});
