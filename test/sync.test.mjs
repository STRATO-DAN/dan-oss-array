// Real integration test — a real sender and receiver, real UDP broadcast discovery, real TCP
// transfer, on the actual network stack (loopback), not mocked sockets.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import dgram from "node:dgram";
import { shareEnv, receiveEnv } from "../src/sync.js";
import { roomHash } from "../src/crypto.js";
import { DISCOVERY_PORT } from "../src/discovery.js";

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
  // receiver fails with an honest decrypt error. The receiver now retries announcers until its own window
  // closes (see the spoofer test below), so it is given a bounded timeout too.
  const share = shareEnv({ envText: "secret", roomCode, passphrase: "the real one", timeoutMs: 3000 }).catch(() => {});
  await assert.rejects(receiveEnv({ roomCode, passphrase: "the wrong one", timeoutMs: 2000 }), /decrypt/i);
  await share;
});

test("A3: a spoofing announcer that can't complete the handshake does not deny the real transfer — the receiver tries the next announcer", async () => {
  const roomCode = `test-spoof-${crypto.randomBytes(4).toString("hex")}`;
  const passphrase = "a real shared passphrase";
  const envText = "API_KEY=demo-only\nDB_URL=postgres://localhost/example\n";

  // A spoofer that wins the discovery race: it announces the SAME room hash on a bogus TCP port that
  // nothing listens on. If the receiver committed to the FIRST announcer (the old behaviour), the whole
  // transfer would fail on that dead port. It must instead skip the spoofer and complete with the real one.
  const hash = roomHash(roomCode);
  const spoof = dgram.createSocket("udp4");
  await new Promise((r) => spoof.bind(r));
  spoof.setBroadcast(true);
  const bogusPort = 1; // nothing listens here → the receiver's fetch fails fast (ECONNREFUSED)
  const spoofMsg = Buffer.from(JSON.stringify({ app: "dan-oss-array", v: 1, roomHash: hash, tcpPort: bogusPort }));
  const spoofTimer = setInterval(() => spoof.send(spoofMsg, DISCOVERY_PORT, "255.255.255.255"), 200);
  spoof.send(spoofMsg, DISCOVERY_PORT, "255.255.255.255");

  try {
    // Start the receiver first and let it see ONLY the spoofer for a moment, so it genuinely commits to a
    // bad announcer before the real sharer appears — that makes this a real fail-before/pass-after test.
    const recvP = receiveEnv({ roomCode, passphrase, timeoutMs: 8000 });
    await new Promise((r) => setTimeout(r, 300));
    const shareP = shareEnv({ envText, roomCode, passphrase, timeoutMs: 8000 });

    const [, receiveResult] = await Promise.all([shareP, recvP]);
    assert.equal(receiveResult.ok, true);
    assert.equal(receiveResult.envText, envText, "the real transfer completes despite the spoofing announcer");
  } finally {
    clearInterval(spoofTimer);
    spoof.close();
  }
});

test("receiveEnv times out honestly when no real peer ever announces", async () => {
  const roomCode = `test-nobody-${crypto.randomBytes(4).toString("hex")}`;
  await assert.rejects(
    receiveEnv({ roomCode, passphrase: "irrelevant", timeoutMs: 300 }),
    /No matching .* peer found/
  );
});
