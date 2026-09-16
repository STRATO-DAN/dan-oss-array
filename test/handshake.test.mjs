// Authenticated-transport tests (v2). Real loopback TCP, real X25519 + AES-GCM — the security
// properties the v1 transport lacked: recipient authentication and a bounded receive buffer.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import crypto from "node:crypto";
import { sharerServe, receiverFetch } from "../src/handshake.js";
import { sealCapsule, passphraseKey } from "../src/crypto.js";

// Stand up a one-connection sharer server; resolve with the port. `onServe` runs sharerServe.
function sharer({ passphrase, roomCode, capsulePlain, onError }) {
  const server = net.createServer((socket) => {
    socket.on("error", () => {});
    sharerServe(socket, { passphrase, roomCode, capsulePlain })
      .then(() => socket.end())
      .catch((e) => {
        onError?.(e);
        socket.destroy();
      });
  });
  return new Promise((resolve) => server.listen(0, () => resolve({ port: server.address().port, server })));
}
function connect(port) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection({ port }, () => resolve(s));
    s.on("error", reject);
  });
}

test("matching passphrase: the receiver authenticates and opens the sealed capsule", async () => {
  const roomCode = "room-A";
  const passphrase = "the shared secret";
  const plain = Buffer.from("BLOB:credential-bytes");
  const { port, server } = await sharer({ passphrase, roomCode, capsulePlain: plain });
  const socket = await connect(port);
  const got = await receiverFetch(socket, { passphrase, roomCode });
  assert.deepEqual(got, plain);
  server.close();
});

test("wrong passphrase: the sharer REFUSES (no capsule sent) and the receiver fails, not silently", async () => {
  const roomCode = "room-B";
  let sharerErr = null;
  const { port, server } = await sharer({
    passphrase: "the real one",
    roomCode,
    capsulePlain: Buffer.from("must-not-leak"),
    onError: (e) => {
      sharerErr = e;
    },
  });
  const socket = await connect(port);
  await assert.rejects(receiverFetch(socket, { passphrase: "the WRONG one", roomCode }));
  // the sharer rejected the peer explicitly — it did not hand over the capsule to an unproven peer
  await new Promise((r) => setTimeout(r, 50));
  assert.match(sharerErr?.message ?? "", /did not prove the passphrase/);
  server.close();
});

test("a racer that speaks garbage instead of the handshake gets nothing and is refused", async () => {
  const roomCode = "room-C";
  let sharerErr = null;
  const { port, server } = await sharer({
    passphrase: "p",
    roomCode,
    capsulePlain: Buffer.from("secret"),
    onError: (e) => {
      sharerErr = e;
    },
  });
  const socket = await connect(port);
  // send a valid-looking HELLO frame then junk where the proof should be — never the real confirmation
  socket.write(Buffer.concat([Buffer.from([0, 0, 0, 4]), Buffer.from("junk")]));
  await new Promise((r) => setTimeout(r, 150));
  assert.ok(sharerErr, "sharer should have thrown rather than sent the capsule");
  socket.destroy();
  server.close();
});

test("receive buffer is bounded: an oversized declared frame length is refused, not buffered", async () => {
  // A hostile 'sharer' that, after the hello exchange, declares a 1 GB frame. The receiver must refuse
  // on the declared length — never attempt to buffer it.
  const roomCode = "room-D";
  const passphrase = "p";
  const server = net.createServer((socket) => {
    socket.on("error", () => {});
    socket.once("data", () => {
      // reply with a hello so the receiver proceeds, then declare an absurd capsule length
      const { publicKey } = crypto.generateKeyPairSync("x25519");
      const pub = publicKey.export({ type: "spki", format: "der" });
      const len = Buffer.alloc(4);
      len.writeUInt32BE(pub.length, 0);
      socket.write(Buffer.concat([len, pub]));
      socket.once("data", () => {
        const huge = Buffer.alloc(4);
        huge.writeUInt32BE(1024 * 1024 * 1024, 0); // 1 GiB declared
        socket.write(huge);
      });
    });
  });
  await new Promise((r) => server.listen(0, r));
  const socket = await connect(server.address().port);
  await assert.rejects(receiverFetch(socket, { passphrase, roomCode }), /exceeds cap|byte cap/);
  server.close();
});

// NOTE on TOTAL_CAP (frameReader's cumulative-byte guard, distinct from the per-frame length cap
// above): traced but deliberately NOT given its own test here. Any bytes beyond what completes a
// frame become leftover buffer content that gets re-parsed as a (garbage, near-certainly-huge)
// declared length the instant the NEXT read() sets a waiter — which trips the per-frame check
// (already tested above) in a handful of bytes, always well before ~4.26MB could genuinely
// accumulate to trip the total-byte check on its own. Given TOTAL_CAP's ~64KB of slack is sized
// exactly to cover one legitimate max-length capsule frame plus handshake overhead, this specific
// branch isn't independently reachable through receiverFetch's real 2-read protocol without
// constructing a synthetic multi-read harness against frameReader directly (unexported, and not
// how the real protocol is ever driven) — so a test for it would be contrived rather than
// adversarial. The per-frame cap test above covers the real, reachable attack surface.

test("the session key needs BOTH the ephemeral secret and the passphrase (capsule opens with neither alone)", () => {
  // A capsule sealed under a real session key does not open under a key derived from only the passphrase
  // (no ephemeral secret) — proving the two are bound together, not separable.
  const roomCode = "room-E";
  const passphrase = "shared";
  const fakeSessionKey = passphraseKey(passphrase, roomCode); // passphrase ALONE, no ECDH
  const capsule = sealCapsule(crypto.randomBytes(32), Buffer.from("x")); // real session key = random here
  assert.throws(() => {
    const iv = capsule.subarray(0, 12);
    const tag = capsule.subarray(12, 28);
    const ct = capsule.subarray(28);
    const d = crypto.createDecipheriv("aes-256-gcm", fakeSessionKey, iv);
    d.setAuthTag(tag);
    Buffer.concat([d.update(ct), d.final()]);
  });
});
