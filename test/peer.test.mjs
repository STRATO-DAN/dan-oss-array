// Peer-transport liveness/DoS bounds (listenForOnePeer). The authenticated handshake derives an
// expensive scrypt key for EVERY inbound peer (before it can prove the passphrase), so an unauthenticated
// peer that connects then stalls must not tie up the sharer — it is dropped at a hard handshake deadline,
// and the sharer keeps listening for the real receiver. Real loopback TCP, no mocks.
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { listenForOnePeer, fetchOnce } from "../src/peer.js";

test("liveness: a peer that stalls the handshake is dropped at the deadline, and the real receiver is still served", async () => {
  const roomCode = "room-liveness";
  const passphrase = "the shared secret";
  const plain = Buffer.from("BLOB:the-credential-bytes");

  const sharer = listenForOnePeer({ passphrase, roomCode, handshakeTimeoutMs: 200 });
  const port = await sharer.ready;
  const served = sharer.send(plain);

  // A stalled peer: connect, then send nothing. It must be dropped at the handshake deadline (the sharer
  // closes the socket) WITHOUT settling the transfer — the credential is never handed to it.
  const stalled = await new Promise((resolve, reject) => {
    const s = net.createConnection({ port }, () => resolve(s));
    s.on("error", reject);
  });
  let stalledClosed = false;
  stalled.on("close", () => {
    stalledClosed = true;
  });
  await new Promise((r) => setTimeout(r, 400)); // well past the 200ms handshake deadline
  assert.equal(stalledClosed, true, "the stalled peer's socket is dropped at the handshake deadline");

  // The real receiver still completes the handshake and opens the capsule — the sharer kept listening.
  const got = await fetchOnce({ address: "127.0.0.1", port, passphrase, roomCode });
  assert.deepEqual(got, plain, "the real, authenticated receiver still gets the credential after the stalled peer was dropped");
  await served; // the sharer settled on the real peer, not the stalled one
});

test("liveness: extra connections beyond the concurrency cap are dropped, not queued as unbounded scrypt work", async () => {
  const roomCode = "room-cap";
  const passphrase = "the shared secret";
  const plain = Buffer.from("BLOB:x");

  // Cap = 1: one stalled peer fills the only handshake slot; a second connection must be dropped
  // immediately (not admitted into another expensive handshake).
  const sharer = listenForOnePeer({ passphrase, roomCode, handshakeTimeoutMs: 5000, maxConcurrentHandshakes: 1 });
  const port = await sharer.ready;
  const served = sharer.send(plain);
  served.catch(() => {}); // stop() below settles this with a "stopped" rejection — expected, don't leak it

  const first = await new Promise((resolve, reject) => {
    const s = net.createConnection({ port }, () => resolve(s));
    s.on("error", reject);
  }); // occupies the single slot (then stalls)
  await new Promise((r) => setTimeout(r, 50));

  const second = await new Promise((resolve, reject) => {
    const s = net.createConnection({ port }, () => resolve(s));
    s.on("error", reject);
  });
  let secondClosed = false;
  second.on("close", () => {
    secondClosed = true;
  });
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(secondClosed, true, "a connection beyond the concurrency cap is dropped immediately");

  first.destroy();
  sharer.stop();
});
