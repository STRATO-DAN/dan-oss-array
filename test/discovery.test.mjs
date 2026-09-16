// UDP discovery had NO test coverage at all before this file. startListening()'s own filter — real
// app name, real protocol version, real room-hash match, tcpPort really an integer — is exercised
// here against genuinely malformed, adversarial packets: non-JSON garbage, wrong app/version, a
// DIFFERENT room's real-shaped announcement, type-confused fields, and an oversized datagram. None
// of these may ever trigger onFound for a room they don't match.
import { test } from "node:test";
import assert from "node:assert/strict";
import dgram from "node:dgram";
import { startListening, DISCOVERY_PORT } from "../src/discovery.js";
import { roomHash } from "../src/crypto.js";

function sendRaw(buf) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket("udp4");
    s.send(buf, DISCOVERY_PORT, "127.0.0.1", (err) => {
      s.close();
      err ? reject(err) : resolve();
    });
  });
}
function sendJson(obj) {
  return sendRaw(Buffer.from(JSON.stringify(obj)));
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// The listener binds the SAME fixed DISCOVERY_PORT every time, so tests run sequentially (this
// file's default node:test behavior) with a short settle delay between them to avoid a transient
// EADDRINUSE from the previous test's socket not having fully released the port yet.
async function withListener(roomCode, fn) {
  let found = null;
  const listener = startListening({ roomCode, onFound: (f) => { found = f; } });
  try {
    await fn(() => found);
  } finally {
    listener.stop();
    await wait(60);
  }
}

test("ADVERSARIAL: non-JSON garbage on the discovery port is silently ignored, never crashes the listener", () =>
  withListener("room-json-garbage", async (getFound) => {
    await sendRaw(Buffer.from("not json at all {{{"));
    await sendRaw(Buffer.from([0x00, 0xff, 0x13, 0x88, 0xde, 0xad, 0xbe, 0xef])); // raw binary junk
    await wait(100);
    assert.equal(getFound(), null, "garbage must never be mistaken for a real announcement");
  }));

test("ADVERSARIAL: a well-formed announcement for a DIFFERENT room is ignored (no cross-room leakage)", () =>
  withListener("room-mine", async (getFound) => {
    await sendJson({ app: "dan-oss-array", v: 1, roomHash: roomHash("room-SOMEONE-ELSES"), tcpPort: 9999 });
    await wait(100);
    assert.equal(getFound(), null, "a real announcement for a room this listener never asked about must not fire onFound");
  }));

test("ADVERSARIAL: wrong app name / wrong protocol version / non-integer tcpPort are each refused", () =>
  withListener("room-strict-fields", async (getFound) => {
    const hash = roomHash("room-strict-fields");
    await sendJson({ app: "some-other-tool", v: 1, roomHash: hash, tcpPort: 1234 });      // wrong app
    await sendJson({ app: "dan-oss-array", v: 2, roomHash: hash, tcpPort: 1234 });          // wrong version
    await sendJson({ app: "dan-oss-array", v: 1, roomHash: hash, tcpPort: "1234" });        // type-confused port (string, not int)
    await sendJson({ app: "dan-oss-array", v: 1, roomHash: hash, tcpPort: 80.5 });          // non-integer number
    await sendJson({ app: "dan-oss-array", v: 1, roomHash: hash });                          // missing tcpPort entirely
    await wait(100);
    assert.equal(getFound(), null, "every field must be validated — none of these near-misses may be accepted as a real announcement");
  }));

test("ADVERSARIAL: an oversized UDP datagram (near the practical max) does not crash the listener or false-positive", () =>
  withListener("room-oversized", async (getFound) => {
    // ~60KB — well past any real announcement, close to the practical UDP payload ceiling.
    const huge = Buffer.concat([Buffer.from('{"app":"dan-oss-array","v":1,"roomHash":"'), Buffer.alloc(60_000, 0x41), Buffer.from('"}')]);
    await sendRaw(huge).catch(() => {}); // some platforms refuse to send oversized datagrams — either outcome is fine, it must not crash the receiver
    await wait(100);
    assert.equal(getFound(), null, "an oversized/garbled datagram must never be accepted as a match");
    // the listener must still be alive and correct after the oversized packet — a REAL matching
    // announcement sent right after must still be found.
    await sendJson({ app: "dan-oss-array", v: 1, roomHash: roomHash("room-oversized"), tcpPort: 4242 });
    await wait(100);
    assert.deepEqual(getFound(), { address: "127.0.0.1", tcpPort: 4242 });
  }));

test("ADVERSARIAL: after a real match latches, a later announcement (even a different, also-valid one) never overwrites it", () =>
  withListener("room-latch", async (getFound) => {
    const hash = roomHash("room-latch");
    await sendJson({ app: "dan-oss-array", v: 1, roomHash: hash, tcpPort: 1111 });
    await wait(60);
    assert.deepEqual(getFound(), { address: "127.0.0.1", tcpPort: 1111 });
    // a second, equally well-formed announcement for the SAME room (simulating two sharers
    // racing / a broadcast collision) must not silently replace the first result.
    await sendJson({ app: "dan-oss-array", v: 1, roomHash: hash, tcpPort: 2222 });
    await wait(60);
    assert.deepEqual(getFound(), { address: "127.0.0.1", tcpPort: 1111 }, "the first real match wins; a colliding second announcer does not overwrite it");
  }));

test("real happy path: a genuine announcement is found with the real sender address and port", () =>
  withListener("room-happy", async (getFound) => {
    await sendJson({ app: "dan-oss-array", v: 1, roomHash: roomHash("room-happy"), tcpPort: 5555 });
    await wait(100);
    assert.deepEqual(getFound(), { address: "127.0.0.1", tcpPort: 5555 });
  }));
