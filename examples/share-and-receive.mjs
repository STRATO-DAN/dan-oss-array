// Real, runnable example — two real peers (sender + receiver) in one process, using this
// package's own library functions directly: real UDP broadcast discovery, real TCP transfer,
// real AES-256-GCM encryption. In practice these run as separate `shareEnv`/`receiveEnv` calls
// on two different machines; running both here in one process still exercises the real network
// calls end-to-end (same technique used to verify this tool during its own development).
//
//   node examples/share-and-receive.mjs
//
import crypto from "node:crypto";
import { shareEnv, receiveEnv } from "../src/sync.js";

const roomCode = `example-${crypto.randomBytes(4).toString("hex")}`;
const passphrase = "correct horse battery staple";
const envText = "API_KEY=demo-only-not-real\nDB_URL=postgres://localhost/example\n";

console.log(`Room: ${roomCode}`);
console.log("Starting sender and receiver concurrently — real UDP discovery, real TCP transfer...\n");

const [sendResult, receiveResult] = await Promise.all([
  shareEnv({ envText, roomCode, passphrase }),
  receiveEnv({ roomCode, passphrase }),
]);

console.log("Sender result:", sendResult);
console.log("Receiver result:", { ...receiveResult, envText: receiveResult.envText.length + " chars" });
console.log("\nReceived text matches what was sent:", receiveResult.envText === envText);

// A real, honest failure case: wrong passphrase never silently "succeeds" with garbage. The sharer
// refuses the unproven peer and keeps listening, and the receiver keeps trying announcers until its
// window closes — so both are given a short, explicit window here to demonstrate the honest failure.
console.log("\nNow trying with a WRONG passphrase — should fail loudly, not decrypt garbage:");
const wrongRoomCode = `example-${crypto.randomBytes(4).toString("hex")}`;
try {
  await Promise.all([
    shareEnv({ envText, roomCode: wrongRoomCode, passphrase, timeoutMs: 3000 }),
    receiveEnv({ roomCode: wrongRoomCode, passphrase: "the wrong passphrase entirely", timeoutMs: 3000 }),
  ]);
} catch (err) {
  console.log("Failed as expected:", err.message);
}
