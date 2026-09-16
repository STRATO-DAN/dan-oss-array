// [DAN] ARRAY — authenticated transport (v2). The v1 transport handed the encrypted blob to the FIRST
// peer that connected, with no proof of who they were: a host on the same LAN that won the connection
// race got the ciphertext (and could deny the real receiver). This layer fixes that WITHOUT adding a
// dependency — everything here is Node's own `crypto`.
//
//   • Ephemeral X25519 per transfer → a fresh key agreement (forward secrecy). The session key is
//     HKDF(sharedSecret ‖ scrypt(passphrase, roomHash), transcript) — it needs BOTH the ephemeral
//     secret AND the passphrase, so knowing one is useless.
//   • The RECEIVER proves the passphrase FIRST (a MAC over the transcript). The sharer verifies it
//     before releasing anything, so an unauthenticated racer is refused and the sharer keeps waiting
//     for the right peer — the credential is never sent to a peer that hasn't proven the passphrase.
//   • The credential travels as ONE sealed CAPSULE keyed by that same session key — credential and
//     handshake bound together, not a separate plaintext-keyed step. A wrong passphrase (or an
//     impostor sharer) yields a capsule that will not open.
//   • Every frame is length-prefixed and hard-capped, and total received bytes are capped — so the
//     receive path can no longer be made to buffer without bound.
//
// Residual (honest, inherent to a passphrase and no PKI): an ACTIVE impostor that lures a receiver and
// wins its discovery race obtains one transcript MAC it can attack OFFLINE against the passphrase —
// scrypt (N=16384) makes that costly, and it yields a passphrase guess, never the payload of a past
// session (that rode an ephemeral key the attacker never had). Higher assurance = the advanced tier.
import crypto from "node:crypto";
import { passphraseKey, sealCapsule, openCapsule } from "./crypto.js";

const HS_FRAME_CAP = 8 * 1024; // hello/confirm frames are tiny — this is generous
export const CAPSULE_CAP = 4 * 1024 * 1024; // an env file is small; this bounds one sealed capsule
const TOTAL_CAP = CAPSULE_CAP + 64 * 1024; // hard cap on everything a peer may ever send us
const HKDF_INFO = Buffer.from("dan-oss-array/v2 session");
const T_RECEIVER = Buffer.from("confirm-receiver");

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}
function writeFrame(socket, buf) {
  socket.write(Buffer.concat([u32(buf.length), buf]));
}
function equal(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// A length-prefixed frame reader with a per-frame cap AND a total-bytes cap. The total cap is the real
// fix for unbounded buffering: a peer can never make us hold more than TOTAL_CAP, whatever it streams.
function frameReader(socket) {
  let buf = Buffer.alloc(0);
  let total = 0;
  let ended = false;
  let failure = null;
  let waiter = null;

  const pump = () => {
    if (!waiter) return;
    if (failure) {
      const w = waiter;
      waiter = null;
      return w.reject(failure);
    }
    if (buf.length >= 4) {
      const len = buf.readUInt32BE(0);
      if (len > waiter.cap) {
        const w = waiter;
        waiter = null;
        socket.destroy();
        return w.reject(new Error(`frame length ${len} exceeds cap ${w.cap} — refused`));
      }
      if (buf.length >= 4 + len) {
        const out = Buffer.from(buf.subarray(4, 4 + len));
        buf = buf.subarray(4 + len);
        const w = waiter;
        waiter = null;
        return w.resolve(out);
      }
    }
    if (ended) {
      const w = waiter;
      waiter = null;
      return w.reject(new Error("the connection ended before a full message arrived"));
    }
  };

  socket.on("data", (chunk) => {
    total += chunk.length;
    if (total > TOTAL_CAP) {
      failure = new Error("transport exceeded its total byte cap — refused");
      socket.destroy();
      return pump();
    }
    buf = Buffer.concat([buf, chunk]);
    pump();
  });
  socket.on("end", () => {
    ended = true;
    pump();
  });
  socket.on("error", (e) => {
    failure = e;
    pump();
  });

  return (cap = HS_FRAME_CAP) => new Promise((resolve, reject) => {
    waiter = { resolve, reject, cap };
    pump();
  });
}

function ephemeral() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  return { pub: publicKey.export({ type: "spki", format: "der" }), privateKey };
}

// Derive the shared session key + the receiver's confirmation MAC. `pubR`/`pubS` are the receiver's and
// sharer's ephemeral public keys; both sides pass them in the SAME order, so both compute the same key.
function session(privateKey, peerPubDer, pubR, pubS, passphrase, roomCode) {
  const peer = crypto.createPublicKey({ key: peerPubDer, type: "spki", format: "der" });
  const shared = crypto.diffieHellman({ privateKey, publicKey: peer });
  const pk = passphraseKey(passphrase, roomCode);
  const transcript = Buffer.concat([pubR, pubS]);
  const sk = Buffer.from(crypto.hkdfSync("sha256", Buffer.concat([shared, pk]), transcript, HKDF_INFO, 32));
  const confirmR = crypto.createHmac("sha256", sk).update(Buffer.concat([T_RECEIVER, transcript])).digest();
  return { sk, confirmR };
}

// SHARER side of an inbound connection. Verifies the receiver knows the passphrase (bound to THIS key
// agreement) BEFORE releasing anything, then hands over exactly one sealed capsule. Throws if the peer
// cannot authenticate — the caller destroys that socket and keeps listening for the right peer.
export async function sharerServe(socket, { passphrase, roomCode, capsulePlain }) {
  const read = frameReader(socket);
  const me = ephemeral();
  const pubR = await read(); // HELLO from the receiver
  writeFrame(socket, me.pub); // HELLO back
  const { sk, confirmR } = session(me.privateKey, pubR, pubR, me.pub, passphrase, roomCode);
  const got = await read(); // the receiver's passphrase proof
  if (!equal(got, confirmR)) throw new Error("peer did not prove the passphrase — refused");
  writeFrame(socket, sealCapsule(sk, capsulePlain)); // the credential, sealed under the authenticated session
}

// RECEIVER side. Connects, proves the passphrase, opens the one sealed capsule. A wrong passphrase (or
// an impostor sharer that doesn't know it) yields a capsule that will not open — surfaced by the caller
// as a decrypt failure, which is the honest answer in both cases.
export async function receiverFetch(socket, { passphrase, roomCode }) {
  const read = frameReader(socket);
  const me = ephemeral();
  writeFrame(socket, me.pub); // HELLO
  const pubS = await read(); // HELLO from the sharer
  const { sk, confirmR } = session(me.privateKey, pubS, me.pub, pubS, passphrase, roomCode);
  writeFrame(socket, confirmR); // prove the passphrase first
  const capsule = await read(CAPSULE_CAP + 64); // the sealed credential
  return openCapsule(sk, capsule); // throws on a wrong session key (wrong passphrase / impostor)
}
