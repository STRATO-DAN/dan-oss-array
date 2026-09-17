// [DAN] ARRAY — generic passphrase encryption. Basic tier: AES-256-GCM + scrypt key derivation,
// Node's own stdlib `crypto`, the same real primitive family age/sops use for password mode.
// The advanced tier (DAN ENCRYPTED MODULE) is a genuinely different, proprietary mechanism and
// lives only inside DAN MEMORY SMASH's own frontend — never here.
import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);

const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };

// scrypt at N=16384 is deliberately slow; the SYNC version blocks Node's single event-loop thread for
// its full duration, freezing every other socket and timer. This derivation now runs on the libuv
// threadpool (async scrypt) — the payload path matches the handshake path, which was moved async in
// 0.2.1. The wire format is unchanged, so a blob is byte-for-byte compatible with the previous release.
async function deriveKey(passphrase, salt) {
  return scrypt(passphrase, salt, KEY_LEN, SCRYPT_OPTS);
}

// Wire format: salt(16) || iv(12) || tag(16) || ciphertext. Self-contained — the receiver needs
// nothing but this buffer and the passphrase to decrypt. Async so scrypt never blocks the event loop.
export async function encrypt(plaintext, passphrase) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = await deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, ciphertext]);
}

// Throws on a wrong passphrase or corrupted data — GCM's auth tag makes tampering and a wrong
// key indistinguishable from "invalid", which is the honest answer in both cases.
export async function decrypt(blob, passphrase) {
  if (blob.length < SALT_LEN + IV_LEN + TAG_LEN) throw new Error("payload too short to be valid");
  const salt = blob.subarray(0, SALT_LEN);
  const iv = blob.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const tag = blob.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const ciphertext = blob.subarray(SALT_LEN + IV_LEN + TAG_LEN);
  const key = await deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}

export function roomHash(roomCode) {
  return crypto.createHash("sha256").update(roomCode).digest("hex").slice(0, 16);
}

// ── authenticated-transport primitives (v2) ─────────────────────────────────────────────────────
// The transport binds the CREDENTIAL and the HANDSHAKE together: the secret only ever travels as ONE
// sealed CAPSULE, keyed by a session key that is derived from BOTH an ephemeral key agreement AND the
// passphrase (see handshake.js). No unauthenticated peer can open it, and none is ever handed it.

// Per-session scrypt salt for the passphrase KDF. roomHash alone is a PUBLIC constant — it is broadcast
// on the LAN in every announce packet — so using it as the sole salt made the derived passphrase key
// IDENTICAL across every session in a room, letting an offline guessing effort be amortised across all
// of them. Folding in the per-session handshake transcript (the exchanged ephemeral public keys, which
// both sides already share) makes the salt unique per handshake without exchanging anything extra. Both
// peers pass the SAME transcript in the SAME order, so both still derive the same key — interop holds.
function kdfSalt(roomCode, transcript) {
  const h = crypto.createHash("sha256").update(Buffer.from(roomHash(roomCode), "utf8"));
  if (transcript) h.update(transcript);
  return h.digest();
}

// scrypt over the per-session salt → the passphrase key that is mixed into the session key. Same
// hardening (N=16384) the payload encryption uses, so a captured capsule is no cheaper to attack.
export function passphraseKey(passphrase, roomCode, transcript) {
  return crypto.scryptSync(passphrase, kdfSalt(roomCode, transcript), KEY_LEN, SCRYPT_OPTS);
}

// Async twin of passphraseKey, used by the handshake. scrypt is deliberately expensive (N=16384); the
// SYNC version blocks Node's single event-loop thread for its full duration, so an unauthenticated peer
// that merely connects (the sharer must derive this key to check the peer's proof) could stall the whole
// process — a cheap denial-of-service that needs no valid passphrase. The async version runs on the
// libuv threadpool, so one handshake's key derivation no longer freezes every other socket and timer.
export async function passphraseKeyAsync(passphrase, roomCode, transcript) {
  return scrypt(passphrase, kdfSalt(roomCode, transcript), KEY_LEN, SCRYPT_OPTS);
}

// Domain-separated session subkeys from one shared IKM (the ECDH secret ‖ the passphrase key). Two
// distinct HKDF `info` labels yield INDEPENDENT keys for the capsule cipher and the handshake
// confirmation MAC — so the MAC that travels in the clear during the handshake shares no key material
// with the capsule encryption (previously a single session key served as both roles). Both peers derive
// the same IKM and transcript, so both compute the same pair — interop preserved.
const HKDF_ENC = Buffer.from("dan-oss-array/v2 capsule-enc");
const HKDF_MAC = Buffer.from("dan-oss-array/v2 confirm-mac");
export function deriveSessionKeys(ikm, transcript) {
  const kEnc = Buffer.from(crypto.hkdfSync("sha256", ikm, transcript, HKDF_ENC, KEY_LEN));
  const kMac = Buffer.from(crypto.hkdfSync("sha256", ikm, transcript, HKDF_MAC, KEY_LEN));
  return { kEnc, kMac };
}

// Seal one capsule under the raw session key. Wire: iv(12) || tag(16) || ciphertext.
export function sealCapsule(sessionKey, data) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv("aes-256-gcm", sessionKey, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

// Open a capsule. Throws (GCM auth) on the wrong session key — i.e. a wrong passphrase or an impostor
// peer — which is the honest answer and, wrapped by the caller, reads as a "could not decrypt" failure.
export function openCapsule(sessionKey, capsule) {
  if (capsule.length < IV_LEN + TAG_LEN) throw new Error("capsule too short to be valid");
  const iv = capsule.subarray(0, IV_LEN);
  const tag = capsule.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = capsule.subarray(IV_LEN + TAG_LEN);
  const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
