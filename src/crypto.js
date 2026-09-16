// [DAN] ARRAY — generic passphrase encryption. Basic tier: AES-256-GCM + scrypt key derivation,
// Node's own stdlib `crypto`, the same real primitive family age/sops use for password mode.
// The advanced tier (DAN ENCRYPTED MODULE) is a genuinely different, proprietary mechanism and
// lives only inside DAN MEMORY SMASH's own frontend — never here.
import crypto from "node:crypto";

const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase, salt, KEY_LEN, SCRYPT_OPTS);
}

// Wire format: salt(16) || iv(12) || tag(16) || ciphertext. Self-contained — the receiver needs
// nothing but this buffer and the passphrase to decrypt.
export function encrypt(plaintext, passphrase) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, ciphertext]);
}

// Throws on a wrong passphrase or corrupted data — GCM's auth tag makes tampering and a wrong
// key indistinguishable from "invalid", which is the honest answer in both cases.
export function decrypt(blob, passphrase) {
  if (blob.length < SALT_LEN + IV_LEN + TAG_LEN) throw new Error("payload too short to be valid");
  const salt = blob.subarray(0, SALT_LEN);
  const iv = blob.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const tag = blob.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
  const ciphertext = blob.subarray(SALT_LEN + IV_LEN + TAG_LEN);
  const key = deriveKey(passphrase, salt);
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

// scrypt over a room-bound salt → the passphrase key that is mixed into the session key. Same hardening
// (N=16384) the payload encryption uses, so a captured capsule is no cheaper to attack than the blob.
export function passphraseKey(passphrase, roomCode) {
  return crypto.scryptSync(passphrase, Buffer.from(roomHash(roomCode), "utf8"), KEY_LEN, SCRYPT_OPTS);
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
