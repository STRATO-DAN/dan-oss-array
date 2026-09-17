// Reproducible crypto-core demo — no LAN, no sockets, no dependencies. Exercises the real
// passphrase encryption from src/crypto.js: seal a secret .env payload under a passphrase and open
// it back (success), then prove that a WRONG passphrase and a TAMPERED ciphertext both fail loudly
// (AES-256-GCM's auth tag makes silent corruption impossible). Run: `make demo` or `node scripts/demo.mjs`.
import { encrypt, decrypt } from "../src/crypto.js";

const passphrase = "correct horse battery staple";
const secret = "API_KEY=demo-only-not-real\nDB_URL=postgres://localhost/example\n";

console.log("[DAN] ARRAY — crypto-core demo (AES-256-GCM + scrypt, Node stdlib only)\n");

// 1. Seal, then open with the right passphrase.
const sealed = await encrypt(secret, passphrase);
console.log(`1. Sealed ${secret.length}-byte secret → ${sealed.length}-byte blob`);
console.log(`   wire format: salt(16) || iv(12) || tag(16) || ciphertext`);
const opened = await decrypt(sealed, passphrase);
console.log(`   Opened with the correct passphrase → round-trip matches: ${opened === secret}\n`);

// 2. Wrong passphrase must fail, never return garbage.
console.log("2. Opening the same blob with a WRONG passphrase:");
try {
  await decrypt(sealed, "the wrong passphrase entirely");
  console.log("   UNEXPECTED: decrypt succeeded with the wrong passphrase");
  process.exit(1);
} catch (err) {
  console.log(`   Rejected as expected: ${err.message}\n`);
}

// 3. Tampered ciphertext must fail — flip one byte in the ciphertext region.
console.log("3. Opening a TAMPERED blob (one ciphertext byte flipped) with the right passphrase:");
const tampered = Buffer.from(sealed);
tampered[tampered.length - 1] ^= 0x01;
try {
  await decrypt(tampered, passphrase);
  console.log("   UNEXPECTED: decrypt succeeded on tampered ciphertext");
  process.exit(1);
} catch (err) {
  console.log(`   Rejected as expected: ${err.message}\n`);
}

console.log("Demo complete — seal/open works, wrong passphrase and tampering both fail loudly.");
