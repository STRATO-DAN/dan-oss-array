// [DAN] ARRAY — real orchestration: encrypt -> announce -> serve-once (share), or
// listen -> connect -> decrypt (receive). No server in either path but this machine and the peer.
import { encrypt, decrypt } from "./crypto.js";
import { startAnnouncing, startListening } from "./discovery.js";
import { listenForOnePeer, fetchOnce } from "./peer.js";

export async function shareEnv({ envText, roomCode, passphrase, timeoutMs = 120000 }) {
  const payload = await encrypt(envText, passphrase);
  const peer = listenForOnePeer({ passphrase, roomCode, timeoutMs });
  const tcpPort = await peer.ready;
  const announcer = startAnnouncing({ roomCode, tcpPort });
  try {
    const { peerAddress } = await peer.send(payload);
    return { ok: true, peerAddress };
  } finally {
    announcer.stop();
  }
}

export async function receiveEnv({ roomCode, passphrase, timeoutMs = 30000 }) {
  return new Promise((resolve, reject) => {
    let done = false;
    let sawAnnouncer = false;
    const tried = new Set(); // announcers we've already attempted, by address:port

    const finish = (fn, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      listener.stop();
      fn(value);
    };

    const timer = setTimeout(() => {
      // If we never even saw a matching announcer, that's the honest "nobody here" message; if we DID
      // try one or more announcers and none completed, it reads as a decrypt/authorisation failure.
      finish(
        reject,
        new Error(
          sawAnnouncer
            ? "Could not decrypt the received data — wrong passphrase, no authorised peer answered, or the payload was corrupted in transit."
            : "No matching [DAN] ARRAY peer found on this network within the time window."
        )
      );
    }, timeoutMs);

    // Keep listening for EVERY distinct announcer, not just the first. A spoofing LAN host that wins the
    // discovery race with a bogus announcement no longer denies the transfer: its fetch fails and we
    // simply try the next announcer, until one completes or the window closes. (Discovery itself is
    // unauthenticated — a DoS-adjacent residual SECURITY.md explicitly de-scopes; this makes the
    // transfer SURVIVE a spoofer rather than claiming to prevent one from announcing.)
    const listener = startListening({
      roomCode,
      once: false,
      onFound: async (info) => {
        if (done) return;
        const key = `${info.address}:${info.tcpPort}`;
        if (tried.has(key)) return; // same announcer re-broadcasting — don't hammer it
        tried.add(key);
        sawAnnouncer = true;
        try {
          // fetchOnce runs the authenticated handshake and returns the OPENED capsule (the encrypted
          // blob); a wrong passphrase fails the capsule open here, an impostor peer likewise.
          const blob = await fetchOnce({ address: info.address, port: info.tcpPort, passphrase, roomCode });
          const envText = await decrypt(blob, passphrase);
          finish(resolve, { ok: true, envText, fromAddress: info.address });
        } catch {
          // this announcer couldn't complete (spoofer, wrong peer, or corrupt payload) — keep listening
          // for another announcer rather than committing to the first and failing the whole transfer
        }
      },
    });
  });
}
