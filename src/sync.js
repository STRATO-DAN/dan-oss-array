// [DAN] ARRAY — real orchestration: encrypt -> announce -> serve-once (share), or
// listen -> connect -> decrypt (receive). No server in either path but this machine and the peer.
import { encrypt, decrypt } from "./crypto.js";
import { startAnnouncing, startListening } from "./discovery.js";
import { listenForOnePeer, fetchOnce } from "./peer.js";

export async function shareEnv({ envText, roomCode, passphrase, timeoutMs = 120000 }) {
  const payload = encrypt(envText, passphrase);
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
  const found = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      listener.stop();
      reject(new Error("No matching [DAN] ARRAY peer found on this network within the time window."));
    }, timeoutMs);
    const listener = startListening({
      roomCode,
      onFound: (info) => {
        clearTimeout(timer);
        listener.stop();
        resolve(info);
      },
    });
  });

  let envText;
  try {
    // fetchOnce runs the authenticated handshake and returns the OPENED capsule (the encrypted blob);
    // a wrong passphrase fails the capsule open here, an impostor peer likewise — both honest failures.
    const blob = await fetchOnce({ address: found.address, port: found.tcpPort, passphrase, roomCode });
    envText = decrypt(blob, passphrase);
  } catch {
    throw new Error("Could not decrypt the received data — wrong passphrase, no authorised peer answered, or the payload was corrupted in transit.");
  }
  return { ok: true, envText, fromAddress: found.address };
}
