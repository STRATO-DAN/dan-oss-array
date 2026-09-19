// [DAN] ARRAY — real orchestration: encrypt -> announce -> serve-once (share), or
// listen -> connect -> decrypt (receive). No server in either path but this machine and the peer.
import { encrypt, decrypt } from "./crypto.js";
import { startAnnouncing, startListening } from "./discovery.js";
import { listenForOnePeer, fetchOnce } from "./peer.js";

export async function shareEnv({ envText, roomCode, passphrase, timeoutMs = 120000 }, { signal } = {}) {
  const abortedErr = () => {
    const e = new Error("share cancelled — the requesting client disconnected before a peer arrived.");
    e.name = "AbortError";
    return e;
  };
  if (signal?.aborted) throw abortedErr();
  const payload = await encrypt(envText, passphrase);
  if (signal?.aborted) throw abortedErr();
  const peer = listenForOnePeer({ passphrase, roomCode, timeoutMs });
  const tcpPort = await peer.ready;
  const announcer = startAnnouncing({ roomCode, tcpPort });
  // Cancellation coupling: a disconnected client stops the TCP listener AND the UDP announcer
  // immediately — share state never outlives the browser action that started it.
  const onAbort = () => {
    peer.stop();
    announcer.stop();
  };
  if (signal) signal.addEventListener("abort", onAbort, { once: true });
  // An abort that landed in the microtask gap above never re-fires the listener — re-check.
  if (signal?.aborted) {
    if (signal) signal.removeEventListener("abort", onAbort);
    announcer.stop();
    peer.stop();
    throw abortedErr();
  }
  try {
    const { peerAddress } = await peer.send(payload);
    return { ok: true, peerAddress };
  } catch (err) {
    if (signal?.aborted) throw abortedErr();
    throw err;
  } finally {
    if (signal) signal.removeEventListener("abort", onAbort);
    announcer.stop();
  }
}

export async function receiveEnv({ roomCode, passphrase, timeoutMs = 30000 }, { signal } = {}) {
  return new Promise((resolve, reject) => {
    let done = false;
    let sawAnnouncer = false;
    const tried = new Set(); // announcers we've already attempted, by address:port
    // FINDING 11 fix: fan-out budget — each attempt costs scrypt + socket + event loop.
    // 8 distinct announcers is generous for a LAN; beyond that fail closed rather than churn.
    const MAX_ANNOUNCERS = 8;
    const abortedErr = () => {
      const e = new Error("receive cancelled — the requesting client disconnected before a peer answered.");
      e.name = "AbortError";
      return e;
    };

    const onAbort = () => finish(reject, abortedErr());
    const finish = (fn, value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      listener.stop();
      if (signal) signal.removeEventListener("abort", onAbort);
      fn(value);
    };
    // An already-cancelled caller never starts listening; a live one stops the listener,
    // the timer, and any in-flight fetches the moment it goes away.
    if (signal?.aborted) {
      done = true;
      reject(abortedErr());
      return;
    }
    if (signal) signal.addEventListener("abort", onAbort, { once: true });

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
        if (tried.size >= MAX_ANNOUNCERS) return; // budget exhausted — fail closed at timeout
        tried.add(key);
        sawAnnouncer = true;
        try {
          // fetchOnce runs the authenticated handshake and returns the OPENED capsule (the encrypted
          // blob); a wrong passphrase fails the capsule open here, an impostor peer likewise.
          // The abort signal travels with it so a cancelled receive kills in-flight sockets now,
          // not at their individual 15s timeouts (an abort rejection just keeps listening — unless
          // the abort itself finished us, which finish() guards via `done`).
          const blob = await fetchOnce({ address: info.address, port: info.tcpPort, passphrase, roomCode, signal });
          const envText = await decrypt(blob, passphrase);
          finish(resolve, { ok: true, envText, fromAddress: info.address });
        } catch (err) {
          if (done) return; // our own abort finished already — don't swallow its error as "spoofer"
          // this announcer couldn't complete (spoofer, wrong peer, or corrupt payload) — keep listening
          // for another announcer rather than committing to the first and failing the whole transfer
        }
      },
    });
  });
}
