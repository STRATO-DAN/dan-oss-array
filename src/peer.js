// [DAN] ARRAY — real, direct peer-to-peer transfer, now AUTHENTICATED. A one-shot TCP server hands the
// sealed credential capsule to exactly one peer that has PROVEN the passphrase (see handshake.js), then
// closes — never a relay, never a service. A peer that cannot authenticate is refused and the server
// keeps waiting for the right one, so a racing LAN host can neither steal the capsule nor deny the real
// receiver.
import net from "node:net";
import { sharerServe, receiverFetch } from "./handshake.js";

export function listenForOnePeer({
  passphrase,
  roomCode,
  timeoutMs = 120000,
  handshakeTimeoutMs = 15000, // a single peer's handshake must complete in this long, or it is dropped
  maxConcurrentHandshakes = 4, // bound pre-auth work: cap how many scrypt-bearing handshakes run at once
} = {}) {
  const server = net.createServer();
  let settled = false;
  let inFlight = 0;
  let timer = null; // the overall "no peer connected in time" timer — hoisted so stop() can cancel it
  let rejectServed = null;
  let capsulePlain = null;
  let payloadResolve = null;
  const payloadReady = new Promise((resolve) => {
    payloadResolve = resolve;
  });

  const ready = new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, () => resolve(server.address().port));
  });

  const served = new Promise((resolve, reject) => {
    rejectServed = reject;
    timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      server.close();
      reject(new Error("No authenticated peer connected within the time window — nothing was sent."));
    }, timeoutMs);

    server.on("connection", async (socket) => {
      socket.on("error", () => {}); // a peer that hangs up mid-handshake is not our failure
      if (settled) {
        socket.destroy();
        return;
      }
      // An unauthenticated peer forces an expensive scrypt (the sharer must derive the session key to
      // check the peer's proof). Cap concurrent handshakes so a connection flood cannot pile up unbounded
      // pre-auth CPU work, and give each handshake a hard deadline so a peer that connects then stalls
      // (or drips bytes) is dropped instead of holding a slot — then keep listening for the right peer.
      if (inFlight >= maxConcurrentHandshakes) {
        socket.destroy();
        return;
      }
      inFlight++;
      const hsTimer = setTimeout(() => socket.destroy(), handshakeTimeoutMs);
      try {
        await payloadReady; // the payload is handed in via send(); wait for it before serving
        // `claim` runs synchronously inside sharerServe, immediately before the capsule is written, and
        // atomically decides whether THIS connection is the one served. The FIRST authenticated peer to
        // reach it wins; any other peer that finishes its handshake is refused before the capsule reaches
        // the wire — so the "exactly one peer" contract holds even when two authenticated peers race.
        await sharerServe(socket, {
          passphrase,
          roomCode,
          capsulePlain,
          claim: () => {
            if (settled) return false;
            settled = true;
            clearTimeout(timer);
            return true;
          },
        });
        socket.end(() => {
          server.close();
          resolve({ peerAddress: socket.remoteAddress });
        });
      } catch {
        // unauthenticated, malformed, oversized, timed out, or lost the single-serve race — refuse THIS
        // peer and keep listening (unless another peer already settled the transfer)
        socket.destroy();
      } finally {
        clearTimeout(hsTimer);
        inFlight--;
      }
    });
  });

  return {
    ready,
    send(payload) {
      capsulePlain = payload;
      payloadResolve();
      return served;
    },
    stop() {
      // Clean shutdown: cancel the pending timeout (so a stopped sharer leaves no timer keeping the
      // process alive) and settle `served` if no peer ever completed, rather than leaving it hanging.
      if (!settled) {
        settled = true;
        if (timer) clearTimeout(timer);
        rejectServed?.(new Error("sharer stopped before an authenticated peer connected"));
      }
      server.close();
    },
  };
}

export function fetchOnce({ address, port, passphrase, roomCode, timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.createConnection({ host: address, port });
    const timer = setTimeout(() => finish(reject, new Error("Connection to the peer timed out.")), timeoutMs);

    function finish(fn, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      fn(value);
    }

    socket.on("connect", async () => {
      try {
        finish(resolve, await receiverFetch(socket, { passphrase, roomCode }));
      } catch (err) {
        finish(reject, err);
      }
    });
    socket.on("error", (err) => finish(reject, err));
  });
}
