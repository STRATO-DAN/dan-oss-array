// [DAN] ARRAY — real, direct peer-to-peer transfer, now AUTHENTICATED. A one-shot TCP server hands the
// sealed credential capsule to exactly one peer that has PROVEN the passphrase (see handshake.js), then
// closes — never a relay, never a service. A peer that cannot authenticate is refused and the server
// keeps waiting for the right one, so a racing LAN host can neither steal the capsule nor deny the real
// receiver.
import net from "node:net";
import { sharerServe, receiverFetch } from "./handshake.js";

export function listenForOnePeer({ passphrase, roomCode, timeoutMs = 120000 } = {}) {
  const server = net.createServer();
  let settled = false;
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
    const timer = setTimeout(() => {
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
      try {
        await payloadReady; // the payload is handed in via send(); wait for it before serving
        await sharerServe(socket, { passphrase, roomCode, capsulePlain });
        if (settled) {
          socket.destroy();
          return;
        }
        settled = true;
        clearTimeout(timer);
        socket.end(() => {
          server.close();
          resolve({ peerAddress: socket.remoteAddress });
        });
      } catch {
        // unauthenticated, malformed, or oversized — refuse THIS peer and keep listening for the right one
        socket.destroy();
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
