// [DAN] ARRAY — real, direct peer-to-peer transfer. A one-shot TCP server sends the already-
// encrypted payload to exactly one connecting peer, then closes — never a long-running service,
// never a relay, never anything but this machine talking directly to the one that connects.
import net from "node:net";

// Two real steps, not one call: the caller needs the bound port (to announce it over UDP) before
// a peer has connected, and needs to hand over the payload only once discovery has happened — so
// binding and sending are split rather than folded into a single all-at-once function.
export function listenForOnePeer({ timeoutMs = 120000 } = {}) {
  const server = net.createServer();
  let onConnection = null;

  const ready = new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, () => resolve(server.address().port));
  });

  const served = new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      server.close();
      reject(new Error("No peer connected within the time window — nothing was sent."));
    }, timeoutMs);

    onConnection = (payload) => {
      server.on("connection", (socket) => {
        if (settled) { socket.destroy(); return; }
        settled = true;
        clearTimeout(timer);
        socket.end(payload, () => {
          server.close();
          resolve({ peerAddress: socket.remoteAddress });
        });
      });
    };
  });

  return {
    ready,
    send(payload) {
      onConnection(payload);
      return served;
    },
    stop() {
      server.close();
    },
  };
}

export function fetchOnce({ address, port, timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const chunks = [];
    const socket = net.createConnection({ host: address, port });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error("Connection to the peer timed out."));
    }, timeoutMs);

    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(Buffer.concat(chunks));
    });
    socket.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}
