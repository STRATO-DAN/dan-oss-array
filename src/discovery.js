// [DAN] ARRAY — real LAN peer discovery, UDP broadcast, no central server, no signaling service.
// Honest limit: this only finds a peer inside the same broadcast domain (same LAN/subnet/Wi-Fi
// network). It does not cross the public internet or a NAT boundary — that would need a relay,
// which is exactly the central point of failure this basic tier exists to avoid.
import dgram from "node:dgram";
import { roomHash } from "./crypto.js";

export const DISCOVERY_PORT = 47401;
const ANNOUNCE_INTERVAL_MS = 1000;

// Broadcasts "a room with this hash is being shared, connect to me on this TCP port" — the real
// room code itself never goes on the wire, only its hash, so a passive LAN listener without the
// code can't reconstruct it.
export function startAnnouncing({ roomCode, tcpPort, intervalMs = ANNOUNCE_INTERVAL_MS }) {
  const socket = dgram.createSocket("udp4");
  const hash = roomHash(roomCode);
  const message = Buffer.from(JSON.stringify({ app: "dan-oss-array", v: 1, roomHash: hash, tcpPort }));
  let timer = null;
  let stopped = false;

  socket.bind(() => {
    if (stopped) return;
    socket.setBroadcast(true);
    const send = () => socket.send(message, DISCOVERY_PORT, "255.255.255.255");
    send();
    timer = setInterval(send, intervalMs);
  });

  return {
    stop() {
      stopped = true;
      if (timer) clearInterval(timer);
      socket.close();
    },
  };
}

// Listens for announce packets matching this room's hash, reporting the announcer's real address
// and TCP port the first time a match arrives. Ignores every other broadcast on the LAN silently
// — a shared network carries plenty of unrelated traffic, and that isn't this tool's concern.
export function startListening({ roomCode, onFound }) {
  const hash = roomHash(roomCode);
  const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
  let found = false;

  socket.on("message", (msg, rinfo) => {
    if (found) return;
    let data;
    try {
      data = JSON.parse(msg.toString("utf8"));
    } catch {
      return;
    }
    if (data.app === "dan-oss-array" && data.v === 1 && data.roomHash === hash && Number.isInteger(data.tcpPort)) {
      found = true;
      onFound({ address: rinfo.address, tcpPort: data.tcpPort });
    }
  });

  socket.bind(DISCOVERY_PORT);

  return {
    stop() {
      socket.close();
    },
  };
}
