// Real local HTTP server, Node stdlib only — zero runtime dependencies, the same discipline as
// DAN-OSS-COMMIT/MOCK. Loopback-only: the UI never needs to be reachable off the local machine —
// the actual P2P transfer happens over its own direct TCP/UDP sockets, not through this server.
import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { shareEnv, receiveEnv } from "./sync.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "..", "public");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

function sendJson(res, status, body) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [], size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 2 * 1024 * 1024) { reject(new Error("request body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(new Error("invalid JSON body")); }
    });
    req.on("error", reject);
  });
}

async function serveStatic(res, urlPath) {
  const rel = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
  const resolved = path.resolve(PUBLIC_DIR, rel);
  if (resolved !== PUBLIC_DIR && !resolved.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403).end("forbidden"); return; }
  try {
    const data = await fs.readFile(resolved);
    res.writeHead(200, { "content-type": MIME[path.extname(resolved)] || "application/octet-stream" });
    res.end(data);
  } catch {
    res.writeHead(404).end("not found");
  }
}

// 🔴 Room-code length — roomHash() (crypto.js) broadcasts an unsalted, truncated SHA-256 of the room
// code in every UDP announce (it has to be public: peers need it to find each other before any secret
// is exchanged). A short code is cheap to brute-force back from that hash — 4 characters is recoverable
// in low thousands of tries, milliseconds. This alone never leaks the payload (the passphrase-derived
// scrypt key still guards that), but it hands an attacker the exact room to target with their online
// guessing budget instead of guessing rooms blind. 10 lowercase-alnum chars raises the offline search
// space enough that brute-forcing the hash back to a code stops being the cheap step in an attack.
const MIN_ROOM_CODE_LENGTH = 10;

function validateShareBody(body) {
  if (typeof body.envText !== "string" || !body.envText.trim()) return "envText is required";
  if (typeof body.roomCode !== "string" || body.roomCode.length < MIN_ROOM_CODE_LENGTH)
    return `roomCode must be at least ${MIN_ROOM_CODE_LENGTH} characters`;
  if (typeof body.passphrase !== "string" || body.passphrase.length < 8) return "passphrase must be at least 8 characters";
  // 🔴 A passphrase equal to the room code collapses two independent secrets into one: roomHash is
  // PUBLIC (broadcast every announce), so if the passphrase reuses that same string, brute-forcing the
  // public hash back to the room code (cheap, see above) also recovers the passphrase that guards the
  // payload — the two layers stop being independent. Reject the reuse outright rather than relying on
  // room-code length alone to make that combined attack merely "harder."
  if (body.passphrase === body.roomCode) return "passphrase must not be the same as roomCode";
  return null;
}

// 🔴 DNS-rebinding guard — this loopback UI can initiate a secret (.env) transfer, so it must refuse any
// request whose Host isn't loopback: a web page the user visits cannot rebind a hostname to 127.0.0.1 and
// drive the local share/receive API.
function isLoopbackHost(hostHeader) {
  if (!hostHeader) return false;
  let host = String(hostHeader).trim().toLowerCase();
  if (host.startsWith("[")) {
    host = host.slice(1, host.indexOf("]"));
  } else {
    host = host.replace(/:\d+$/, "");
  }
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

// 🔴 Cross-origin (CSRF) guard — the Host check above blocks DNS-rebinding; this rejects any request
// that carries a browser `Origin` which isn't loopback, so a cross-origin web page cannot drive the
// local share/receive API. A same-origin request from the local UI sends a loopback Origin (or none);
// a non-browser client (curl, the CLI) sends none; an opaque "null" origin (sandboxed/file://) is
// rejected. A determined LAN attacker broadcasting to DoS the port stays out of scope per SECURITY.md.
function isAllowedOrigin(originHeader, hostHeader) {
  if (originHeader == null) return true; // no Origin — non-browser client or a same-origin GET
  const o = String(originHeader).trim();
  if (o === "" || o.toLowerCase() === "null") return false;
  try {
    const origin = new URL(o);
    return origin.origin === `http://${hostHeader}` && o === origin.origin;
  } catch {
    return false; // an Origin header that isn't a valid URL is not trusted
  }
}

export function createServer() {
  return http.createServer(async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const url = new URL(req.url, "http://127.0.0.1");
    if (!isLoopbackHost(req.headers.host)) {
      res.writeHead(403).end("forbidden");
      return;
    }
    if (!isAllowedOrigin(req.headers.origin, req.headers.host) || req.headers["sec-fetch-site"] === "cross-site") {
      res.writeHead(403).end("forbidden");
      return;
    }
    const p = url.pathname;
    if (req.method === "POST" && p.startsWith("/api/") &&
        req.headers["content-type"]?.split(";")[0].trim().toLowerCase() !== "application/json") {
      return sendJson(res, 415, { ok: false, reason: "application/json is required" });
    }

    try {
      if (p === "/api/status" && req.method === "GET") {
        return sendJson(res, 200, { ok: true, mode: "p2p-basic", encryption: "AES-256-GCM (generic, local)" });
      }

      // Held open for as long as sharing runs (until a peer downloads it, it times out, or the
      // client disconnects) — cancellation is coupled: a closed request aborts the TCP listener
      // AND the UDP announcer immediately, so server-side transfer never outlives the browser action.
      if (p === "/api/share" && req.method === "POST") {
        const body = await readBody(req);
        const problem = validateShareBody(body);
        if (problem) return sendJson(res, 200, { ok: false, reason: problem });
        const ac = new AbortController();
        req.on("close", () => {
          if (!res.writableEnded) ac.abort();
        });
        try {
          const result = await shareEnv(body, { signal: ac.signal });
          return sendJson(res, 200, result);
        } catch (err) {
          return sendJson(res, 200, { ok: false, reason: err.message });
        }
      }

      // Same real shape on the receive side — the request holds open until a peer is found and
      // the transfer completes, the window closes with an honest "not found" error, or the client
      // disconnects (which stops the listener and kills in-flight fetches at once).
      if (p === "/api/receive" && req.method === "POST") {
        const body = await readBody(req);
        if (typeof body.roomCode !== "string" || !body.roomCode) return sendJson(res, 200, { ok: false, reason: "roomCode is required" });
        if (typeof body.passphrase !== "string" || !body.passphrase) return sendJson(res, 200, { ok: false, reason: "passphrase is required" });
        const ac = new AbortController();
        req.on("close", () => {
          if (!res.writableEnded) ac.abort();
        });
        try {
          const result = await receiveEnv(body, { signal: ac.signal });
          return sendJson(res, 200, result);
        } catch (err) {
          return sendJson(res, 200, { ok: false, reason: err.message });
        }
      }

      if (req.method === "GET") return serveStatic(res, p);
      res.writeHead(404).end("not found");
    } catch (err) {
      sendJson(res, 500, { ok: false, reason: err.message });
    }
  });
}

export function listen(port) {
  const server = createServer();
  return new Promise((resolve, reject) => {
    // Reject (rather than let the server emit an unhandled 'error' that crashes the process with a
    // raw stack) so the caller can report a startup failure honestly — e.g. EADDRINUSE when the port
    // is already in use. The error listener is removed once binding succeeds so it can't later fire.
    const onError = (err) => reject(err);
    server.once("error", onError);
    server.listen(port, "127.0.0.1", () => {
      server.removeListener("error", onError);
      resolve(server);
    });
  });
}
