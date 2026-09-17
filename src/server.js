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

function validateShareBody(body) {
  if (typeof body.envText !== "string" || !body.envText.trim()) return "envText is required";
  if (typeof body.roomCode !== "string" || body.roomCode.length < 4) return "roomCode must be at least 4 characters";
  if (typeof body.passphrase !== "string" || body.passphrase.length < 8) return "passphrase must be at least 8 characters";
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
// allowed. A determined LAN attacker broadcasting to DoS the port stays out of scope per SECURITY.md.
function isAllowedOrigin(originHeader) {
  if (originHeader == null) return true; // no Origin — non-browser client or a same-origin GET
  const o = String(originHeader).trim();
  if (o === "" || o.toLowerCase() === "null") return true; // opaque origin — not a readable cross-site attacker
  let host;
  try {
    host = new URL(o).hostname.toLowerCase();
  } catch {
    return false; // an Origin header that isn't a valid URL is not trusted
  }
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

export function createServer() {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (!isLoopbackHost(req.headers.host)) {
      res.writeHead(403).end("forbidden");
      return;
    }
    if (!isAllowedOrigin(req.headers.origin)) {
      res.writeHead(403).end("forbidden");
      return;
    }
    const p = url.pathname;

    try {
      if (p === "/api/status" && req.method === "GET") {
        return sendJson(res, 200, { ok: true, mode: "p2p-basic", encryption: "AES-256-GCM (generic, local)" });
      }

      // Held open for as long as sharing runs (until a peer downloads it, or it times out) — the
      // request IS the share session, so closing the tab / cancelling the fetch stops it.
      if (p === "/api/share" && req.method === "POST") {
        const body = await readBody(req);
        const problem = validateShareBody(body);
        if (problem) return sendJson(res, 200, { ok: false, reason: problem });
        try {
          const result = await shareEnv(body);
          return sendJson(res, 200, result);
        } catch (err) {
          return sendJson(res, 200, { ok: false, reason: err.message });
        }
      }

      // Same real shape on the receive side — the request holds open until a peer is found and
      // the transfer completes, or the window closes with an honest "not found" error.
      if (p === "/api/receive" && req.method === "POST") {
        const body = await readBody(req);
        if (typeof body.roomCode !== "string" || !body.roomCode) return sendJson(res, 200, { ok: false, reason: "roomCode is required" });
        if (typeof body.passphrase !== "string" || !body.passphrase) return sendJson(res, 200, { ok: false, reason: "passphrase is required" });
        try {
          const result = await receiveEnv(body);
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
