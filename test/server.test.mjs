// Real loopback HTTP server tests. The UI can initiate a secret (.env) transfer, so the local API must
// refuse a request driven from another origin (CSRF) — on top of the existing DNS-rebinding Host guard.
// Real http.request against a real server bound to 127.0.0.1, no mocks.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { listen } from "../src/server.js";

// One request against 127.0.0.1:<port>. `headers` can override Host / Origin. Resolves { status, body }.
function request(port, { method = "GET", path = "/", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

async function withServer(fn) {
  const server = await listen(0);
  const { port } = server.address();
  try {
    await fn(port);
  } finally {
    server.close();
  }
}

test("a request with a NON-loopback Host is refused (DNS-rebinding guard, unchanged)", () =>
  withServer(async (port) => {
    const res = await request(port, { path: "/api/status", headers: { host: "evil.example.com" } });
    assert.equal(res.status, 403);
  }));

test("A2: a GET with a cross-origin Origin is refused (CSRF guard)", () =>
  withServer(async (port) => {
    const res = await request(port, { path: "/api/status", headers: { origin: "http://evil.example.com" } });
    assert.equal(res.status, 403, "a cross-origin browser request must not reach the local API");
  }));

test("A2: a POST /api/share driven from another origin is refused BEFORE any transfer starts", () =>
  withServer(async (port) => {
    const payload = JSON.stringify({ envText: "X=1", roomCode: "room-abcd", passphrase: "passphrase-1234" });
    const res = await request(port, {
      method: "POST",
      path: "/api/share",
      headers: { "content-type": "application/json", origin: "https://attacker.test" },
      body: payload,
    });
    assert.equal(res.status, 403, "cross-origin CSRF cannot drive a share");
  }));

test("A2: a same-origin request (loopback Origin) passes the guard and reaches the handler", () =>
  withServer(async (port) => {
    const res = await request(port, {
      path: "/api/status",
      headers: { origin: `http://127.0.0.1:${port}` },
    });
    assert.equal(res.status, 200);
    assert.match(res.body, /"ok":true/);
  }));

test("A2: a non-browser request (no Origin) still works — the guard only rejects a cross-origin one", () =>
  withServer(async (port) => {
    // A valid-shaped POST with no Origin passes the guard and reaches validation (which here rejects the
    // too-short fields with ok:false) — proving the guard didn't block a legitimate same-origin/CLI call.
    const res = await request(port, {
      method: "POST",
      path: "/api/share",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ envText: "", roomCode: "x", passphrase: "short" }),
    });
    assert.equal(res.status, 200);
    assert.match(res.body, /"ok":false/, "reached the share validator rather than being blocked as cross-origin");
  }));
