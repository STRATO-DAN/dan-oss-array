#!/usr/bin/env node
// [DAN] ARRAY — real CLI entry. Starts the local UI server (loopback only), opens the browser.
// Flags are hand-rolled (zero runtime dependencies, Node stdlib only): --version, --help, --json.
import { listen } from "../src/server.js";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Read the package version from package.json rather than hard-coding it, so `--version` can never
// drift from the published version. Falls back to "unknown" if the file is somehow unreadable.
function readVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

const HELP = `[DAN] ARRAY — P2P .env sync over your LAN, no central server.

Usage:
  dan-oss-array [options]

Options:
  --version     Print the version and exit.
  --help        Print this help and exit.
  --json        Print the startup banner as one JSON object ({url,port,mode,encryption})
                instead of human-readable text. The human banner is the default.

Environment:
  DAN_OSS_ARRAY_PORT   Loopback port for the local UI server (default: 4873).

Exit codes:
  0   Clean startup (or --version / --help), or a clean shutdown via Ctrl-C.
  1   Startup failure (e.g. the port is already in use — EADDRINUSE).
  2   Usage error (an unknown flag).

The UI binds 127.0.0.1 only; the actual peer-to-peer transfer runs over its own direct
TCP/UDP sockets, not through this server.`;

// Hand-rolled flag parse — no dependency. Unknown flags are a usage error (exit 2); the flags we
// support are order-independent and terminal (each prints and exits) except --json, which only
// selects the banner format.
const argv = process.argv.slice(2);
let jsonBanner = false;
for (const arg of argv) {
  if (arg === "--version" || arg === "-v") {
    process.stdout.write(readVersion() + "\n");
    process.exit(0);
  } else if (arg === "--help" || arg === "-h") {
    process.stdout.write(HELP + "\n");
    process.exit(0);
  } else if (arg === "--json") {
    jsonBanner = true;
  } else {
    process.stderr.write(`dan-oss-array: unknown option '${arg}'. Try --help.\n`);
    process.exit(2);
  }
}

const port = Number(process.env.DAN_OSS_ARRAY_PORT) || 4873;
const url = `http://127.0.0.1:${port}`;
const mode = "p2p-basic";
const encryption = "AES-256-GCM";

let server;
try {
  server = await listen(port);
} catch (err) {
  // Never surface a raw stack for an expected startup failure (a busy port is the common one) —
  // print one honest line and exit non-zero so scripts and CI can detect it.
  const reason =
    err && err.code === "EADDRINUSE"
      ? `port ${port} is already in use (set DAN_OSS_ARRAY_PORT to pick another)`
      : (err && err.message) || String(err);
  process.stderr.write(`dan-oss-array: could not start — ${reason}\n`);
  process.exit(1);
}

if (jsonBanner) {
  process.stdout.write(JSON.stringify({ url, port, mode, encryption }) + "\n");
} else {
  console.log(`[DAN] ARRAY running at ${url}`);
  console.log("Mode: P2P .env sync, basic tier — generic AES-256-GCM encryption, no central server.");
  console.log("Ctrl-C to stop.\n");
}

// execFile, not exec — no shell. On Windows `start` is a cmd builtin, so it must run via cmd.exe
// rather than be exec'd as a binary (otherwise auto-open silently no-ops on Windows).
const [openerCmd, openerArgs] =
  process.platform === "darwin" ? ["open", [url]]
    : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]]
      : ["xdg-open", [url]];
execFile(openerCmd, openerArgs, () => {});

process.on("SIGINT", () => {
  server.close(() => process.exit(0));
});
