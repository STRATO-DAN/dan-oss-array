#!/usr/bin/env node
// [DAN] ARRAY — real CLI entry. Starts the local UI server (loopback only), opens the browser.
import { listen } from "../src/server.js";
import { execFile } from "node:child_process";

const port = Number(process.env.DAN_OSS_ARRAY_PORT) || 4873;

const server = await listen(port);
const url = `http://127.0.0.1:${port}`;

console.log(`[DAN] ARRAY running at ${url}`);
console.log("Mode: P2P .env sync, basic tier — generic AES-256-GCM encryption, no central server.");
console.log("Ctrl-C to stop.\n");

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
