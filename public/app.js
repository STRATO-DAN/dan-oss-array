// [DAN] ARRAY — real client logic, plain fetch + DOM. No framework, matches the other DAN-OSS
// tools. Neither the passphrase nor the raw .env text is ever written to localStorage/sessionStorage
// — this page keeps no history of a secret past the life of the tab.
const $ = (id) => document.getElementById(id);

// `opts.busy` shows the rotating `.dan-seal` while actively waiting for a peer; `opts.sub` adds a
// smaller detail line under the main one. Rebuilding the content each call means a later ok/err
// state (no busy) automatically drops the spinner.
function setStatus(el, kind, text, opts = {}) {
  const { busy = false, sub = "" } = opts;
  el.hidden = false;
  el.className = `status-line ${kind}`;
  el.replaceChildren();
  if (busy) {
    const seal = document.createElement("span");
    seal.className = "dan-seal";
    el.appendChild(seal);
  }
  const body = document.createElement("span");
  body.className = "status-body";
  const main = document.createElement("span");
  main.className = "status-main";
  main.textContent = text;
  body.appendChild(main);
  if (sub) {
    const subEl = document.createElement("span");
    subEl.className = "status-sub";
    subEl.textContent = sub;
    body.appendChild(subEl);
  }
  el.appendChild(body);
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function share() {
  const envText = $("shareEnv").value;
  const roomCode = $("shareRoom").value.trim();
  const passphrase = $("sharePass").value;
  const status = $("shareStatus");
  const btn = $("shareBtn");

  if (!envText.trim() || !roomCode || !passphrase) {
    setStatus(status, "err", "Fill in the .env contents, a room code, and a passphrase first.");
    return;
  }

  btn.disabled = true;
  setStatus(status, "busy", "Waiting for a peer…", {
    busy: true,
    sub: "Broadcasting on your local network · up to 2 min",
  });

  try {
    const data = await postJson("/api/share", { envText, roomCode, passphrase });
    if (!data.ok) {
      setStatus(status, "err", data.reason);
    } else {
      setStatus(status, "ok", `Sent — a peer at ${data.peerAddress} received the encrypted data.`);
    }
  } catch (err) {
    setStatus(status, "err", `Request failed: ${err.message}`);
  } finally {
    btn.disabled = false;
  }
}

async function receive() {
  const roomCode = $("recvRoom").value.trim();
  const passphrase = $("recvPass").value;
  const status = $("recvStatus");
  const resultBox = $("recvResult");
  const btn = $("recvBtn");

  if (!roomCode || !passphrase) {
    setStatus(status, "err", "Enter the room code and passphrase the sender is using.");
    return;
  }

  btn.disabled = true;
  resultBox.hidden = true;
  setStatus(status, "busy", "Waiting for a peer…", {
    busy: true,
    sub: "Listening on your local network for a matching room · up to 30 sec",
  });

  try {
    const data = await postJson("/api/receive", { roomCode, passphrase });
    if (!data.ok) {
      setStatus(status, "err", data.reason);
    } else {
      setStatus(status, "ok", `Received from ${data.fromAddress} and decrypted successfully.`);
      $("recvEnv").value = data.envText;
      resultBox.hidden = false;
    }
  } catch (err) {
    setStatus(status, "err", `Request failed: ${err.message}`);
  } finally {
    btn.disabled = false;
  }
}

function downloadEnv() {
  const text = $("recvEnv").value;
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = ".env";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function copyRoom() {
  const btn = $("shareRoomCopy");
  const code = $("shareRoom").value.trim();
  if (!code) return;
  try {
    // navigator.clipboard is available here — http://127.0.0.1 is a secure context.
    await navigator.clipboard.writeText(code);
    const original = btn.textContent;
    btn.textContent = "Copied ✓";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove("copied");
    }, 1500);
  } catch {
    // Clipboard blocked (non-secure context or denied) — leave the field for a manual copy.
  }
}

$("shareBtn").addEventListener("click", share);
$("recvBtn").addEventListener("click", receive);
$("downloadBtn").addEventListener("click", downloadEnv);
$("shareRoomCopy").addEventListener("click", copyRoom);
