// Content script: bridges the page-context enforcement (injected.js) to the
// background worker, renders the overlay/feedback UI, and intercepts uploads
// at the UI layer. Runs at document_start.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;

  // ── Handshake de nonce com o enforcement layer (injected.js, world MAIN) ──
  // Ambos são content scripts document_start: rodam antes de QUALQUER script
  // da página. O nonce é gravado no DOM aqui e lido+removido pelo injected.js
  // antes de existir código do site — a página nunca o observa. Sem ele,
  // mensagens scan-request/scan-result são ignoradas, fechando o bypass por
  // postMessage forjado (um "allow" falso vindo da própria página).
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const NONCE = Array.from(nonceBytes, (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  document.documentElement.dataset.guardianNonce = NONCE;

  // ── Bridge: injected (page) → background (extension) → injected ───────────
  window.addEventListener("message", async (e) => {
    const d = e.data;
    if (!d || d.__guardian !== "scan-request" || d.nonce !== NONCE) return;

    // Scan runs silently — overlay only appears on block/approval below.
    let result;
    try {
      result = await api.runtime.sendMessage({ type: "guardian-scan", payload: d.payload });
    } catch {
      result = { action: "block", reason: "Extensão não conseguiu falar com o background (fail-closed).", offline: true };
    }

    if (result && result.action === "block") {
      showOverlay("block", formatBlock(result));
    } else if (result && result.action === "require-approval") {
      showOverlay("approval", formatApproval(result));
    } else {
      hideOverlay();
    }

    window.postMessage(
      { __guardian: "scan-result", id: d.id, nonce: NONCE, result },
      "*",
    );
  });

  // ── Upload interception (UI layer) ────────────────────────────────────────
  // Block sensitive files by name before they are attached. Content of text
  // files is scanned; binaries are decided by name only.
  const TEXT_EXT_RE = /\.(txt|json|ya?ml|env|js|ts|py|java|cs|rb|go|sh|sql|xml|ini|conf|cfg|toml|pem|key|csv|md|log)$/i;

  async function inspectFiles(files) {
    const payloadFiles = [];
    for (const file of files) {
      let content;
      if (file.size < 512 * 1024 && TEXT_EXT_RE.test(file.name)) {
        try {
          content = await file.text();
        } catch {
          content = undefined;
        }
      }
      payloadFiles.push({ name: file.name, content });
    }
    let result;
    try {
      result = await api.runtime.sendMessage({
        type: "guardian-scan",
        payload: { files: payloadFiles, context: { url: location.href, tabTitle: document.title } },
      });
    } catch {
      result = { action: "block", reason: "Falha ao verificar anexos (fail-closed)." };
    }
    if (result && (result.action === "block" || result.action === "require-approval")) {
      showOverlay(result.action === "block" ? "block" : "approval",
        result.action === "block" ? formatBlock(result) : formatApproval(result));
      return false;
    }
    hideOverlay();
    return true;
  }

  function blockEvent(e) {
    e.preventDefault();
    e.stopImmediatePropagation();
  }

  // Drag-and-drop
  document.addEventListener("drop", (e) => {
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) {
      blockEvent(e);
      inspectFiles([...files]).then((ok) => {
        if (ok) console.info("[guardian] anexos liberados — re-arraste para anexar");
      });
    }
  }, true);

  // Paste of files/images
  document.addEventListener("paste", (e) => {
    const items = e.clipboardData && e.clipboardData.files;
    if (items && items.length) {
      blockEvent(e);
      inspectFiles([...items]);
    }
  }, true);

  // File input dialog
  document.addEventListener("change", (e) => {
    const t = e.target;
    if (t && t.tagName === "INPUT" && t.type === "file" && t.files && t.files.length) {
      const files = [...t.files];
      inspectFiles(files).then((ok) => {
        if (!ok) {
          t.value = "";
          blockEvent(e);
        }
      });
    }
  }, true);

  // ── Overlay UI ────────────────────────────────────────────────────────────
  let overlayEl = null;

  function ensureOverlay() {
    if (overlayEl) return overlayEl;
    overlayEl = document.createElement("div");
    overlayEl.id = "guardian-overlay";
    overlayEl.innerHTML = `
      <style>
        #guardian-overlay { position: fixed; inset: 0; z-index: 2147483647;
          background: rgba(15,15,20,.55); display: none; align-items: center;
          justify-content: center; font-family: system-ui, sans-serif; }
        #guardian-overlay.show { display: flex; }
        #guardian-card { background: #fff; color: #1a1a1a; max-width: 480px;
          width: calc(100% - 2rem); border-radius: 12px; padding: 1.5rem 1.75rem;
          box-shadow: 0 10px 40px rgba(0,0,0,.35); }
        #guardian-card h2 { font-size: 1.1rem; margin: 0 0 .5rem; display:flex; gap:.5rem; align-items:center; }
        #guardian-card pre { white-space: pre-wrap; word-break: break-word;
          font-size: .85rem; background: #f6f6f8; padding: .75rem; border-radius: 8px;
          margin: .5rem 0 1rem; max-height: 220px; overflow:auto; }
        #guardian-card .gbtns { display:flex; gap:.5rem; justify-content:flex-end; }
        #guardian-card button { border:none; border-radius:8px; padding:.55rem 1rem;
          font-size:.9rem; font-weight:600; cursor:pointer; }
        .g-primary { background:#4f46e5; color:#fff; }
        .g-secondary { background:#e5e7eb; color:#111; }
        .g-spinner { width:18px;height:18px;border:3px solid #ddd;border-top-color:#4f46e5;
          border-radius:50%; animation: gspin 1s linear infinite; }
        @keyframes gspin { to { transform: rotate(360deg); } }
        #guardian-card a { color:#4f46e5; }
      </style>
      <div id="guardian-card"></div>`;
    (document.body || document.documentElement).appendChild(overlayEl);
    return overlayEl;
  }

  function showOverlay(kind, html) {
    const el = ensureOverlay();
    const card = el.querySelector("#guardian-card");
    if (kind === "verificando") {
      card.innerHTML = `<h2><span class="g-spinner"></span> Claude Guardian</h2><p>${html}</p>`;
    } else {
      card.innerHTML = html + `<div class="gbtns"><button class="g-secondary" id="g-close">Entendi</button></div>`;
      const close = card.querySelector("#g-close");
      if (close) close.addEventListener("click", hideOverlay);
    }
    el.classList.add("show");
  }

  function hideOverlay() {
    if (overlayEl) overlayEl.classList.remove("show");
  }

  function findingsTable(findings) {
    if (!findings || !findings.length) return "";
    const rows = findings
      .map((f) => `<div>• <b>${esc(f.label)}</b> <code>${esc(f.snippet)}</code></div>`)
      .join("");
    return `<pre>${rows}</pre>`;
  }

  function formatBlock(r) {
    const link = r.approvalUrl
      ? `<p>Para solicitar liberação: <a href="${esc(r.approvalUrl)}" target="_blank">abrir página</a></p>`
      : "";
    return `<h2>🛑 Envio bloqueado</h2><p>${esc(r.reason || "Dado sensível detectado.")}</p>${findingsTable(r.findings)}${link}`;
  }

  function formatApproval(r) {
    const link = r.approvalUrl
      ? `<p><a href="${esc(r.approvalUrl)}" target="_blank">Solicitar liberação</a></p>`
      : "";
    return `<h2>⏳ Aprovação necessária</h2><p>${esc(r.reason || "")}</p>${findingsTable(r.findings)}${link}`;
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
})();
