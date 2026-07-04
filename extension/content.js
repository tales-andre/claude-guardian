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

  // ── Telemetria de drift: injected → background ────────────────────────────
  window.addEventListener("message", (e) => {
    const d = e.data;
    if (!d || d.__guardian !== "extract-fail" || d.nonce !== NONCE) return;
    try {
      api.runtime.sendMessage({
        type: "guardian-extract-fail",
        host: String(d.host || location.hostname),
      });
    } catch {
      // telemetria é best-effort
    }
  });

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

    // Só mostra o overlay de bloqueio para DETECÇÃO real de segredo. Respostas
    // "offline" (daemon fora / sem resposta) são fail-open: o envio passa, então
    // não exibimos overlay de bloqueio enganoso.
    if (result && result.action === "block" && !result.offline) {
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
  // Aviso de segurança institucional: painel slate, acento fino por estado
  // (vermelho = bloqueio, âmbar = aprovação), achados como tabela de evidência
  // de auditoria. Sem webfonts (CSP dos hosts) — a personalidade vem de peso,
  // caixa alta espaçada e mono para evidência. Dark mode via prefers-color-scheme.
  let overlayEl = null;

  const SEV_LABEL = { critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo" };

  const SHIELD_SVG = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2.8 4.8 5.6v5.5c0 4.5 3 8.5 7.2 10.1 4.2-1.6 7.2-5.6 7.2-10.1V5.6L12 2.8Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>`;

  function ensureOverlay() {
    if (overlayEl) return overlayEl;
    overlayEl = document.createElement("div");
    overlayEl.id = "guardian-overlay";
    overlayEl.innerHTML = `
      <style>
        #guardian-overlay { position: fixed; inset: 0; z-index: 2147483647;
          display: none; align-items: center; justify-content: center; padding: 16px;
          background: rgba(9, 11, 15, .62); backdrop-filter: blur(3px) saturate(.85);
          font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
          -webkit-font-smoothing: antialiased; text-align: left; }
        #guardian-overlay.show { display: flex; }
        #guardian-overlay, #guardian-overlay * { box-sizing: border-box; margin: 0; padding: 0; }
        #guardian-card { width: min(460px, 100%); background: #ffffff; color: #16181d;
          border: 1px solid #e3e6eb; border-radius: 10px; overflow: hidden;
          box-shadow: 0 1px 2px rgba(0,0,0,.18), 0 24px 64px rgba(8,10,14,.4); }
        @keyframes g-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
        #guardian-overlay.show #guardian-card { animation: g-in .16s ease-out; }
        @media (prefers-reduced-motion: reduce) { #guardian-overlay.show #guardian-card { animation: none; } }
        #guardian-card .g-accent { height: 3px; background: #b42318; }
        #guardian-card .g-accent.g-amber { background: #b54708; }
        #guardian-card .g-head { display: flex; align-items: center; gap: 7px; padding: 14px 20px 0; color: #5a6270; }
        #guardian-card .g-brand { font-size: 10.5px; font-weight: 600; letter-spacing: .09em; text-transform: uppercase; }
        #guardian-card .g-body { padding: 13px 20px 18px; }
        #guardian-card .g-title { font-size: 16.5px; font-weight: 650; letter-spacing: -.01em;
          line-height: 1.3; margin-bottom: 6px; color: inherit; }
        #guardian-card .g-text { font-size: 13.5px; line-height: 1.55; color: #3d434d; }
        #guardian-card .g-evidence { margin-top: 12px; border: 1px solid #e3e6eb; border-radius: 7px;
          overflow: hidden; max-height: 190px; overflow-y: auto; }
        #guardian-card .g-row { display: flex; align-items: center; gap: 10px; padding: 8px 12px;
          border-top: 1px solid #eef0f3; font-size: 12.5px; min-width: 0; }
        #guardian-card .g-row:first-child { border-top: 0; }
        #guardian-card .g-sev { flex: none; font-size: 9.5px; font-weight: 700; letter-spacing: .07em;
          text-transform: uppercase; padding: 2px 7px; border-radius: 99px;
          background: #eef0f3; color: #5a6270; }
        #guardian-card .g-sev-critical, #guardian-card .g-sev-high { background: #fee4e2; color: #b42318; }
        #guardian-card .g-sev-medium { background: #fef0c7; color: #b54708; }
        #guardian-card .g-det { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        #guardian-card .g-snip { margin-left: auto; flex: none; font-family: ui-monospace, "Cascadia Mono",
          "SF Mono", Consolas, monospace; font-size: 11.5px; color: #5a6270;
          background: #f4f5f7; border: 1px solid #e9ebef; padding: 2px 7px; border-radius: 4px; }
        #guardian-card .g-foot { display: flex; align-items: center; gap: 12px; padding: 12px 20px;
          border-top: 1px solid #e3e6eb; background: #fafbfc; }
        #guardian-card .g-audit { font-size: 11.5px; line-height: 1.45; color: #5a6270; }
        #guardian-card .g-actions { margin-left: auto; display: flex; align-items: center; gap: 8px; flex: none; }
        #guardian-card button, #guardian-card a.g-secondary { font: inherit; font-size: 13px;
          font-weight: 600; border-radius: 7px; padding: 7px 14px; cursor: pointer;
          text-decoration: none; white-space: nowrap; }
        #guardian-card .g-primary { background: #16181d; color: #ffffff; border: 1px solid #16181d; }
        #guardian-card .g-primary:hover { background: #2a2e36; }
        #guardian-card a.g-secondary { background: transparent; color: #16181d; border: 1px solid #d4d8de; }
        #guardian-card a.g-secondary:hover { border-color: #aab1bb; }
        #guardian-card :focus-visible { outline: 2px solid #5a6270; outline-offset: 2px; }
        #guardian-card .g-spinner { width: 16px; height: 16px; border: 2px solid #d4d8de;
          border-top-color: #16181d; border-radius: 50%; flex: none;
          animation: gspin 1s linear infinite; }
        @keyframes gspin { to { transform: rotate(360deg); } }
        #guardian-card .g-checking { display: flex; align-items: center; gap: 10px;
          padding: 16px 20px; font-size: 13.5px; color: #3d434d; }
        @media (prefers-color-scheme: dark) {
          #guardian-card { background: #1c1f26; color: #e8eaee; border-color: #2e333c;
            box-shadow: 0 1px 2px rgba(0,0,0,.5), 0 24px 64px rgba(0,0,0,.6); }
          #guardian-card .g-accent { background: #e5484d; }
          #guardian-card .g-accent.g-amber { background: #d97706; }
          #guardian-card .g-head { color: #9ba3af; }
          #guardian-card .g-text { color: #c3c9d2; }
          #guardian-card .g-evidence { border-color: #2e333c; }
          #guardian-card .g-row { border-top-color: #262b33; }
          #guardian-card .g-sev { background: #262b33; color: #9ba3af; }
          #guardian-card .g-sev-critical, #guardian-card .g-sev-high { background: rgba(229,72,77,.16); color: #ff8f92; }
          #guardian-card .g-sev-medium { background: rgba(217,119,6,.16); color: #f5b45e; }
          #guardian-card .g-snip { background: #262b33; border-color: #30353f; color: #aeb6c2; }
          #guardian-card .g-foot { background: #181b21; border-top-color: #2e333c; }
          #guardian-card .g-audit { color: #9ba3af; }
          #guardian-card .g-primary { background: #e8eaee; color: #16181d; border-color: #e8eaee; }
          #guardian-card .g-primary:hover { background: #ffffff; }
          #guardian-card a.g-secondary { color: #e8eaee; border-color: #3a404b; }
          #guardian-card a.g-secondary:hover { border-color: #5a6270; }
          #guardian-card .g-spinner { border-color: #3a404b; border-top-color: #e8eaee; }
          #guardian-card .g-checking { color: #c3c9d2; }
          #guardian-card :focus-visible { outline-color: #9ba3af; }
        }
      </style>
      <div id="guardian-card" role="alertdialog" aria-modal="true" aria-labelledby="g-title"></div>`;
    (document.body || document.documentElement).appendChild(overlayEl);
    return overlayEl;
  }

  function showOverlay(kind, html) {
    const el = ensureOverlay();
    const card = el.querySelector("#guardian-card");
    if (kind === "verificando") {
      card.innerHTML = `<div class="g-accent"></div><div class="g-checking"><span class="g-spinner"></span>${esc(html)}</div>`;
    } else {
      card.innerHTML = html;
      const close = card.querySelector("#g-close");
      if (close) {
        close.addEventListener("click", hideOverlay);
        try {
          close.focus({ preventScroll: true });
        } catch {
          /* ignore */
        }
      }
    }
    el.classList.add("show");
  }

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && overlayEl && overlayEl.classList.contains("show")) {
      hideOverlay();
    }
  });

  function hideOverlay() {
    if (overlayEl) overlayEl.classList.remove("show");
  }

  function findingsTable(findings) {
    if (!findings || !findings.length) return "";
    const rows = findings
      .map((f) => {
        const sev = String(f.severity || "").toLowerCase();
        const label = SEV_LABEL[sev] || "Info";
        return `<div class="g-row"><span class="g-sev g-sev-${esc(sev)}">${esc(label)}</span><span class="g-det">${esc(f.label)}</span><code class="g-snip">${esc(f.snippet)}</code></div>`;
      })
      .join("");
    return `<div class="g-evidence">${rows}</div>`;
  }

  function renderCard(opts) {
    const secondary = opts.linkUrl
      ? `<a class="g-secondary" href="${esc(opts.linkUrl)}" target="_blank" rel="noopener">${esc(opts.linkLabel)}</a>`
      : "";
    return `
      <div class="g-accent${opts.amber ? " g-amber" : ""}"></div>
      <div class="g-head">${SHIELD_SVG}<span class="g-brand">Claude Guardian &middot; Preven&ccedil;&atilde;o de perda de dados</span></div>
      <div class="g-body">
        <h2 class="g-title" id="g-title">${esc(opts.title)}</h2>
        <p class="g-text">${esc(opts.text)}</p>
        ${findingsTable(opts.findings)}
      </div>
      <div class="g-foot">
        <span class="g-audit">Evento registrado no log de auditoria da organiza&ccedil;&atilde;o.</span>
        <span class="g-actions">${secondary}<button class="g-primary" id="g-close">${esc(opts.closeLabel)}</button></span>
      </div>`;
  }

  function formatBlock(r) {
    const hasFindings = r.findings && r.findings.length;
    return renderCard({
      title: "Envio bloqueado",
      text: hasFindings
        ? "A mensagem contém dados sensíveis e foi retida nesta máquina. Nada foi enviado ao provedor de IA."
        : r.reason || "A mensagem foi retida pela política de segurança de dados.",
      findings: r.findings,
      linkUrl: r.approvalUrl,
      linkLabel: "Solicitar exceção",
      closeLabel: "Entendi",
    });
  }

  function formatApproval(r) {
    return renderCard({
      amber: true,
      title: "Aprovação necessária",
      text: "O envio foi retido e aguarda liberação do time de segurança. Nada foi enviado ao provedor de IA.",
      findings: r.findings,
      linkUrl: r.approvalUrl,
      linkLabel: "Acompanhar solicitação",
      closeLabel: "Fechar",
    });
  }

  function esc(s) {
    // Escapa também aspas: valores são interpolados dentro de atributos
    // (href do link de aprovação, classe do chip de severidade).
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
