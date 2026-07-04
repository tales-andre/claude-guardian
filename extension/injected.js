// Runs in the PAGE context (not the extension sandbox) so it can wrap
// window.fetch / XMLHttpRequest before the AI provider's app uses them.
// This is the ENFORCEMENT layer: even if the UI-layer button interception
// breaks, no message leaves without a verdict. Communicates with the content
// script via window.postMessage.
//
// Multi-provider: the per-site knowledge (which request is a "send" and how to
// pull the user text out of its body) lives in the ADAPTERS registry below.
// The hooks are generic. Adding a site = one adapter here + one host entry in
// the manifests. Política FAIL-OPEN (escolha da org): se um request é
// reconhecido como envio mas não pode ser verificado (texto não extraível ou
// daemon offline), o envio PASSA e o drift é registrado — a extensão não trava
// o site. Bloqueio só quando um segredo é de fato detectado.
(() => {
  // Nonce do handshake com o content script (ver content.js): lido e removido
  // do DOM antes de qualquer script da página rodar (ambos são content scripts
  // document_start; este roda em world MAIN via manifest). Se o nonce faltar,
  // nada é liberado: os scans expiram no timeout e bloqueiam (fail-closed).
  // Handshake de nonce com o content script (ISOLATED). A ordem de execução
  // entre um content script MAIN e um ISOLATED no document_start NÃO é
  // garantida pelo Chromium. Se o nonce ainda não estiver no DOM (injected
  // rodou primeiro), observamos até o content script gravá-lo — ainda antes de
  // qualquer script da página rodar — em vez de assumir "vazio" e travar tudo.
  let NONCE = document.documentElement.dataset.guardianNonce || "";
  if (NONCE) {
    delete document.documentElement.dataset.guardianNonce;
  } else {
    const mo = new MutationObserver(() => {
      const n = document.documentElement.dataset.guardianNonce;
      if (n) {
        NONCE = n;
        delete document.documentElement.dataset.guardianNonce;
        mo.disconnect();
      }
    });
    mo.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-guardian-nonce"],
    });
  }

  const pending = new Map();
  let seq = 0;

  // ── Adapters ──────────────────────────────────────────────────────────────
  // Each adapter: { host: RegExp(hostname), isSendRequest(url, method),
  //                 extractText(body) -> string, injectRedaction?(body, text) -> newBody }
  // extractText returns "" when there is no user text in this request (e.g. a
  // poll/telemetry POST that happens to match) — those are let through.

  function parseJson(body) {
    if (typeof body !== "string") return null;
    try {
      return JSON.parse(body);
    } catch {
      return null;
    }
  }

  // Generic "messages[].content" extractor shared by several providers.
  function textFromMessages(json) {
    if (!json) return "";
    if (typeof json.prompt === "string") return json.prompt;
    if (Array.isArray(json.messages)) {
      return json.messages
        .map((m) => {
          if (typeof m.content === "string") return m.content;
          // OpenAI/others: content can be an array of parts.
          if (Array.isArray(m.content)) {
            return m.content
              .map((p) => (typeof p === "string" ? p : typeof p?.text === "string" ? p.text : ""))
              .join("\n");
          }
          if (Array.isArray(m.parts)) {
            return m.parts.map((p) => (typeof p === "string" ? p : "")).join("\n");
          }
          return "";
        })
        .join("\n");
    }
    return "";
  }

  const claudeAdapter = {
    host: /(^|\.)claude\.ai$/i,
    isSendRequest(url, method) {
      return method === "POST" && /\/(completion|retry_completion|append_message|messages)\b/i.test(url);
    },
    extractText(body) {
      return textFromMessages(parseJson(body));
    },
    injectRedaction(body, redactedText) {
      const json = parseJson(body);
      if (!json) return null;
      json.prompt = redactedText;
      return JSON.stringify(json);
    },
  };

  const chatgptAdapter = {
    host: /(^|\.)chatgpt\.com$|(^|\.)chat\.openai\.com$/i,
    isSendRequest(url, method) {
      // ChatGPT posts new turns to /backend-api/conversation (and /f/ variant).
      return method === "POST" && /\/backend-api\/(f\/)?conversation\b/i.test(url);
    },
    extractText(body) {
      const json = parseJson(body);
      if (!json) return "";
      if (Array.isArray(json.messages)) {
        return json.messages
          .map((m) => {
            const parts = m?.content?.parts;
            if (Array.isArray(parts)) {
              return parts.map((p) => (typeof p === "string" ? p : typeof p?.text === "string" ? p.text : "")).join("\n");
            }
            return typeof m?.content === "string" ? m.content : "";
          })
          .join("\n");
      }
      return textFromMessages(json);
    },
    // No safe in-place redaction (parts carry ids); fall back to block.
  };

  const geminiAdapter = {
    host: /(^|\.)gemini\.google\.com$/i,
    isSendRequest(url, method) {
      // O envio de mensagem no Gemini é o RPC StreamGenerate
      // (assistant.lamda.BardFrontendService/StreamGenerate). NÃO casar
      // `batchexecute`/`GenerateContent` genéricos: o Gemini os usa para
      // dezenas de RPCs que não são envio, e com fail-closed isso travava o
      // app inteiro. TODO: confirmar o rpcid exato com tráfego real (Network).
      return method === "POST" && /StreamGenerate/i.test(url);
    },
    extractText(body) {
      // Body is a urlencoded "f.req=<json>" blob, not plain JSON. O prompt fica
      // numa string interna duplamente JSON-encodada. Decodifica TODAS as
      // strings do envelope e escaneia o conjunto: escolher só a "melhor"
      // string (com whitespace) deixava um segredo sem espaço — ex. uma AWS
      // key colada sozinha — cair no fail-open e sair sem scan.
      // TODO: validar formato exato do f.req com tráfego real do Gemini.
      let raw = typeof body === "string" ? body : "";
      if (!raw) return "";
      try {
        const params = new URLSearchParams(raw);
        if (params.has("f.req")) raw = params.get("f.req") || raw;
      } catch {
        /* not urlencoded — use raw */
      }
      const candidates = raw.match(/"((?:[^"\\]|\\.){8,})"/g) || [];
      const decoded = [];
      for (const c of candidates) {
        try {
          const s = JSON.parse(c);
          if (typeof s === "string") decoded.push(s);
        } catch {
          decoded.push(c.slice(1, -1));
        }
      }
      // Nunca "" para um corpo não-vazio: no pior caso escaneia o blob inteiro
      // (segredos alfanuméricos aparecem literalmente nele).
      return decoded.join("\n") || raw;
    },
  };

  const copilotAdapter = {
    host: /(^|\.)copilot\.microsoft\.com$/i,
    isSendRequest(url, method) {
      // Copilot turns go over a websocket in many flows; the HTTP create/turn
      // endpoints are covered here. WebSocket sends are a known residual gap.
      // TODO: validar endpoint/body de envio do Copilot com tráfego real.
      return method === "POST" && /\/(turns|chat|conversations?\/[^/]+\/messages)\b/i.test(url);
    },
    extractText(body) {
      const json = parseJson(body);
      if (!json) return "";
      if (typeof json.text === "string") return json.text;
      if (typeof json.message === "string") return json.message;
      if (typeof json.content === "string") return json.content;
      return textFromMessages(json);
    },
  };

  const mistralAdapter = {
    host: /(^|\.)chat\.mistral\.ai$/i,
    isSendRequest(url, method) {
      // TODO: validar endpoint/body de envio do Le Chat com tráfego real.
      return method === "POST" && /\/(chat\/completions|conversations?\b|messages\b)/i.test(url);
    },
    extractText(body) {
      const json = parseJson(body);
      if (!json) return "";
      if (typeof json.message === "string") return json.message;
      if (typeof json.text === "string") return json.text;
      return textFromMessages(json);
    },
  };

  const adaptaAdapter = {
    host: /(^|\.)adapta\.one$/i,
    isSendRequest(url, method) {
      // TODO: validar endpoint/body de envio do Adapta One com tráfego real.
      return method === "POST" && /\/(chat|message|conversation|completion)/i.test(url);
    },
    extractText(body) {
      const json = parseJson(body);
      if (!json) return "";
      if (typeof json.message === "string") return json.message;
      if (typeof json.prompt === "string") return json.prompt;
      if (typeof json.text === "string") return json.text;
      return textFromMessages(json);
    },
  };

  const ADAPTERS = [
    claudeAdapter,
    chatgptAdapter,
    geminiAdapter,
    copilotAdapter,
    mistralAdapter,
    adaptaAdapter,
  ];

  const adapter = ADAPTERS.find((a) => a.host.test(location.hostname)) || null;

  // ── Scan bridge ─────────────────────────────────────────────────────────────
  // Ask the content script (which can reach the background worker) to scan.
  function requestScan(payload) {
    return new Promise((resolve) => {
      const id = `gx_${++seq}`;
      pending.set(id, resolve);
      window.postMessage(
        { __guardian: "scan-request", id, nonce: NONCE, payload },
        "*",
      );
      // Hard fail-closed safety net if no reply arrives.
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          resolve({ action: "block", reason: "Sem resposta do Guardian (fail-closed).", offline: true });
        }
      }, 6000);
    });
  }

  window.addEventListener("message", (e) => {
    const d = e.data;
    if (
      !d ||
      d.__guardian !== "scan-result" ||
      d.nonce !== NONCE ||
      !pending.has(d.id)
    )
      return;
    const resolve = pending.get(d.id);
    pending.delete(d.id);
    resolve(d.result);
  });

  // Normaliza qualquer corpo de request para string antes do extractText.
  // Sem isso, um envio reconhecido com corpo não-string (URLSearchParams,
  // Blob, ArrayBuffer, FormData — o que o site usar) virava "" e caía no
  // fail-open: o segredo saía sem scan.
  async function bodyToString(body) {
    try {
      if (body == null) return "";
      if (typeof body === "string") return body;
      if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return body.toString();
      }
      if (typeof Blob !== "undefined" && body instanceof Blob) {
        return await body.text();
      }
      if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
        return new TextDecoder().decode(body);
      }
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        const parts = [];
        for (const [k, v] of body.entries()) {
          parts.push(typeof v === "string" ? `${k}=${v}` : v.name || "");
        }
        return parts.join("\n");
      }
    } catch {
      /* corpo ilegível — segue para "" (drift registrado pelo decide) */
    }
    return "";
  }

  // Shared verdict logic for a recognized send. Returns:
  //  { block: true } | { block: false, redactedBody?: string }
  // Fail-OPEN: um envio que não pôde ser verificado (texto não extraível ou
  // daemon offline) PASSA e registra drift. Bloqueia só em detecção real.
  async function decide(body) {
    let text = "";
    try {
      text = adapter.extractText(body) || "";
    } catch {
      text = "";
    }
    if (!text) {
      // Envio reconhecido mas sem texto extraível (formato do site mudou/desconhecido).
      // Política FAIL-OPEN (escolha da org): não trava o site — deixa passar e
      // registra o drift (via content → background → daemon → fleet) para que a
      // divergência do adapter fique visível e seja corrigida.
      window.postMessage(
        { __guardian: "extract-fail", nonce: NONCE, host: location.hostname },
        "*",
      );
      return { block: false };
    }
    const verdict = await requestScan({ text, context: { url: location.href, tabTitle: document.title } });
    if (verdict.offline) {
      // Não foi possível verificar (daemon offline / sem resposta). FAIL-OPEN:
      // deixa o envio passar em vez de travar o site. A saúde do daemon é
      // acompanhada separadamente pelo heartbeat/fleet.
      return { block: false };
    }
    if (verdict.action === "block" || verdict.action === "require-approval") {
      return { block: true };
    }
    if (verdict.action === "redact" && typeof verdict.redactedText === "string" && adapter.injectRedaction) {
      const newBody = adapter.injectRedaction(body, verdict.redactedText);
      if (typeof newBody === "string") return { block: false, redactedBody: newBody };
    }
    return { block: false };
  }

  if (!adapter) {
    // No adapter for this host — should not happen (manifest only injects on
    // configured sites). Do nothing rather than interfere.
    window.postMessage({ __guardian: "injected-ready" }, "*");
    return;
  }

  // ── fetch hook ──────────────────────────────────────────────────────────────
  const originalFetch = window.fetch;
  window.fetch = async function (input, init) {
    const isRequest = typeof Request !== "undefined" && input instanceof Request;
    const url =
      typeof input === "string" ? input : isRequest ? input.url : String(input || "");
    const method = (init?.method || (isRequest && input.method) || "GET").toUpperCase();

    if (adapter.isSendRequest(url, method)) {
      // O corpo pode vir no init OU dentro de um Request (fetch(new Request(...))).
      // Ler só init.body deixava envios via Request saírem sem scan (fail-open).
      let body;
      if (init?.body != null) {
        body = await bodyToString(init.body);
      } else if (isRequest) {
        try {
          body = await input.clone().text();
        } catch {
          body = "";
        }
      } else {
        body = "";
      }
      const { block, redactedBody } = await decide(body);
      if (block) {
        // TypeError é o que um fetch com falha de rede real rejeita — os
        // handlers de erro do app reconhecem e resetam a UI (uma DOMException
        // com name exótico deixava apps em "processando" eterno).
        console.info("[guardian] envio bloqueado (fetch)");
        throw new TypeError("Failed to fetch — bloqueado pelo Claude Guardian");
      }
      if (typeof redactedBody === "string") {
        init = { ...init, body: redactedBody };
      }
    }

    return originalFetch.call(this, input, init);
  };

  // ── XMLHttpRequest hook ──────────────────────────────────────────────────────
  // Covers providers that send turns over XHR instead of fetch. Same flow:
  // recognize the send on open(), then gate it on send() before bytes leave.
  const XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype) {
    const origOpen = XHR.prototype.open;
    const origSend = XHR.prototype.send;

    XHR.prototype.open = function (method, url, ...rest) {
      try {
        this.__guardianMethod = String(method || "GET").toUpperCase();
        this.__guardianUrl = String(url || "");
      } catch {
        /* ignore */
      }
      return origOpen.call(this, method, url, ...rest);
    };

    XHR.prototype.send = function (body) {
      const method = this.__guardianMethod || "GET";
      const url = this.__guardianUrl || "";
      if (!adapter.isSendRequest(url, method)) {
        return origSend.call(this, body);
      }
      // Normaliza o corpo (string, URLSearchParams, Blob, ArrayBuffer…) antes
      // de decidir — corpo não-string não pode mais escapar do scan.
      bodyToString(body)
        .then((text) => decide(text))
        .then(({ block, redactedBody }) => {
        if (block) {
          // Nenhum byte saiu (origSend nunca foi chamado). Sem a send flag,
          // abort() é no-op: readyState fica preso em OPENED e o app (Gemini/
          // WIZ acompanha readystatechange) fica "processando" para sempre.
          // Simula uma falha de rede completa — readyState DONE, status 0,
          // readystatechange + error + loadend — para o app tratar como
          // request que falhou e liberar a UI.
          try {
            console.info("[guardian] envio bloqueado (xhr)");
            Object.defineProperty(this, "readyState", { value: 4, configurable: true });
            Object.defineProperty(this, "status", { value: 0, configurable: true });
            Object.defineProperty(this, "statusText", { value: "", configurable: true });
            Object.defineProperty(this, "response", { value: "", configurable: true });
            Object.defineProperty(this, "responseText", { value: "", configurable: true });
            this.dispatchEvent(new Event("readystatechange"));
            this.dispatchEvent(new ProgressEvent("error"));
            this.dispatchEvent(new ProgressEvent("loadend"));
          } catch {
            /* ignore */
          }
          return;
        }
        origSend.call(this, typeof redactedBody === "string" ? redactedBody : body);
      });
    };
  }

  window.postMessage({ __guardian: "injected-ready" }, "*");
})();
