// Service worker: the only context allowed to talk to localhost.
// Content scripts message us; we POST to the guardian and relay the verdict.
// Fail-closed: any network/parse error becomes a BLOCK.

const api = globalThis.browser ?? globalThis.chrome;

const DEFAULTS = { endpoint: "http://127.0.0.1:7734", token: "" };

async function getSettings() {
  try {
    const stored = await api.storage.local.get(["endpoint", "token"]);
    return {
      endpoint: stored.endpoint || DEFAULTS.endpoint,
      token: stored.token ?? DEFAULTS.token,
    };
  } catch {
    return DEFAULTS;
  }
}

async function scan(payload) {
  const { endpoint, token } = await getSettings();
  const url = endpoint.replace(/\/$/, "") + "/api/scan-web";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { "X-Guardian-Token": token } : {}),
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      return failClosed(`guardian respondeu ${res.status}`);
    }
    const data = await res.json();
    if (!data || typeof data.action !== "string") {
      return failClosed("resposta inválida do guardian");
    }
    return data;
  } catch (err) {
    clearTimeout(timer);
    return failClosed(
      err && err.name === "AbortError"
        ? "guardian não respondeu (timeout)"
        : "guardian offline (localhost inacessível)",
    );
  }
}

function failClosed(reason) {
  return {
    action: "block",
    findings: [],
    reason: `Claude Guardian indisponível — envio bloqueado por segurança.\n(${reason})`,
    offline: true,
  };
}

api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "guardian-scan") {
    scan(msg.payload).then(sendResponse);
    return true; // async response
  }
  return false;
});
