// Service worker: the only context allowed to talk to localhost.
// Content scripts message us; we POST to the guardian and relay the verdict.
// Em erro de rede/parse retorna um veredito `offline: true`; a camada de
// enforcement (injected.js) trata isso como FAIL-OPEN (deixa passar + registra),
// então um envio não-verificável não trava o site.

const api = globalThis.browser ?? globalThis.chrome;

const DEFAULTS = { endpoint: "http://127.0.0.1:7734", token: "" };

// Managed storage (política da organização via MDM) tem precedência sobre o
// que o usuário salvou na options page. storage.managed lança/retorna vazio
// quando não há política — nesse caso vale storage.local (modo standalone).
async function getManaged() {
  try {
    return (await api.storage.managed.get(["endpoint", "token"])) || {};
  } catch {
    return {};
  }
}

async function getSettings() {
  const managed = await getManaged();
  try {
    const stored = await api.storage.local.get(["endpoint", "token"]);
    return {
      endpoint: managed.endpoint || stored.endpoint || DEFAULTS.endpoint,
      token: managed.endpoint
        ? (managed.token ?? "")
        : (stored.token ?? DEFAULTS.token),
    };
  } catch {
    return {
      endpoint: managed.endpoint || DEFAULTS.endpoint,
      token: managed.token ?? DEFAULTS.token,
    };
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

// ── Heartbeat + telemetria de drift ───────────────────────────────────────────
// A cada 5 min (chrome.alarms — setInterval não sobrevive ao service worker)
// pinga o daemon local com a versão da extensão e as falhas de extractText por
// provider acumuladas. O daemon repassa ao fleet: extensão silenciosa =
// tampered; extract-fail crescendo = endpoint do provider mudou (drift).
const HEARTBEAT_ALARM = "guardian-heartbeat";
const FAIL_KEY = "extractFailures";

async function bumpExtractFailure(host) {
  try {
    const stored = await api.storage.local.get(FAIL_KEY);
    const failures = stored[FAIL_KEY] || {};
    failures[host] = (failures[host] || 0) + 1;
    await api.storage.local.set({ [FAIL_KEY]: failures });
  } catch {
    // telemetria é best-effort
  }
}

async function sendHeartbeat() {
  const { endpoint, token } = await getSettings();
  let failures = {};
  try {
    const stored = await api.storage.local.get(FAIL_KEY);
    failures = stored[FAIL_KEY] || {};
  } catch {
    failures = {};
  }
  try {
    const res = await fetch(endpoint.replace(/\/$/, "") + "/api/extension/heartbeat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { "X-Guardian-Token": token } : {}),
      },
      body: JSON.stringify({
        version: api.runtime.getManifest().version,
        extractFailures: failures,
      }),
    });
    if (res.ok) {
      // Contadores entregues — zera para o próximo ciclo.
      await api.storage.local.set({ [FAIL_KEY]: {} });
    }
  } catch {
    // daemon offline: contadores ficam acumulados para o próximo ping
  }
}

api.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: 5 });
api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === HEARTBEAT_ALARM) sendHeartbeat();
});
sendHeartbeat();

api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "guardian-scan") {
    scan(msg.payload).then(sendResponse);
    return true; // async response
  }
  if (msg && msg.type === "guardian-extract-fail") {
    bumpExtractFailure(String(msg.host || "unknown"));
    return false;
  }
  return false;
});
