// Regressão da ação `substitute` no injected.js (rodado num vm, como
// extension-upload.test.ts). Contrato: o daemon devolve o mapa real→fictício
// (verdict.substitutions); cada adapter aplica no seu formato via
// injectSubstitution, e decide() AUTO-VERIFICA (extractText do corpo novo não
// pode conter nenhum valor real) — senão FAIL-CLOSED (block).
//   • claude.ai e gemini.google.com sabem reescrever → substituem.
//   • sites sem injectSubstitution (ex.: chatgpt.com) → bloqueiam.
// Usa placeholders (sem PII real): o verdict é mockado.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const injectedSrc = readFileSync(
  join(__dirname, "../extension/injected.js"),
  "utf8",
);

type Verdict = () => unknown;

function setupInjected(verdict: Verdict, hostname: string) {
  const listeners: Array<(e: { data: unknown }) => void> = [];
  const fetchCalls: Array<{ input: unknown; init: unknown }> = [];

  const win: Record<string, unknown> = {
    addEventListener: (type: string, fn: (e: { data: unknown }) => void) => {
      if (type === "message") listeners.push(fn);
    },
    removeEventListener: () => {},
    postMessage: (msg: { __guardian?: string; id?: string; nonce?: string }) => {
      if (msg && msg.__guardian === "scan-request") {
        const result = verdict();
        queueMicrotask(() => {
          for (const fn of listeners) {
            fn({
              data: {
                __guardian: "scan-result",
                id: msg.id,
                nonce: msg.nonce,
                result,
              },
            });
          }
        });
      }
    },
    fetch: (input: unknown, init: unknown) => {
      fetchCalls.push({ input, init });
      return Promise.resolve({ ok: true });
    },
    XMLHttpRequest: undefined,
  };

  const context: Record<string, unknown> = {
    window: win,
    document: {
      documentElement: { dataset: { guardianNonce: "testnonce" } },
      title: "t",
    },
    location: { hostname, href: `https://${hostname}/x` },
    MutationObserver: class {
      observe() {}
      disconnect() {}
    },
    console,
    setTimeout,
    queueMicrotask,
    FormData,
    File,
    Blob,
    URLSearchParams,
    TextDecoder,
    ArrayBuffer,
    Request: undefined,
  };
  vm.createContext(context);
  vm.runInContext(injectedSrc, context);
  const doFetch = win["fetch"] as (
    input: string,
    init: { method: string; body: unknown },
  ) => Promise<unknown>;
  return { doFetch, fetchCalls };
}

// Placeholders sem PII: o valor real "digitado" e o fictício que o daemon
// (mockado) devolveria no mapa substitutions.
const REAL = "SENSITIVE-PLACEHOLDER-1111";
const FAKE = "FICTION-PLACEHOLDER-2222";
const substituteVerdict = () => ({
  action: "substitute",
  substitutions: [{ raw: REAL, fake: FAKE }],
});

function sentBody(fetchCalls: Array<{ init: unknown }>): string {
  return String((fetchCalls[0]?.init as { body: unknown }).body ?? "");
}

describe("injected.js — ação substitute", () => {
  it("claude.ai: reescreve o prompt com o fictício (não bloqueia)", async () => {
    const { doFetch, fetchCalls } = setupInjected(substituteVerdict, "claude.ai");
    await doFetch("https://claude.ai/api/o/chat_conversations/c/completion", {
      method: "POST",
      body: JSON.stringify({ prompt: `dado ${REAL}` }),
    });
    expect(fetchCalls).toHaveLength(1);
    const sent = JSON.parse(sentBody(fetchCalls)) as { prompt: string };
    expect(sent.prompt).toBe(`dado ${FAKE}`);
    expect(sent.prompt).not.toContain(REAL);
  });

  it("gemini: reescreve o f.req com o fictício (não bloqueia)", async () => {
    const { doFetch, fetchCalls } = setupInjected(
      substituteVerdict,
      "gemini.google.com",
    );
    const body = `f.req=${encodeURIComponent(JSON.stringify([[`dado ${REAL}`]]))}`;
    await doFetch(
      "https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?rpcids=x",
      { method: "POST", body },
    );
    expect(fetchCalls).toHaveLength(1);
    const out = sentBody(fetchCalls);
    expect(out).toContain(FAKE);
    expect(out).not.toContain(REAL);
  });

  it("chatgpt: sem injectSubstitution, BLOQUEIA em vez de vazar (fail-closed)", async () => {
    const { doFetch, fetchCalls } = setupInjected(
      substituteVerdict,
      "chatgpt.com",
    );
    await expect(
      doFetch("https://chatgpt.com/backend-api/conversation", {
        method: "POST",
        body: JSON.stringify({
          messages: [{ content: { parts: [`dado ${REAL}`] } }],
        }),
      }),
    ).rejects.toThrow(/bloqueado/i);
    expect(fetchCalls).toHaveLength(0);
  });
});
