// Regressão: a ação `substitute` só pode reescrever o corpo do envio onde o
// adapter sabe fazê-lo in-place (injectRedaction — hoje só claude.ai). Em sites
// sem essa capacidade (ChatGPT/Gemini/…), substitute NÃO pode deixar o dado real
// sair: precisa degradar para BLOCK (fail-closed). Roda o injected.js real num
// vm, como em extension-upload.test.ts. Usa placeholders (sem PII real): o
// verdict é mockado, então o conteúdo do texto é irrelevante para o teste.
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

// Placeholders sem PII: o valor real que o site "digitou" e o fictício que o
// daemon (mockado) devolveria em substitutedText.
const REAL = "SENSITIVE-PLACEHOLDER-1111";
const FAKE = "FICTION-PLACEHOLDER-2222";
const substituteVerdict = () => ({
  action: "substitute",
  substitutedText: `dado ${FAKE}`,
});

describe("injected.js — substitute é fail-closed sem injectRedaction", () => {
  it("claude.ai: reescreve o corpo com o fictício e NÃO bloqueia", async () => {
    const { doFetch, fetchCalls } = setupInjected(substituteVerdict, "claude.ai");
    await doFetch("https://claude.ai/api/o/chat_conversations/c/completion", {
      method: "POST",
      body: JSON.stringify({ prompt: `dado ${REAL}` }),
    });
    expect(fetchCalls).toHaveLength(1);
    const sent = JSON.parse((fetchCalls[0]?.init as { body: string }).body) as {
      prompt: string;
    };
    expect(sent.prompt).toBe(`dado ${FAKE}`);
    expect(sent.prompt).not.toContain(REAL);
  });

  it("gemini: sem injectRedaction, BLOQUEIA em vez de vazar o dado real", async () => {
    const { doFetch, fetchCalls } = setupInjected(
      substituteVerdict,
      "gemini.google.com",
    );
    const body = `f.req=${encodeURIComponent(JSON.stringify([[`dado ${REAL}`]]))}`;
    await expect(
      doFetch(
        "https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?rpcids=x",
        { method: "POST", body },
      ),
    ).rejects.toThrow(/bloqueado/i);
    expect(fetchCalls).toHaveLength(0);
  });
});
