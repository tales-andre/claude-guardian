// Restrição de modelos no navegador (injected.js num vm, como
// extension-substitute.test.ts). Contrato: o adapter extrai o campo `model`
// do corpo do envio e o manda em context.model; o daemon (mockado aqui)
// bloqueia quando o modelo casa com config.blockedWebModels. O envio nunca
// sai quando o veredito é block — inclusive com prompt limpo (a restrição é
// de governança, não de conteúdo) e com prompt VAZIO (caminho !text, que
// antes era fail-open incondicional).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const injectedSrc = readFileSync(
  join(__dirname, "../extension/injected.js"),
  "utf8",
);

type ScanPayload = {
  text?: string;
  context?: { model?: string; url?: string };
};
type Verdict = (payload: ScanPayload) => unknown;

function setupInjected(verdict: Verdict, hostname: string) {
  const listeners: Array<(e: { data: unknown }) => void> = [];
  const fetchCalls: Array<{ input: unknown; init: unknown }> = [];
  const scanPayloads: ScanPayload[] = [];

  const win: Record<string, unknown> = {
    addEventListener: (type: string, fn: (e: { data: unknown }) => void) => {
      if (type === "message") listeners.push(fn);
    },
    removeEventListener: () => {},
    postMessage: (msg: {
      __guardian?: string;
      id?: string;
      nonce?: string;
      payload?: ScanPayload;
    }) => {
      if (msg && msg.__guardian === "scan-request") {
        const payload = msg.payload ?? {};
        scanPayloads.push(payload);
        const result = verdict(payload);
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
  return { doFetch, fetchCalls, scanPayloads };
}

// Espelha o check do daemon (scanWeb): bloqueia quando o modelo declarado
// contém "fable" (substring, case-insensitive).
const modelPolicyVerdict = (payload: ScanPayload) =>
  payload.context?.model?.toLowerCase().includes("fable")
    ? { action: "block", reason: "modelo restrito" }
    : { action: "allow" };

describe("injected.js — restrição de modelos", () => {
  it("claude.ai: envio com modelo bloqueado NÃO sai, mesmo com prompt limpo", async () => {
    const { doFetch, fetchCalls, scanPayloads } = setupInjected(
      modelPolicyVerdict,
      "claude.ai",
    );
    await expect(
      doFetch("https://claude.ai/api/o/chat_conversations/c/completion", {
        method: "POST",
        body: JSON.stringify({
          prompt: "qual é a capital da França?",
          model: "claude-fable-5",
        }),
      }),
    ).rejects.toThrow(/bloqueado/i);
    expect(fetchCalls).toHaveLength(0);
    expect(scanPayloads[0]?.context?.model).toBe("claude-fable-5");
  });

  it("claude.ai: modelo permitido passa normalmente", async () => {
    const { doFetch, fetchCalls } = setupInjected(
      modelPolicyVerdict,
      "claude.ai",
    );
    await doFetch("https://claude.ai/api/o/chat_conversations/c/completion", {
      method: "POST",
      body: JSON.stringify({
        prompt: "qual é a capital da França?",
        model: "claude-sonnet-5",
      }),
    });
    expect(fetchCalls).toHaveLength(1);
  });

  it("claude.ai: prompt vazio + modelo bloqueado ainda bloqueia (não cai no fail-open de !text)", async () => {
    const { doFetch, fetchCalls, scanPayloads } = setupInjected(
      modelPolicyVerdict,
      "claude.ai",
    );
    await expect(
      doFetch("https://claude.ai/api/o/chat_conversations/c/completion", {
        method: "POST",
        body: JSON.stringify({ model: "claude-fable-5" }),
      }),
    ).rejects.toThrow(/bloqueado/i);
    expect(fetchCalls).toHaveLength(0);
    expect(scanPayloads).toHaveLength(1);
  });

  it("claude.ai: prompt vazio SEM modelo mantém o fail-open (drift, não trava o site)", async () => {
    const { doFetch, fetchCalls, scanPayloads } = setupInjected(
      modelPolicyVerdict,
      "claude.ai",
    );
    await doFetch("https://claude.ai/api/o/chat_conversations/c/completion", {
      method: "POST",
      body: JSON.stringify({ irrelevante: true }),
    });
    expect(fetchCalls).toHaveLength(1);
    expect(scanPayloads).toHaveLength(0);
  });

  it("chatgpt.com: modelo do corpo chega ao daemon em context.model", async () => {
    const { doFetch, scanPayloads } = setupInjected(
      modelPolicyVerdict,
      "chatgpt.com",
    );
    await doFetch("https://chatgpt.com/backend-api/conversation", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-5",
        messages: [{ content: { parts: ["olá"] } }],
      }),
    });
    expect(scanPayloads[0]?.context?.model).toBe("gpt-5");
  });
});
