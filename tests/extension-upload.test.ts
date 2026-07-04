// Integração da camada de enforcement de anexos do injected.js.
// Node 22 tem FormData/File/Blob globais, então rodamos o injected.js real
// dentro de um vm com um bridge de scan simulado (o papel do content.js +
// background + daemon) e verificamos que um anexo com segredo é BLOQUEADO
// antes de qualquer byte sair, e que um anexo limpo passa.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const injectedSrc = readFileSync(
  join(__dirname, "../extension/injected.js"),
  "utf8",
);

type Verdict = (payload: {
  text?: string;
  files?: Array<{ name: string; content?: string }>;
}) => unknown;

// Monta o ambiente de página, roda o injected.js, e devolve o window (com o
// fetch já embrulhado) + o registro de chamadas ao fetch original.
function setupInjected(verdict: Verdict) {
  const messageListeners: Array<(e: { data: unknown }) => void> = [];
  const fetchCalls: Array<{ input: unknown; init: unknown }> = [];

  const win: Record<string, unknown> = {
    addEventListener: (type: string, fn: (e: { data: unknown }) => void) => {
      if (type === "message") messageListeners.push(fn);
    },
    removeEventListener: () => {},
    postMessage: (msg: {
      __guardian?: string;
      id?: string;
      nonce?: string;
      payload?: Parameters<Verdict>[0];
    }) => {
      // Simula o content.js: responde a um scan-request com o veredito.
      if (msg && msg.__guardian === "scan-request") {
        const result = verdict(msg.payload ?? {});
        queueMicrotask(() => {
          for (const fn of messageListeners) {
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
      title: "Claude",
    },
    location: { hostname: "claude.ai", href: "https://claude.ai/chat/x" },
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
  // fetch já embrulhado pelo injected.js.
  const doFetch = win["fetch"] as (
    input: string,
    init: { method: string; body: unknown },
  ) => Promise<unknown>;
  return { doFetch, fetchCalls };
}

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

// Veredito que bloqueia se o texto OU algum arquivo escaneado contém uma AWS key.
const secretAwareVerdict: Verdict = (payload) => {
  const hay = [
    payload.text ?? "",
    ...(payload.files ?? []).map((f) => f.content ?? ""),
  ].join("\n");
  return hay.includes("AKIA")
    ? { action: "block", reason: "secret", findings: [] }
    : { action: "allow", findings: [] };
};

describe("injected.js — enforcement de anexo (upload)", () => {
  it("bloqueia upload de arquivo com segredo (FormData) — nada sai", async () => {
    const { doFetch, fetchCalls } = setupInjected(secretAwareVerdict);
    const fd = new FormData();
    fd.append("file", new File([`key=${AWS_KEY}`], "creds.env", { type: "text/plain" }));

    await expect(
      doFetch("https://claude.ai/api/org/upload", { method: "POST", body: fd }),
    ).rejects.toThrow(/anexo bloqueado/i);
    expect(fetchCalls).toHaveLength(0);
  });

  it("libera upload de arquivo limpo", async () => {
    const { doFetch, fetchCalls } = setupInjected(secretAwareVerdict);
    const fd = new FormData();
    fd.append("file", new File(["apenas notas"], "notes.txt", { type: "text/plain" }));

    await doFetch("https://claude.ai/api/org/upload", { method: "POST", body: fd });
    expect(fetchCalls).toHaveLength(1);
  });

  it("bloqueia upload de File cru (sem FormData)", async () => {
    const { doFetch, fetchCalls } = setupInjected(secretAwareVerdict);
    const file = new File([`aws=${AWS_KEY}`], "secrets.txt", { type: "text/plain" });

    await expect(
      doFetch("https://claude.ai/upload", { method: "PUT", body: file }),
    ).rejects.toThrow(/anexo bloqueado/i);
    expect(fetchCalls).toHaveLength(0);
  });

  it("não interfere em POST sem arquivos (telemetria)", async () => {
    const { doFetch, fetchCalls } = setupInjected(secretAwareVerdict);
    await doFetch("https://claude.ai/api/telemetry", { method: "POST", body: "ping" });
    expect(fetchCalls).toHaveLength(1);
  });
});

// Regressão do fluxo REAL do claude.ai (capturado por HAR): arquivos de texto
// pequenos NÃO sobem por multipart — o conteúdo vai inline no /completion, em
// attachments[].extracted_content, com prompt vazio. O extractText precisa ler
// o anexo, senão o prompt "" caía no fail-open e o anexo era enviado sem scan.
describe("injected.js — anexo inline no /completion do claude.ai", () => {
  const COMPLETION_URL =
    "https://claude.ai/api/organizations/org-x/chat_conversations/conv-y/completion";

  function completionBody(extracted: string) {
    return JSON.stringify({
      prompt: "",
      model: "claude-haiku-4-5-20251001",
      attachments: [
        {
          file_name: "creds.txt",
          file_type: "text/plain",
          file_size: extracted.length,
          extracted_content: extracted,
          origin: "user_upload",
          kind: "file",
        },
      ],
      files: [],
    });
  }

  it("bloqueia quando o conteúdo do anexo tem segredo (prompt vazio)", async () => {
    const { doFetch, fetchCalls } = setupInjected(secretAwareVerdict);
    await expect(
      doFetch(COMPLETION_URL, {
        method: "POST",
        body: completionBody(`AWS_SECRET=${AWS_KEY}`),
      }),
    ).rejects.toThrow(/bloqueado/i);
    expect(fetchCalls).toHaveLength(0);
  });

  it("deixa passar anexo inline limpo", async () => {
    const { doFetch, fetchCalls } = setupInjected(secretAwareVerdict);
    await doFetch(COMPLETION_URL, {
      method: "POST",
      body: completionBody("apenas uma nota de reunião"),
    });
    expect(fetchCalls).toHaveLength(1);
  });
});
