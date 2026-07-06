// Camada de UI do content.js: paste/drop de arquivos não podem ser ENGOLIDOS.
// Bug real: o handler era block-first mas não tinha caminho de re-injeção no
// allow — colar imagem nunca funcionava (em site nenhum) e o "re-arraste para
// anexar" do drop caía no mesmo handler e era bloqueado para sempre.
// Roda o content.js real em vm com DOM mínimo e verifica:
//  - paste FLUI em hosts com enforcement de rede (claude.ai/gemini): o upload
//    real é interceptado pelo injected.js (anexo é fail-closed lá);
//  - nos demais hosts, paste/drop seguem block-first, mas o allow re-despacha
//    o evento sintético com os arquivos reais, e esse re-despacho não é
//    re-bloqueado pelo próprio guardian;
//  - block continua bloqueando (sem re-despacho com arquivos).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const contentSrc = readFileSync(
  join(__dirname, "../extension/content.js"),
  "utf8",
);

class FakeDataTransfer {
  files: unknown[] = [];
  items = { add: (f: unknown) => this.files.push(f) };
}

class FakeEvent {
  type: string;
  bubbles: boolean;
  cancelable: boolean;
  target: unknown = null;
  prevented = false;
  stopped = false;
  constructor(
    type: string,
    init: { bubbles?: boolean; cancelable?: boolean } & Record<string, unknown> = {},
  ) {
    this.type = type;
    this.bubbles = !!init.bubbles;
    this.cancelable = !!init.cancelable;
  }
  preventDefault() {
    this.prevented = true;
  }
  stopImmediatePropagation() {
    this.stopped = true;
  }
}

class FakeDragEvent extends FakeEvent {
  dataTransfer: { files: unknown[] } | null;
  constructor(
    type: string,
    init: { dataTransfer?: { files: unknown[] } } = {},
  ) {
    super(type, init);
    this.dataTransfer = init.dataTransfer ?? null;
  }
}

class FakeClipboardEvent extends FakeEvent {
  clipboardData: { files: unknown[] } | null;
  constructor(
    type: string,
    init: { clipboardData?: { files: unknown[] } } = {},
  ) {
    super(type, init);
    this.clipboardData = init.clipboardData ?? null;
  }
}

// Elemento DOM mínimo: registra eventos despachados e aceita o que o overlay
// do content.js precisa (innerHTML, querySelector, classList...).
type El = {
  dispatched: Array<FakeDragEvent & FakeClipboardEvent>;
  [k: string]: unknown;
};
function makeEl(): El {
  const el: El = {
    dispatched: [],
    innerHTML: "",
    dataset: {},
    classList: { add() {}, remove() {}, contains: () => false },
    appendChild() {},
    addEventListener() {},
    focus() {},
    querySelector: () => makeEl(),
    dispatchEvent(evt: unknown) {
      el.dispatched.push(evt as FakeDragEvent & FakeClipboardEvent);
      return true;
    },
  };
  return el;
}

type Verdict = (payload: unknown) => unknown;

// Monta o ambiente de página, roda o content.js real e devolve os listeners
// de documento + o registro de scans enviados ao background.
function setupContent(hostname: string, verdict: Verdict) {
  const docListeners = new Map<string, (e: unknown) => void>();
  const scans: Array<{ payload?: unknown }> = [];
  const context: Record<string, unknown> = {
    chrome: {
      runtime: {
        sendMessage: (msg: { payload?: unknown }) => {
          scans.push(msg);
          return Promise.resolve(verdict(msg.payload ?? {}));
        },
      },
    },
    window: { addEventListener() {}, postMessage() {} },
    document: {
      documentElement: { dataset: {} },
      body: makeEl(),
      title: "Chat",
      addEventListener: (t: string, fn: (e: unknown) => void) =>
        docListeners.set(t, fn),
      createElement: () => makeEl(),
    },
    location: { hostname, href: `https://${hostname}/` },
    crypto: { getRandomValues: (a: Uint8Array) => a },
    console,
    setTimeout,
    clearTimeout,
    queueMicrotask,
    DataTransfer: FakeDataTransfer,
    DragEvent: FakeDragEvent,
    ClipboardEvent: FakeClipboardEvent,
  };
  vm.createContext(context);
  vm.runInContext(contentSrc, context);
  return { docListeners, scans };
}

async function flush() {
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
}

const allowVerdict: Verdict = () => ({ action: "allow", findings: [] });
const blockVerdict: Verdict = () => ({
  action: "block",
  reason: "dado sensível detectado",
  findings: [],
});

// Imagem colada/arrastada: binário, escaneado só pelo nome (quase sempre allow).
const img = { name: "foto.png", size: 1024 };
// Arquivo de texto: o scan pode reprovar pelo CONTEÚDO → fica retido até o veredito.
const txt = { name: "notas.txt", size: 64 };

describe("content.js — paste de arquivos/imagens", () => {
  for (const host of ["claude.ai", "gemini.google.com"]) {
    it(`deixa o paste FLUIR no ${host} (enforcement fica na rede)`, async () => {
      const { docListeners, scans } = setupContent(host, allowVerdict);
      const evt = new FakeClipboardEvent("paste", {
        clipboardData: { files: [img] },
      });
      docListeners.get("paste")?.(evt);
      await flush();
      // Não bloqueia nem escaneia na UI: o injected.js intercepta o upload real.
      expect(evt.prevented).toBe(false);
      expect(scans.length).toBe(0);
    });
  }

  it("deixa o paste de IMAGEM fluir mesmo sem enforcement de rede (scan seria só por nome)", async () => {
    const { docListeners, scans } = setupContent("chatgpt.com", allowVerdict);
    const evt = new FakeClipboardEvent("paste", {
      clipboardData: { files: [img] },
    });
    docListeners.get("paste")?.(evt);
    await flush();
    expect(evt.prevented).toBe(false);
    expect(scans.length).toBe(0);
  });

  it("re-despacha o paste de arquivo de TEXTO liberado pelo scan em host sem enforcement de rede", async () => {
    const { docListeners } = setupContent("chatgpt.com", allowVerdict);
    const target = makeEl();
    const evt = new FakeClipboardEvent("paste", {
      clipboardData: { files: [txt] },
    });
    evt.target = target;
    docListeners.get("paste")?.(evt);
    // Block-first: o evento original é sempre retido até o veredito.
    expect(evt.prevented).toBe(true);
    await flush();
    const re = target.dispatched.find((d) => d.type === "paste");
    expect(re).toBeDefined();
    expect(re?.clipboardData?.files).toEqual([txt]);
    // O re-despacho sintético não pode ser re-bloqueado pelo próprio guardian.
    docListeners.get("paste")?.(re);
    expect(re?.prevented).toBe(false);
  });

  it("mantém o bloqueio de paste quando o scan detecta segredo", async () => {
    const { docListeners } = setupContent("chatgpt.com", blockVerdict);
    const target = makeEl();
    const evt = new FakeClipboardEvent("paste", {
      clipboardData: { files: [{ name: "credenciais.txt", size: 64 }] },
    });
    evt.target = target;
    docListeners.get("paste")?.(evt);
    expect(evt.prevented).toBe(true);
    await flush();
    expect(target.dispatched.find((d) => d.type === "paste")).toBeUndefined();
  });
});

describe("content.js — drop de arquivos", () => {
  it("gemini: drop de IMAGEM flui direto (scan seria só por nome; sintético não anexa lá)", async () => {
    const { docListeners, scans } = setupContent(
      "gemini.google.com",
      allowVerdict,
    );
    const evt = new FakeDragEvent("drop", { dataTransfer: { files: [img] } });
    docListeners.get("drop")?.(evt);
    await flush();
    expect(evt.prevented).toBe(false);
    expect(scans.length).toBe(0);
  });

  it("gemini: drop de arquivo com NOME sensível (.pem) é retido mesmo sendo binário", async () => {
    const { docListeners } = setupContent("gemini.google.com", blockVerdict);
    const evt = new FakeDragEvent("drop", {
      dataTransfer: { files: [{ name: "server.pem", size: 2048 }] },
    });
    docListeners.get("drop")?.(evt);
    expect(evt.prevented).toBe(true);
  });

  it("gemini: re-despacha o drop de TEXTO liberado pelo scan (antes: re-arraste caía em loop de bloqueio)", async () => {
    const { docListeners } = setupContent("gemini.google.com", allowVerdict);
    const target = makeEl();
    const evt = new FakeDragEvent("drop", { dataTransfer: { files: [txt] } });
    evt.target = target;
    docListeners.get("drop")?.(evt);
    expect(evt.prevented).toBe(true);
    await flush();
    // resetDropUI despacha drops VAZIOS (some com o overlay do site); o
    // re-despacho liberado é o único drop com arquivos.
    const withFiles = target.dispatched.filter(
      (d) => d.type === "drop" && d.dataTransfer && d.dataTransfer.files.length,
    );
    expect(withFiles.length).toBe(1);
    const re = withFiles[0];
    expect(re?.dataTransfer?.files).toEqual([txt]);
    // E não é re-bloqueado ao cair de novo no handler do guardian.
    docListeners.get("drop")?.(re);
    expect(re?.prevented).toBe(false);
  });

  it("gemini: segue bloqueando drop com segredo (nenhum drop com arquivos chega ao site)", async () => {
    const { docListeners } = setupContent("gemini.google.com", blockVerdict);
    const target = makeEl();
    const evt = new FakeDragEvent("drop", {
      dataTransfer: { files: [{ name: "credenciais.txt", size: 64 }] },
    });
    evt.target = target;
    docListeners.get("drop")?.(evt);
    expect(evt.prevented).toBe(true);
    await flush();
    const withFiles = target.dispatched.filter(
      (d) => d.type === "drop" && d.dataTransfer && d.dataTransfer.files.length,
    );
    expect(withFiles.length).toBe(0);
  });

  it("claude.ai: drop continua fluindo (enforcement na rede)", async () => {
    const { docListeners, scans } = setupContent("claude.ai", allowVerdict);
    const evt = new FakeDragEvent("drop", { dataTransfer: { files: [img] } });
    docListeners.get("drop")?.(evt);
    await flush();
    expect(evt.prevented).toBe(false);
    expect(scans.length).toBe(0);
  });
});
