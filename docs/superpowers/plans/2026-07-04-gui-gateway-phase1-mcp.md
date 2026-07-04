# Guardian GUI Gateway — Fase 1 (Proxy MCP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Interceptar e bloquear tráfego DLP nos MCP servers do Claude Desktop e do Kiro IDE, reusando o mesmo engine/policy/audit dos hooks, sem depender de CA nem do daemon.

**Architecture:** Um shim stdio (`mcp-proxy.ts`) é injetado na config MCP de cada cliente pelo `init`. O cliente passa a spawnar o shim no lugar do server real; o shim faz spawn do server real e senta no meio do stream JSON-RPC (newline-delimited), escaneando `tools/call` (argumentos = egress) e as respostas (resultados = ingress) **in-process** via um novo `scanMcp` que espelha o `scanWeb`. Bloqueio = erro JSON-RPC devolvido ao cliente; a request nunca chega ao server real. Incidentes vão pro DB local + outbox central, igual aos hooks.

**Tech Stack:** Node >= 22.6 (`--experimental-strip-types`, sem build), better-sqlite3, vitest. MCP stdio transport = JSON-RPC 2.0 em linhas delimitadas por `\n`.

---

## File Structure

- `src/lib/mcp-scan.ts` — **novo**. `scanMcp(db, config, req)`: pipeline de scan de uma peça de texto MCP (args OU result) reusando engine/policy/approval/audit/central. Espelha `src/lib/web-scan.ts`. Tools virtuais `McpToolCall`/`McpToolResult`.
- `src/proxy/mcp-proxy.ts` — **novo**. (a) funções puras `handleClientMessage`/`handleServerMessage` que decidem o que encaminhar/bloquear dado um `ScanFn`; (b) `main()` que faz spawn do server real e liga os streams. Executável via `node --experimental-strip-types`.
- `src/lib/mcp-install.ts` — **novo**. `wrapMcpServers(configObj, proxyInvocation)` (pura) + localizadores dos arquivos de config (Claude Desktop / Kiro IDE) + `installMcpProxy()`/`uninstallMcpProxy()`. Idempotente e reversível (backup).
- `src/hosts/index.ts` — **modificar**. Adiciona `claude-desktop` e `kiro-ide` ao tipo `Host` e ao `detectHost`.
- `src/cli/commands/init.ts` — **modificar**. Novo passo: chamar `installMcpProxy()` (flag `--mcp` / detecção automática de configs presentes).
- Testes: `tests/mcp-scan.test.ts`, `tests/mcp-proxy.test.ts`, `tests/mcp-install.test.ts`, e adições em `tests/hosts.test.ts`.
- `docs/GUI-GATEWAY.md` — **novo**. Doc da superfície + rollback manual.

**Preliminar (spike, sem código):** ver Task 0.

---

## Task 0: Spike — Kiro IDE aceita o contrato de hook do kiro-cli?

**Files:** nenhum (investigação). Registrar resultado em `docs/GUI-GATEWAY.md` (criado na Task 8).

- [ ] **Step 1: Investigar**

Rodar o Kiro IDE numa máquina de teste e verificar:
1. O Kiro IDE lê o mesmo `settings.json`/hooks do kiro-cli? (checar `~/.kiro/` e a doc do produto).
2. Ele respeita `PreToolUse` com `exit 2` bloqueando, como o kiro-cli?

- [ ] **Step 2: Registrar decisão**

Anotar em `docs/GUI-GATEWAY.md` um bloco "Kiro IDE hook-compat: SIM/NÃO":
- **SIM** → o prompt/arquivo do Kiro IDE já fica coberto pelo `init` de hooks existente; o proxy MCP desta fase vira defesa em profundidade.
- **NÃO** → o proxy MCP desta fase é a única cobertura do Kiro IDE (arquivos/tools via MCP), como o spec já assume.

Este spike **não bloqueia** as Tasks 1–8 (o proxy MCP é construído de qualquer forma). Serve só pra saber se ganhamos cobertura de prompt de graça no Kiro IDE.

---

## Task 1: `scanMcp` — core de scan de uma peça MCP

**Files:**
- Create: `src/lib/mcp-scan.ts`
- Test: `tests/mcp-scan.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// tests/mcp-scan.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { getDb } from "../src/db/client.ts";
import { MCP_CALL_TOOL, MCP_RESULT_TOOL, scanMcp } from "../src/lib/mcp-scan.ts";
import type { Config } from "../src/types/index.ts";

let tmpDir: string;
let dbPath: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-mcp-scan-"));
  dbPath = join(tmpDir, "test.db");
});
afterAll(() => rmSync(tmpDir, { recursive: true, force: true }));
function cfg(o: Partial<Config> = {}): Config {
  return { ...DEFAULT_CONFIG, dbPath, ...o };
}
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

describe("scanMcp", () => {
  it("allows clean tool-call args", () => {
    const db = getDb(dbPath);
    const r = scanMcp(db, cfg(), {
      tool: MCP_CALL_TOOL,
      serverName: "fs",
      toolName: "read_file",
      text: JSON.stringify({ path: "/etc/hosts" }),
    });
    expect(r.action).toBe("allow");
    expect(r.findings).toHaveLength(0);
  });

  it("blocks a secret in tool-call args", () => {
    const db = getDb(dbPath);
    const r = scanMcp(db, cfg(), {
      tool: MCP_CALL_TOOL,
      serverName: "http",
      toolName: "post",
      text: JSON.stringify({ body: `key=${AWS_KEY}` }),
    });
    expect(r.action).toBe("block");
    expect(r.findings.some((f) => f.dataType === "aws-key")).toBe(true);
  });

  it("blocks a secret in tool results (ingress)", () => {
    const db = getDb(dbPath);
    const r = scanMcp(db, cfg(), {
      tool: MCP_RESULT_TOOL,
      serverName: "fs",
      toolName: "read_file",
      text: `content: ${AWS_KEY}`,
    });
    expect(r.action).toBe("block");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/mcp-scan.test.ts`
Expected: FAIL — `Cannot find module '../src/lib/mcp-scan.ts'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/lib/mcp-scan.ts
import type BetterSqlite3 from "better-sqlite3";
import { loadCustomDetectors } from "../engine/detectors/custom.ts";
import { gitleaksDetector } from "../engine/detectors/gitleaks.ts";
import type { Detector } from "../engine/detectors/types.ts";
import { scanSync } from "../engine/index.ts";
import type {
  Config,
  DataType,
  DetectorFinding,
  PolicyAction,
} from "../types/index.ts";
import { buildScope, createApproval, findActiveApproval } from "./approval.ts";
import { appendAuditEntry } from "./audit.ts";
import { dashboardBaseUrl, reportToCentral } from "./central.ts";
import { recordIncident } from "./incident.ts";
import { evaluatePolicy, findApprovalTtl } from "./policy.ts";

// Tools virtuais para casar policy `tools:` separadamente dos hooks/extensão.
export const MCP_CALL_TOOL = "McpToolCall"; // egress: argumentos que o modelo envia a um tool
export const MCP_RESULT_TOOL = "McpToolResult"; // ingress: dado que um tool devolve

export interface McpScanRequest {
  tool: typeof MCP_CALL_TOOL | typeof MCP_RESULT_TOOL;
  serverName: string;
  toolName: string;
  text: string;
}

export interface McpScanFinding {
  detectorId: string;
  label: string;
  dataType: string;
  severity: string;
  snippet: string;
}

export interface McpScanResponse {
  action: PolicyAction;
  findings: McpScanFinding[];
  redactedText?: string;
  approvalUrl?: string;
  reason: string;
}

function toFinding(f: DetectorFinding): McpScanFinding {
  return {
    detectorId: f.detectorId,
    label: f.label,
    dataType: f.dataType,
    severity: f.severity,
    snippet: f.snippet,
  };
}

function redactText(text: string, findings: DetectorFinding[]): string {
  let out = text;
  for (const f of findings) {
    if (!f.rawValue) continue;
    out = out.split(f.rawValue).join(`[REDACTED:${f.detectorId}]`);
  }
  return out;
}

function failClosed(tool: string): McpScanResponse {
  return {
    action: "block",
    findings: [
      {
        detectorId: "engine-timeout",
        label: `Scan timeout (${tool})`,
        dataType: "generic-secret",
        severity: "critical",
        snippet: "(timeout)",
      },
    ],
    reason: "Timeout ao escanear — bloqueado por segurança (fail-closed).",
  };
}

/**
 * Scan de uma peça MCP (argumentos de tools/call OU conteúdo de resultado).
 * Reusa engine/policy/approval/audit dos hooks. Fail-closed no timeout.
 */
export function scanMcp(
  db: BetterSqlite3.Database,
  config: Config,
  req: McpScanRequest,
): McpScanResponse {
  const sessionId = `mcp:${req.serverName}/${req.toolName}`;
  const extraDetectors: Detector[] = [
    gitleaksDetector,
    ...loadCustomDetectors(db),
  ];

  const res = scanSync(req.text, {
    timeoutMs: config.engineTimeoutMs,
    allowlist: config.allowlist,
    extraDetectors,
  });
  if (res.timedOut) return failClosed(req.tool);

  const findings = res.findings;
  const action = evaluatePolicy(findings, req.tool, config.policies);

  if (action === "allow" || findings.length === 0) {
    return { action: "allow", findings: [], reason: "Nenhum dado sensível." };
  }

  if (action === "redact") {
    const incident = recordIncident(db, req.tool, sessionId, findings, "redact");
    appendAuditEntry(db, "redact", {
      incidentId: incident.id,
      tool: req.tool,
      dataTypes: incident.dataTypes,
    });
    reportToCentral(config, incident, findings, null, "redact");
    return {
      action: "redact",
      findings: findings.map(toFinding),
      redactedText: redactText(req.text, findings),
      reason: "Dado sensível redigido no tráfego MCP.",
    };
  }

  const dataTypes = [...new Set(findings.map((f) => f.dataType))] as DataType[];
  const scope = buildScope(req.tool, dataTypes);
  if (findActiveApproval(db, scope)) {
    return { action: "allow", findings: [], reason: "Liberação ativa para o escopo." };
  }

  if (action === "require-approval") {
    const incident = recordIncident(
      db,
      req.tool,
      sessionId,
      findings,
      "require-approval",
    );
    const approval = createApproval(
      db,
      incident.id,
      scope,
      `MCP: ${sessionId}`,
      findApprovalTtl(findings, req.tool, config.policies),
    );
    appendAuditEntry(db, "approval-requested", {
      approvalId: approval.id,
      incidentId: incident.id,
      scope,
      requestedBy: "mcp-proxy",
    });
    reportToCentral(config, incident, findings, approval, "approval-requested");
    return {
      action: "require-approval",
      findings: findings.map(toFinding),
      approvalUrl: `${dashboardBaseUrl(config)}/request-approval/${incident.id}`,
      reason: "Aprovação necessária para o tráfego MCP.",
    };
  }

  const incident = recordIncident(db, req.tool, sessionId, findings, "block");
  appendAuditEntry(db, "block", {
    incidentId: incident.id,
    tool: req.tool,
    dataTypes: incident.dataTypes,
    severities: incident.severities,
  });
  reportToCentral(config, incident, findings, null, "block");
  return {
    action: "block",
    findings: findings.map(toFinding),
    approvalUrl: `${dashboardBaseUrl(config)}/request-approval/${incident.id}`,
    reason: "Tráfego MCP bloqueado: dado sensível detectado.",
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/mcp-scan.test.ts`
Expected: PASS (3 passing).

- [ ] **Step 5: Commit**

```bash
git add src/lib/mcp-scan.ts tests/mcp-scan.test.ts
git commit -m "feat(mcp): scanMcp reusa engine/policy/audit para tráfego MCP"
```

---

## Task 2: Handlers puros de mensagens JSON-RPC

**Files:**
- Create: `src/proxy/mcp-proxy.ts` (só a parte pura nesta task)
- Test: `tests/mcp-proxy.test.ts`

`ScanFn` é injetado para testar sem DB. `handleClientMessage` decide o que vai pro server real e o que volta direto ao cliente (bloqueio). `handleServerMessage` escaneia resultados de `tools/call` pendentes.

- [ ] **Step 1: Write the failing test**

```ts
// tests/mcp-proxy.test.ts
import { describe, expect, it } from "vitest";
import {
  handleClientMessage,
  handleServerMessage,
  type ScanFn,
} from "../src/proxy/mcp-proxy.ts";

const allow: ScanFn = () => ({ action: "allow", reason: "" });
const block: ScanFn = () => ({ action: "block", reason: "blocked" });
const redact: ScanFn = () => ({
  action: "redact",
  reason: "",
  redactedText: JSON.stringify({ body: "[REDACTED:aws-key]" }),
});

describe("handleClientMessage", () => {
  it("forwards non tools/call messages untouched", () => {
    const pending = new Map<string | number, string>();
    const msg = { jsonrpc: "2.0", id: 1, method: "initialize", params: {} };
    const out = handleClientMessage(msg, allow, pending);
    expect(out.toChild).toEqual(msg);
    expect(out.toClient).toBeUndefined();
  });

  it("forwards a clean tools/call and registers it as pending", () => {
    const pending = new Map<string | number, string>();
    const msg = {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "/x" } },
    };
    const out = handleClientMessage(msg, allow, pending);
    expect(out.toChild).toEqual(msg);
    expect(pending.get(7)).toBe("read_file");
  });

  it("blocks a dirty tools/call: replies error to client, nothing to child", () => {
    const pending = new Map<string | number, string>();
    const msg = {
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: { name: "post", arguments: { body: "secret" } },
    };
    const out = handleClientMessage(msg, block, pending);
    expect(out.toChild).toBeUndefined();
    expect(out.toClient?.error?.code).toBe(-32001);
    expect(out.toClient?.id).toBe(8);
    expect(pending.has(8)).toBe(false);
  });

  it("redacts a tools/call: rewrites arguments before forwarding", () => {
    const pending = new Map<string | number, string>();
    const msg = {
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: { name: "post", arguments: { body: "k=AKIA..." } },
    };
    const out = handleClientMessage(msg, redact, pending);
    expect(out.toChild?.params.arguments).toEqual({ body: "[REDACTED:aws-key]" });
    expect(pending.get(9)).toBe("post");
  });
});

describe("handleServerMessage", () => {
  it("passes through a response with no matching pending call", () => {
    const pending = new Map<string | number, string>();
    const msg = { jsonrpc: "2.0", id: 99, result: { content: [] } };
    const out = handleServerMessage(msg, allow, pending);
    expect(out.toClient).toEqual(msg);
  });

  it("blocks a dirty result: replaces it with an error and clears pending", () => {
    const pending = new Map<string | number, string>([[5, "read_file"]]);
    const msg = {
      jsonrpc: "2.0",
      id: 5,
      result: { content: [{ type: "text", text: "AKIA..." }] },
    };
    const out = handleServerMessage(msg, block, pending);
    expect(out.toClient.error?.code).toBe(-32001);
    expect(out.toClient.result).toBeUndefined();
    expect(pending.has(5)).toBe(false);
  });

  it("clears pending on a clean result", () => {
    const pending = new Map<string | number, string>([[6, "read_file"]]);
    const msg = {
      jsonrpc: "2.0",
      id: 6,
      result: { content: [{ type: "text", text: "hello" }] },
    };
    handleServerMessage(msg, allow, pending);
    expect(pending.has(6)).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/mcp-proxy.test.ts`
Expected: FAIL — module/exports não existem.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/proxy/mcp-proxy.ts
export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: any;
  result?: any;
  error?: { code: number; message: string; data?: unknown };
}

export interface ScanDecision {
  action: "allow" | "block" | "redact" | "require-approval";
  reason: string;
  redactedText?: string;
}
export type ScanFn = (
  tool: "McpToolCall" | "McpToolResult",
  toolName: string,
  text: string,
) => ScanDecision;

const BLOCK_CODE = -32001; // JSON-RPC server error range (guardian block)

function blockError(id: JsonRpcMessage["id"], reason: string): JsonRpcMessage {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code: BLOCK_CODE, message: `claude-guardian: ${reason}` },
  };
}

/** Texto legível de um resultado MCP (concatena as partes `text`). */
function resultText(result: unknown): string {
  const content = (result as { content?: unknown })?.content;
  if (!Array.isArray(content)) return JSON.stringify(result ?? "");
  return content
    .map((c) =>
      c && typeof c === "object" && typeof (c as any).text === "string"
        ? (c as any).text
        : JSON.stringify(c),
    )
    .join("\n");
}

export function handleClientMessage(
  msg: JsonRpcMessage,
  scan: ScanFn,
  pending: Map<string | number, string>,
): { toChild?: JsonRpcMessage; toClient?: JsonRpcMessage } {
  if (msg.method !== "tools/call") return { toChild: msg };

  const name = String(msg.params?.name ?? "unknown");
  const args = msg.params?.arguments ?? {};
  const decision = scan("McpToolCall", name, JSON.stringify(args));

  if (decision.action === "block" || decision.action === "require-approval") {
    return { toClient: blockError(msg.id, decision.reason) };
  }
  if (decision.action === "redact" && decision.redactedText) {
    let redacted: unknown = args;
    try {
      redacted = JSON.parse(decision.redactedText);
    } catch {
      // se a redação quebrar o JSON, é mais seguro bloquear
      return { toClient: blockError(msg.id, "redação inválida") };
    }
    const rewritten: JsonRpcMessage = {
      ...msg,
      params: { ...msg.params, arguments: redacted },
    };
    if (msg.id != null) pending.set(msg.id, name);
    return { toChild: rewritten };
  }
  if (msg.id != null) pending.set(msg.id, name);
  return { toChild: msg };
}

export function handleServerMessage(
  msg: JsonRpcMessage,
  scan: ScanFn,
  pending: Map<string | number, string>,
): { toClient: JsonRpcMessage } {
  if (msg.id == null || !pending.has(msg.id) || msg.result === undefined) {
    return { toClient: msg };
  }
  const name = pending.get(msg.id) as string;
  pending.delete(msg.id);
  const decision = scan("McpToolResult", name, resultText(msg.result));
  if (decision.action === "block" || decision.action === "require-approval") {
    return { toClient: blockError(msg.id, decision.reason) };
  }
  return { toClient: msg };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/mcp-proxy.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/proxy/mcp-proxy.ts tests/mcp-proxy.test.ts
git commit -m "feat(mcp): handlers puros de JSON-RPC (block/redact de tools/call e result)"
```

---

## Task 3: Wiring do shim stdio (spawn + streams)

**Files:**
- Modify: `src/proxy/mcp-proxy.ts` (adiciona `main()` e um `parseTarget`)
- Test: `tests/mcp-proxy.test.ts` (adiciona bloco de integração com server fake)

O shim lê o comando real de `GUARDIAN_MCP_TARGET` (JSON `{command,args,env}`) OU dos argv após `--`. Faz spawn, e liga os streams via readline (linhas JSON). O scan real é criado dentro de `main()` abrindo o DB (igual aos hooks); nos testes injetamos um `ScanFn` fake e um server fake.

- [ ] **Step 1: Write the failing test (integração)**

```ts
// adicionar em tests/mcp-proxy.test.ts
import { PassThrough } from "node:stream";
import { runProxyStreams } from "../src/proxy/mcp-proxy.ts";

describe("runProxyStreams (integração de streams)", () => {
  it("bloqueia tools/call sujo antes de chegar ao server", async () => {
    const clientIn = new PassThrough(); // cliente -> proxy
    const clientOut = new PassThrough(); // proxy -> cliente
    const childIn = new PassThrough(); // proxy -> server real
    const childOut = new PassThrough(); // server real -> proxy

    const toChild: string[] = [];
    childIn.on("data", (b) => toChild.push(b.toString()));
    const toClient: string[] = [];
    clientOut.on("data", (b) => toClient.push(b.toString()));

    const scan: ScanFn = () => ({ action: "block", reason: "secret" });
    runProxyStreams({ clientIn, clientOut, childIn, childOut, scan });

    clientIn.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "post", arguments: { body: "AKIA..." } },
      }) + "\n",
    );
    await new Promise((r) => setTimeout(r, 20));

    expect(toChild.join("")).toBe(""); // nada chegou ao server
    expect(toClient.join("")).toContain("-32001");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/mcp-proxy.test.ts`
Expected: FAIL — `runProxyStreams` não existe.

- [ ] **Step 3: Write minimal implementation**

```ts
// adicionar em src/proxy/mcp-proxy.ts
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";

export interface ProxyStreams {
  clientIn: Readable;
  clientOut: Writable;
  childIn: Writable;
  childOut: Readable;
  scan: ScanFn;
}

/** Liga os quatro streams aplicando os handlers linha a linha. */
export function runProxyStreams({
  clientIn,
  clientOut,
  childIn,
  childOut,
  scan,
}: ProxyStreams): void {
  const pending = new Map<string | number, string>();
  const write = (w: Writable, m: JsonRpcMessage) => w.write(JSON.stringify(m) + "\n");

  const fromClient = createInterface({ input: clientIn });
  fromClient.on("line", (line) => {
    if (!line.trim()) return;
    let msg: JsonRpcMessage;
    try {
      msg = JSON.parse(line);
    } catch {
      childIn.write(line + "\n"); // não-JSON: repassa cru
      return;
    }
    const out = handleClientMessage(msg, scan, pending);
    if (out.toChild) write(childIn, out.toChild);
    if (out.toClient) write(clientOut, out.toClient);
  });

  const fromChild = createInterface({ input: childOut });
  fromChild.on("line", (line) => {
    if (!line.trim()) return;
    let msg: JsonRpcMessage;
    try {
      msg = JSON.parse(line);
    } catch {
      clientOut.write(line + "\n");
      return;
    }
    write(clientOut, handleServerMessage(msg, scan, pending).toClient);
  });
}

interface Target {
  command: string;
  args: string[];
  env?: Record<string, string>;
}
export function parseTarget(argv: string[], env: NodeJS.ProcessEnv): Target {
  const raw = env["GUARDIAN_MCP_TARGET"];
  if (raw) return JSON.parse(raw) as Target;
  const sep = argv.indexOf("--");
  if (sep === -1 || sep === argv.length - 1) {
    throw new Error("mcp-proxy: alvo ausente (use -- <command> [args] ou GUARDIAN_MCP_TARGET)");
  }
  return { command: argv[sep + 1], args: argv.slice(sep + 2) };
}

async function main(): Promise<void> {
  const target = parseTarget(process.argv, process.env);
  // Scan real: abre DB + config uma vez, igual aos hooks (import dinâmico
  // para manter os handlers puros testáveis sem dependências pesadas).
  const [{ getDb }, { loadConfig }, { scanMcp }] = await Promise.all([
    import("../db/client.ts"),
    import("../config/loader.ts"),
    import("../lib/mcp-scan.ts"),
  ]);
  const config = loadConfig();
  const db = getDb(config.dbPath);
  const serverName = process.env["GUARDIAN_MCP_NAME"] ?? target.command;

  const scan: ScanFn = (tool, toolName, text) => {
    try {
      const r = scanMcp(db, config, { tool, serverName, toolName, text });
      return { action: r.action, reason: r.reason, redactedText: r.redactedText };
    } catch {
      return { action: "block", reason: "erro interno do guardian (fail-closed)" };
    }
  };

  const child = spawn(target.command, target.args, {
    env: { ...process.env, ...target.env },
    stdio: ["pipe", "pipe", "inherit"],
  });
  child.on("exit", (code) => process.exit(code ?? 0));

  runProxyStreams({
    clientIn: process.stdin,
    clientOut: process.stdout,
    childIn: child.stdin!,
    childOut: child.stdout!,
    scan,
  });
}

// Só executa main() quando rodado como entrypoint, não quando importado no teste.
if (process.argv[1] && process.argv[1].endsWith("mcp-proxy.ts")) {
  void main();
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/mcp-proxy.test.ts`
Expected: PASS (todos os blocos).

- [ ] **Step 5: Commit**

```bash
git add src/proxy/mcp-proxy.ts tests/mcp-proxy.test.ts
git commit -m "feat(mcp): shim stdio faz spawn do server real e escaneia in-process"
```

---

## Task 4: `wrapMcpServers` — reescrita idempotente da config

**Files:**
- Create: `src/lib/mcp-install.ts` (só a função pura nesta task)
- Test: `tests/mcp-install.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// tests/mcp-install.test.ts
import { describe, expect, it } from "vitest";
import { isWrapped, wrapMcpServers } from "../src/lib/mcp-install.ts";

const PROXY = "/repo/src/proxy/mcp-proxy.ts";

describe("wrapMcpServers", () => {
  it("wraps each server, preserving the original command as target", () => {
    const cfg = {
      mcpServers: {
        fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"] },
      },
    };
    const out = wrapMcpServers(cfg, PROXY);
    const fs = out.mcpServers.fs;
    expect(fs.command).toBe("node");
    expect(fs.args[0]).toBe("--experimental-strip-types");
    expect(fs.args[1]).toBe(PROXY);
    expect(fs.env.GUARDIAN_MCP_NAME).toBe("fs");
    const target = JSON.parse(fs.env.GUARDIAN_MCP_TARGET);
    expect(target).toEqual({
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
      env: {},
    });
  });

  it("is idempotent: wrapping twice is a no-op", () => {
    const cfg = { mcpServers: { fs: { command: "foo", args: [] } } };
    const once = wrapMcpServers(cfg, PROXY);
    const twice = wrapMcpServers(once, PROXY);
    expect(twice).toEqual(once);
    expect(isWrapped(twice.mcpServers.fs, PROXY)).toBe(true);
  });

  it("leaves a config without mcpServers untouched", () => {
    expect(wrapMcpServers({}, PROXY)).toEqual({});
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/mcp-install.test.ts`
Expected: FAIL — módulo inexistente.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/lib/mcp-install.ts
export interface McpServerEntry {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}
export interface McpConfig {
  mcpServers?: Record<string, McpServerEntry>;
  [k: string]: unknown;
}

export function isWrapped(entry: McpServerEntry, proxyPath: string): boolean {
  return (
    entry.command === "node" && (entry.args ?? []).includes(proxyPath)
  );
}

/** Envolve cada server para rotear pelo shim, preservando o original em env. */
export function wrapMcpServers<T extends McpConfig>(config: T, proxyPath: string): T {
  const servers = config.mcpServers;
  if (!servers) return config;

  const wrapped: Record<string, McpServerEntry> = {};
  for (const [name, entry] of Object.entries(servers)) {
    if (isWrapped(entry, proxyPath)) {
      wrapped[name] = entry; // idempotente
      continue;
    }
    wrapped[name] = {
      command: "node",
      args: ["--experimental-strip-types", proxyPath],
      env: {
        ...(entry.env ?? {}),
        GUARDIAN_MCP_NAME: name,
        GUARDIAN_MCP_TARGET: JSON.stringify({
          command: entry.command,
          args: entry.args ?? [],
          env: entry.env ?? {},
        }),
      },
    };
  }
  return { ...config, mcpServers: wrapped };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/mcp-install.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/mcp-install.ts tests/mcp-install.test.ts
git commit -m "feat(mcp): wrapMcpServers reescreve config MCP de forma idempotente"
```

---

## Task 5: Localizadores de config + install/uninstall com backup

**Files:**
- Modify: `src/lib/mcp-install.ts` (adiciona localizadores + install/uninstall)
- Test: `tests/mcp-install.test.ts` (adiciona bloco de install em tmpdir)

- [ ] **Step 1: Write the failing test**

```ts
// adicionar em tests/mcp-install.test.ts
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach } from "vitest";
import { installMcpProxyAt, uninstallMcpProxyAt } from "../src/lib/mcp-install.ts";

describe("installMcpProxyAt", () => {
  let dir: string;
  let file: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "guardian-mcp-install-"));
    file = join(dir, "claude_desktop_config.json");
    writeFileSync(file, JSON.stringify({ mcpServers: { fs: { command: "foo", args: [] } } }));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("wraps the file and writes a .bak backup", () => {
    installMcpProxyAt(file, PROXY);
    const out = JSON.parse(readFileSync(file, "utf8"));
    expect(out.mcpServers.fs.command).toBe("node");
    const bak = JSON.parse(readFileSync(file + ".guardian.bak", "utf8"));
    expect(bak.mcpServers.fs.command).toBe("foo");
  });

  it("uninstall restores the original from backup", () => {
    installMcpProxyAt(file, PROXY);
    uninstallMcpProxyAt(file);
    const out = JSON.parse(readFileSync(file, "utf8"));
    expect(out.mcpServers.fs.command).toBe("foo");
  });

  it("install on a missing file is a no-op (returns false)", () => {
    expect(installMcpProxyAt(join(dir, "nope.json"), PROXY)).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/mcp-install.test.ts`
Expected: FAIL — `installMcpProxyAt`/`uninstallMcpProxyAt` inexistentes.

- [ ] **Step 3: Write minimal implementation**

```ts
// adicionar em src/lib/mcp-install.ts
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";

const BAK = ".guardian.bak";

/** Reescreve um arquivo de config MCP; retorna false se ele não existir. */
export function installMcpProxyAt(file: string, proxyPath: string): boolean {
  if (!existsSync(file)) return false;
  const raw = readFileSync(file, "utf8");
  const config = JSON.parse(raw) as McpConfig;
  if (!config.mcpServers || Object.keys(config.mcpServers).length === 0) {
    return false;
  }
  if (!existsSync(file + BAK)) copyFileSync(file, file + BAK);
  const wrapped = wrapMcpServers(config, proxyPath);
  writeFileSync(file, JSON.stringify(wrapped, null, 2) + "\n", "utf8");
  return true;
}

/** Restaura a config original a partir do backup .guardian.bak. */
export function uninstallMcpProxyAt(file: string): boolean {
  if (!existsSync(file + BAK)) return false;
  copyFileSync(file + BAK, file);
  return true;
}

/** Caminhos padrão das configs MCP por SO (Claude Desktop + Kiro IDE). */
export function mcpConfigPaths(env: NodeJS.ProcessEnv = process.env): string[] {
  const home = homedir();
  const paths: string[] = [];
  const os = platform();
  if (os === "darwin") {
    paths.push(join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"));
  } else if (os === "win32") {
    const appData = env["APPDATA"] ?? join(home, "AppData", "Roaming");
    paths.push(join(appData, "Claude", "claude_desktop_config.json"));
  } else {
    paths.push(join(home, ".config", "Claude", "claude_desktop_config.json"));
  }
  // Kiro IDE (user-level); workspace-level é resolvido pelo cwd quando existir.
  paths.push(join(home, ".kiro", "settings", "mcp.json"));
  const ws = join(process.cwd(), ".kiro", "settings", "mcp.json");
  if (existsSync(ws)) paths.push(ws);
  return paths;
}

export function installMcpProxy(proxyPath: string): string[] {
  const done: string[] = [];
  for (const file of mcpConfigPaths()) {
    if (installMcpProxyAt(file, proxyPath)) done.push(file);
  }
  return done;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/mcp-install.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/mcp-install.ts tests/mcp-install.test.ts
git commit -m "feat(mcp): install/uninstall com backup + localizadores por SO"
```

---

## Task 6: Detecção de host — `claude-desktop` e `kiro-ide`

**Files:**
- Modify: `src/hosts/index.ts:8` (tipo `Host`) e `detectHost`
- Test: `tests/hosts.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// adicionar em tests/hosts.test.ts
import { detectHost } from "../src/hosts/index.ts";

describe("detectHost — superfícies GUI", () => {
  it("detecta claude-desktop via GUARDIAN_HOST explícito", () => {
    expect(detectHost({ GUARDIAN_HOST: "claude-desktop" })).toBe("claude-desktop");
  });
  it("detecta kiro-ide via GUARDIAN_HOST explícito", () => {
    expect(detectHost({ GUARDIAN_HOST: "kiro-ide" })).toBe("kiro-ide");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/hosts.test.ts`
Expected: FAIL — `detectHost` ainda não reconhece os novos valores (retorna `"claude"`).

- [ ] **Step 3: Write minimal implementation**

Em `src/hosts/index.ts`, trocar a linha 8:

```ts
export type Host = "claude" | "kiro" | "claude-desktop" | "kiro-ide";
```

E, dentro de `detectHost`, trocar o bloco do valor explícito:

```ts
export function detectHost(env: NodeJS.ProcessEnv = process.env): Host {
  const explicit = env["GUARDIAN_HOST"]?.toLowerCase();
  if (
    explicit === "kiro" ||
    explicit === "claude" ||
    explicit === "claude-desktop" ||
    explicit === "kiro-ide"
  ) {
    return explicit;
  }
  if (Object.keys(env).some((k) => k.startsWith("KIRO"))) return "kiro";
  return "claude";
}
```

`normalizeHookInput` já trata `host === "claude"` como passthrough; os novos valores não passam por hooks (só pelo proxy), então nenhuma mudança de normalização é necessária.

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/hosts.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/hosts/index.ts tests/hosts.test.ts
git commit -m "feat(hosts): reconhece claude-desktop e kiro-ide"
```

---

## Task 7: Integrar no comando `init`

**Files:**
- Modify: `src/cli/commands/init.ts`

Adiciona um passo que, ao final do `init`, envolve as configs MCP encontradas. Reversível via `init --uninstall-mcp` (ou documentado como manual). O `packageRoot` já é resolvido no arquivo (linha 74).

- [ ] **Step 1: Write the failing test**

```ts
// adicionar em tests/mcp-install.test.ts
import { installMcpProxy } from "../src/lib/mcp-install.ts";

describe("installMcpProxy (varredura por SO)", () => {
  it("retorna [] quando nenhuma config MCP existe", () => {
    // HOME apontando para um tmp vazio garante ausência de configs.
    const prev = process.env.HOME;
    const empty = mkdtempSync(join(tmpdir(), "guardian-empty-home-"));
    process.env.HOME = empty;
    try {
      expect(installMcpProxy(PROXY)).toEqual([]);
    } finally {
      process.env.HOME = prev;
      rmSync(empty, { recursive: true, force: true });
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/mcp-install.test.ts`
Expected: FAIL se `installMcpProxy` não estiver exportado (já está da Task 5) — caso contrário PASS. Se PASS, este teste apenas fixa o contrato; siga para o Step 3 (a integração no `init` é verificada manualmente).

- [ ] **Step 3: Write minimal implementation**

Em `src/cli/commands/init.ts`, após o bloco que escreve `settings.json` (logo depois da linha 106, `console.log("✓ Hooks registered ...")`), adicionar:

```ts
  // ── Proxy MCP: envolve as configs do Claude Desktop / Kiro IDE ─────────────
  const { installMcpProxy } = await import("../../lib/mcp-install.ts");
  const proxyPath = join(packageRoot, "src/proxy/mcp-proxy.ts");
  const wrapped = installMcpProxy(proxyPath);
  if (wrapped.length > 0) {
    for (const f of wrapped) console.log(`✓ MCP proxy instalado em ${f}`);
    console.log("Reinicie o Claude Desktop / Kiro IDE para ativar o proxy MCP.");
  } else {
    console.log("• Nenhuma config MCP encontrada (Claude Desktop / Kiro IDE).");
  }
```

Garanta que a função que contém esse bloco seja `async` (o `init` já usa `await` em outros pontos; se não, marcar a função como `async`).

- [ ] **Step 4: Run typecheck + suite**

Run: `npm run typecheck && npx vitest run tests/mcp-install.test.ts`
Expected: typecheck sem erros; testes PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli/commands/init.ts tests/mcp-install.test.ts
git commit -m "feat(init): envolve configs MCP do Claude Desktop/Kiro IDE no init"
```

---

## Task 8: Documentação + rollback

**Files:**
- Create: `docs/GUI-GATEWAY.md`
- Modify: `CLAUDE.md` (nota curta na seção de arquitetura)

- [ ] **Step 1: Escrever `docs/GUI-GATEWAY.md`**

Conteúdo mínimo (preencher o resultado do spike da Task 0):

```markdown
# Guardian GUI Gateway

Cobertura DLP para superfícies GUI que não têm hooks: Claude Desktop e Kiro IDE.

## Fase 1 — Proxy MCP (esta entrega)

`init` envolve cada MCP server configurado (`claude_desktop_config.json`,
`~/.kiro/settings/mcp.json`, `.kiro/settings/mcp.json` do workspace) com o shim
`src/proxy/mcp-proxy.ts`. O shim faz spawn do server real e escaneia o tráfego
JSON-RPC (`tools/call` args = egress, resultados = ingress) via `scanMcp`,
reusando engine/policy/audit/central. Bloqueio = erro JSON-RPC `-32001`.

### Rollback manual
Restaurar o backup: cada config vira `<arquivo>.guardian.bak`. Rode
`init --uninstall-mcp` (ou copie o `.bak` de volta) e reinicie o cliente.

### Kiro IDE hook-compat (spike Task 0): SIM/NÃO
<preencher com o resultado do spike>

## Fases futuras
- Fase 2: proxy HTTPS + CA/MDM (prompt + anexo no Claude Desktop).
- Fase 3: heartbeat/tamper do proxy no fleet.
```

- [ ] **Step 2: Nota no `CLAUDE.md`**

Adicionar sob a seção de arquitetura um parágrafo curto:

```markdown
### GUI Gateway (extensão para Desktop/IDE)

`src/proxy/mcp-proxy.ts` é um shim stdio injetado nas configs MCP do Claude
Desktop e Kiro IDE pelo `init` (`src/lib/mcp-install.ts`). Ele escaneia o
tráfego JSON-RPC via `src/lib/mcp-scan.ts` (`scanMcp`, tools virtuais
`McpToolCall`/`McpToolResult`), reusando o mesmo pipeline dos hooks. Fase 2
(proxy HTTPS + CA para prompt/anexo no Desktop) fica em plano separado.
```

- [ ] **Step 3: Rodar a suite completa**

Run: `npm run ci`
Expected: typecheck + biome + todos os testes PASS.

- [ ] **Step 4: Commit**

```bash
git add docs/GUI-GATEWAY.md CLAUDE.md
git commit -m "docs: GUI Gateway fase 1 (proxy MCP) + nota no CLAUDE.md"
```

---

## Self-Review (executado durante a escrita)

- **Cobertura do spec (Fase 1):** proxy MCP stdio ✅ (Tasks 2–3); scan reusando pipeline ✅ (Task 1); bloqueio via erro JSON-RPC ✅ (Task 2); reescrita idempotente + reversível das configs ✅ (Tasks 4–5); Claude Desktop + Kiro IDE cobertos pelos localizadores ✅ (Task 5); host detection ✅ (Task 6); integração no `init` ✅ (Task 7); spike Kiro IDE hook-compat ✅ (Task 0); docs ✅ (Task 8). Fases 2/3 (HTTPS/CA, fleet/tamper) são planos separados — fora do escopo desta Fase 1, como decidido no spec.
- **Placeholders:** nenhum "TBD/TODO" em código; o único `<preencher>` é resultado de investigação (spike), não código.
- **Consistência de tipos:** `ScanFn`/`ScanDecision` usados igual nas Tasks 2–3; `wrapMcpServers`/`isWrapped`/`installMcpProxyAt`/`installMcpProxy`/`mcpConfigPaths` consistentes entre Tasks 4–5–7; tools virtuais `McpToolCall`/`McpToolResult` idênticos entre `mcp-scan.ts` e os handlers; `GUARDIAN_MCP_TARGET`/`GUARDIAN_MCP_NAME` consistentes entre `wrapMcpServers` (produz) e `parseTarget`/`main` (consome).
```
