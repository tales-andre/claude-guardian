// Shim stdio injetado nas configs MCP do Claude Desktop / Kiro IDE pelo init.
// O cliente spawna ESTE processo no lugar do MCP server real; nós fazemos spawn
// do server real e sentamos no meio do stream JSON-RPC (newline-delimited),
// escaneando tools/call (args = egress) e as respostas (result = ingress).
// Bloqueio = erro JSON-RPC devolvido ao cliente; a request nunca chega ao server.
// Scan roda in-process (igual aos hooks), sem depender do daemon.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  // biome-ignore lint/suspicious/noExplicitAny: JSON-RPC params/result são arbitrários
  params?: any;
  // biome-ignore lint/suspicious/noExplicitAny: JSON-RPC params/result são arbitrários
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
      c &&
      typeof c === "object" &&
      typeof (c as { text?: unknown }).text === "string"
        ? (c as { text: string }).text
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
  const write = (w: Writable, m: JsonRpcMessage) =>
    w.write(`${JSON.stringify(m)}\n`);

  const fromClient = createInterface({ input: clientIn });
  fromClient.on("line", (line) => {
    if (!line.trim()) return;
    let msg: JsonRpcMessage;
    try {
      msg = JSON.parse(line);
    } catch {
      childIn.write(`${line}\n`); // não-JSON: repassa cru
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
      clientOut.write(`${line}\n`);
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
    throw new Error(
      "mcp-proxy: alvo ausente (use -- <command> [args] ou GUARDIAN_MCP_TARGET)",
    );
  }
  return { command: argv[sep + 1] as string, args: argv.slice(sep + 2) };
}

async function main(): Promise<void> {
  const target = parseTarget(process.argv, process.env);
  // Scan real: abre DB + config uma vez, igual aos hooks (import dinâmico para
  // manter os handlers puros testáveis sem dependências pesadas).
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
      const d: ScanDecision = { action: r.action, reason: r.reason };
      if (r.redactedText !== undefined) d.redactedText = r.redactedText;
      return d;
    } catch {
      return {
        action: "block",
        reason: "erro interno do guardian (fail-closed)",
      };
    }
  };

  const child = spawn(target.command, target.args, {
    env: { ...process.env, ...target.env },
    stdio: ["pipe", "pipe", "inherit"],
  });
  child.on("exit", (code) => process.exit(code ?? 0));

  // biome-ignore lint/style/noNonNullAssertion: stdio "pipe" garante os streams
  runProxyStreams({
    clientIn: process.stdin,
    clientOut: process.stdout,
    // biome-ignore lint/style/noNonNullAssertion: stdio "pipe" garante os streams
    childIn: child.stdin!,
    // biome-ignore lint/style/noNonNullAssertion: stdio "pipe" garante os streams
    childOut: child.stdout!,
    scan,
  });
}

// Só executa main() quando rodado como entrypoint, não quando importado no teste.
if (process.argv[1]?.endsWith("mcp-proxy.ts")) {
  void main();
}
