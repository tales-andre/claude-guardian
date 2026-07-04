// Instala/remove o shim mcp-proxy.ts nas configs MCP do Claude Desktop e do
// Kiro IDE, envolvendo cada server configurado. Idempotente e reversível
// (guarda backup <arquivo>.guardian.bak antes da primeira reescrita).
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";

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
  return entry.command === "node" && (entry.args ?? []).includes(proxyPath);
}

/** Envolve cada server para rotear pelo shim, preservando o original em env. */
export function wrapMcpServers<T extends McpConfig>(
  config: T,
  proxyPath: string,
): T {
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

const BAK = ".guardian.bak";

/** Reescreve um arquivo de config MCP; retorna false se ele não existir/vazio. */
export function installMcpProxyAt(file: string, proxyPath: string): boolean {
  if (!existsSync(file)) return false;
  const raw = readFileSync(file, "utf8");
  const config = JSON.parse(raw) as McpConfig;
  if (!config.mcpServers || Object.keys(config.mcpServers).length === 0) {
    return false;
  }
  if (!existsSync(file + BAK)) copyFileSync(file, file + BAK);
  const wrapped = wrapMcpServers(config, proxyPath);
  writeFileSync(file, `${JSON.stringify(wrapped, null, 2)}\n`, "utf8");
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
    paths.push(
      join(
        home,
        "Library",
        "Application Support",
        "Claude",
        "claude_desktop_config.json",
      ),
    );
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

/** Envolve todas as configs MCP encontradas; devolve os arquivos alterados. */
export function installMcpProxy(proxyPath: string): string[] {
  const done: string[] = [];
  for (const file of mcpConfigPaths()) {
    if (installMcpProxyAt(file, proxyPath)) done.push(file);
  }
  return done;
}

/** Restaura todas as configs MCP a partir do backup; devolve as restauradas. */
export function uninstallMcpProxy(): string[] {
  const done: string[] = [];
  for (const file of mcpConfigPaths()) {
    if (uninstallMcpProxyAt(file)) done.push(file);
  }
  return done;
}
