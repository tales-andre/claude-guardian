import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { hashConfig } from "../../lib/fleet.ts";
import {
  compileManagedSettings,
  type OrgPolicyInput,
} from "../../lib/managed-settings.ts";

interface EmitOptions {
  out?: string;
  hookCommand?: string;
  allowMcp?: string;
  denyMcp?: string;
  denyRead?: string;
}

function list(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function hookCmd(script: string): string {
  const hookPath = fileURLToPath(
    new URL(`../../hooks/${script}`, import.meta.url),
  );
  return `node --experimental-strip-types ${hookPath}`;
}

/**
 * Compila os artefatos de managed settings e grava em disco. O server payload
 * vai colado no console claude.ai; os arquivos endpoint vão via MDM. Imprime o
 * hash esperado da config (para o painel de frota comparar e flagar tampered).
 */
export function cmdEmitManagedSettings(options: EmitOptions): void {
  const outDir = resolve(options.out ?? "./managed-settings-out");

  const input: OrgPolicyInput = {
    hookCommand: options.hookCommand ?? hookCmd("pre-tool-use.ts"),
    postToolUseCommand: hookCmd("post-tool-use.ts"),
    userPromptSubmitCommand: hookCmd("user-prompt-submit.ts"),
    configChangeCommand: hookCmd("config-change.ts"),
    allowedMcpServers: list(options.allowMcp),
    deniedMcpServers: list(options.denyMcp),
    denyReadPaths: list(options.denyRead),
  };

  const compiled = compileManagedSettings(input);
  mkdirSync(outDir, { recursive: true });

  const files: Array<[string, unknown]> = [
    ["managed-settings.server.json", compiled.serverManaged],
    ["managed-settings.json", compiled.endpointManagedSettings],
    ["managed-mcp.json", compiled.managedMcp],
  ];
  for (const [name, content] of files) {
    writeFileSync(join(outDir, name), `${JSON.stringify(content, null, 2)}\n`);
  }

  const expectedHash = hashConfig(compiled.serverManaged);
  process.stdout.write(
    [
      `Managed settings written to ${outDir}`,
      "",
      "  managed-settings.server.json  → paste into Admin Settings > Claude Code > Managed settings",
      "  managed-settings.json         → push via MDM to the OS managed path",
      "  managed-mcp.json              → push via MDM (MCP allowlist)",
      "",
      `Expected config hash (for fleet tamper-detection): ${expectedHash}`,
      "",
      "Note: against developers with local admin this is tamper-resistant and",
      "auto-reverted (the MDM re-applies) — detected, not absolutely prevented.",
      "",
    ].join("\n"),
  );
}
