import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type BrowserPolicyInput,
  compileBrowserPolicies,
} from "../../lib/browser-policies.ts";
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
  extensionId?: string;
  extensionUpdateUrl?: string;
  edgeExtensionId?: string;
  edgeUpdateUrl?: string;
  firefoxId?: string;
  firefoxXpi?: string;
  guardianEndpoint?: string;
  guardianToken?: string;
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

  // ── Políticas de browser (opcional: exige --extension-id) ──────────────────
  const browserLines: string[] = [];
  if (options.extensionId) {
    const browserInput: BrowserPolicyInput = {
      extensionId: options.extensionId,
      ...(options.extensionUpdateUrl && {
        updateUrl: options.extensionUpdateUrl,
      }),
      ...(options.edgeExtensionId && {
        edgeExtensionId: options.edgeExtensionId,
      }),
      ...(options.edgeUpdateUrl && { edgeUpdateUrl: options.edgeUpdateUrl }),
      ...(options.firefoxId && { firefoxExtensionId: options.firefoxId }),
      ...(options.firefoxXpi && { firefoxInstallUrl: options.firefoxXpi }),
      ...(options.guardianEndpoint && {
        guardianEndpoint: options.guardianEndpoint,
      }),
      ...(options.guardianToken && { guardianToken: options.guardianToken }),
    };
    const browser = compileBrowserPolicies(browserInput);
    const browserDir = join(outDir, "browser");
    mkdirSync(browserDir, { recursive: true });

    writeFileSync(
      join(browserDir, "chrome-policy.linux.json"),
      `${JSON.stringify(browser.chromeLinuxPolicy, null, 2)}\n`,
    );
    writeFileSync(
      join(browserDir, "edge-policy.linux.json"),
      `${JSON.stringify(browser.edgeLinuxPolicy, null, 2)}\n`,
    );
    writeFileSync(
      join(browserDir, "browser-policy.windows.reg"),
      browser.windowsRegistry,
    );
    writeFileSync(
      join(browserDir, "browser-policy.macos.mobileconfig"),
      browser.macMobileconfig,
    );
    writeFileSync(
      join(browserDir, "firefox-policies.json"),
      `${JSON.stringify(browser.firefoxPolicies, null, 2)}\n`,
    );

    browserLines.push(
      "  browser/chrome-policy.linux.json        → /etc/opt/chrome/policies/managed/",
      "  browser/edge-policy.linux.json          → /etc/opt/microsoft/msedge/policies/managed/",
      "  browser/browser-policy.windows.reg      → import via Intune/GPO (Chrome + Edge)",
      "  browser/browser-policy.macos.mobileconfig → push via Jamf/Kandji",
      "  browser/firefox-policies.json           → distribution/policies.json do Firefox",
    );
  }

  // O daemon reporta hashConfig(managed-settings.json efetivo) no heartbeat —
  // o hash de endpoint abaixo é o valor a colar no campo do fleet dashboard.
  const expectedEndpointHash = hashConfig(compiled.endpointManagedSettings);
  const serverHash = hashConfig(compiled.serverManaged);
  process.stdout.write(
    [
      `Managed settings written to ${outDir}`,
      "",
      "  managed-settings.server.json  → paste into Admin Settings > Claude Code > Managed settings",
      "  managed-settings.json         → push via MDM to the OS managed path",
      "  managed-mcp.json              → push via MDM (MCP allowlist)",
      ...browserLines,
      "",
      `Expected config hash — fleet/tamper (endpoint managed-settings.json): ${expectedEndpointHash}`,
      `Server-managed payload hash (referência):                             ${serverHash}`,
      "",
      "Note: against developers with local admin this is tamper-resistant and",
      "auto-reverted (the MDM re-applies) — detected, not absolutely prevented.",
      "",
    ].join("\n"),
  );
}
