import { randomUUID } from "node:crypto";

// ── Compilador de políticas de browser ────────────────────────────────────────
// O control-plane compila os artefatos que instalam e configuram a extensão
// DLP à força nos browsers gerenciados. Um input → um artefato por canal:
//   • Linux:   JSON em /etc/opt/chrome/policies/managed/ (e equivalente Edge)
//   • Windows: .reg (Intune/GPO) com forcelist + managed storage (3rdparty)
//   • macOS:   .mobileconfig (Jamf/Kandji) com payloads Chrome/Edge
//   • Firefox: policies.json (ExtensionSettings + 3rdparty)
// Quem distribui é o MDM — o guardian só gera. Mesmo modelo de ameaça do
// resto: força + reaplicação + detecção via fleet, não prevenção absoluta.

export const CHROME_WEBSTORE_UPDATE_URL =
  "https://clients2.google.com/service/update2/crx";

export interface BrowserPolicyInput {
  /** ID da extensão no Chrome/Edge (32 chars, da Web Store ou self-hosted). */
  extensionId: string;
  /** update_url do CRX; default: Chrome Web Store. */
  updateUrl?: string;
  /** ID/update_url próprios para o Edge (default: mesmos do Chrome). */
  edgeExtensionId?: string;
  edgeUpdateUrl?: string;
  /** ID gecko da extensão Firefox (browser_specific_settings.gecko.id). */
  firefoxExtensionId?: string;
  /** URL do .xpi para force install no Firefox (sem ela, só managed storage). */
  firefoxInstallUrl?: string;
  /** Endpoint do daemon local que a extensão consulta. */
  guardianEndpoint?: string;
  /** dashboardToken do daemon local. */
  guardianToken?: string;
}

export interface CompiledBrowserPolicies {
  /** /etc/opt/chrome/policies/managed/claude-guardian.json */
  chromeLinuxPolicy: Record<string, unknown>;
  /** /etc/opt/edge/policies/managed/claude-guardian.json */
  edgeLinuxPolicy: Record<string, unknown>;
  /** Importar via Intune/GPO (Chrome + Edge no mesmo arquivo). */
  windowsRegistry: string;
  /** Perfil de configuração para Jamf/Kandji. */
  macMobileconfig: string;
  /** distribution/policies.json do Firefox. */
  firefoxPolicies: Record<string, unknown>;
}

interface ManagedStorage {
  endpoint: string;
  token?: string;
}

function managedStorage(input: BrowserPolicyInput): ManagedStorage {
  const storage: ManagedStorage = {
    endpoint: input.guardianEndpoint ?? "http://127.0.0.1:7734",
  };
  if (input.guardianToken) storage.token = input.guardianToken;
  return storage;
}

function chromiumPolicy(
  extensionId: string,
  updateUrl: string,
  storage: ManagedStorage,
): Record<string, unknown> {
  return {
    ExtensionInstallForcelist: [`${extensionId};${updateUrl}`],
    "3rdparty": { extensions: { [extensionId]: { ...storage } } },
  };
}

function regEscape(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function registrySection(
  root: string,
  extensionId: string,
  updateUrl: string,
  storage: ManagedStorage,
): string {
  const lines = [
    `[HKEY_LOCAL_MACHINE\\${root}\\ExtensionInstallForcelist]`,
    `"1"="${regEscape(`${extensionId};${updateUrl}`)}"`,
    "",
    `[HKEY_LOCAL_MACHINE\\${root}\\3rdparty\\extensions\\${extensionId}\\policy]`,
    `"endpoint"="${regEscape(storage.endpoint)}"`,
  ];
  if (storage.token) lines.push(`"token"="${regEscape(storage.token)}"`);
  lines.push("");
  return lines.join("\r\n");
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function plistDict(entries: string): string {
  return `    <dict>\n${entries}\n    </dict>`;
}

function payload(type: string, body: string): string {
  return plistDict(
    [
      "      <key>PayloadType</key>",
      `      <string>${type}</string>`,
      "      <key>PayloadVersion</key>",
      "      <integer>1</integer>",
      "      <key>PayloadIdentifier</key>",
      `      <string>${type}.claude-guardian</string>`,
      "      <key>PayloadUUID</key>",
      `      <string>${randomUUID()}</string>`,
      "      <key>PayloadEnabled</key>",
      "      <true/>",
      body,
    ].join("\n"),
  );
}

function forcelistPayload(
  bundle: string,
  extensionId: string,
  updateUrl: string,
): string {
  return payload(
    bundle,
    [
      "      <key>ExtensionInstallForcelist</key>",
      "      <array>",
      `        <string>${xmlEscape(`${extensionId};${updateUrl}`)}</string>`,
      "      </array>",
    ].join("\n"),
  );
}

function storagePayload(
  bundle: string,
  extensionId: string,
  storage: ManagedStorage,
): string {
  const entries = [
    "      <key>endpoint</key>",
    `      <string>${xmlEscape(storage.endpoint)}</string>`,
  ];
  if (storage.token) {
    entries.push(
      "      <key>token</key>",
      `      <string>${xmlEscape(storage.token)}</string>`,
    );
  }
  return payload(`${bundle}.extensions.${extensionId}`, entries.join("\n"));
}

function buildMobileconfig(
  chromeId: string,
  chromeUpdateUrl: string,
  edgeId: string,
  edgeUpdateUrl: string,
  storage: ManagedStorage,
): string {
  const payloads = [
    forcelistPayload("com.google.Chrome", chromeId, chromeUpdateUrl),
    storagePayload("com.google.Chrome", chromeId, storage),
    forcelistPayload("com.microsoft.Edge", edgeId, edgeUpdateUrl),
    storagePayload("com.microsoft.Edge", edgeId, storage),
  ].join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadIdentifier</key>
  <string>com.claude-guardian.browser-dlp</string>
  <key>PayloadUUID</key>
  <string>${randomUUID()}</string>
  <key>PayloadDisplayName</key>
  <string>Claude Guardian — DLP de browser</string>
  <key>PayloadContent</key>
  <array>
${payloads}
  </array>
</dict>
</plist>
`;
}

function buildFirefoxPolicies(
  input: BrowserPolicyInput,
  storage: ManagedStorage,
): Record<string, unknown> {
  const policies: Record<string, unknown> = {};
  const ffId = input.firefoxExtensionId;
  if (!ffId) return { policies };

  if (input.firefoxInstallUrl) {
    policies["ExtensionSettings"] = {
      [ffId]: {
        installation_mode: "force_installed",
        install_url: input.firefoxInstallUrl,
      },
    };
  }
  policies["3rdparty"] = { Extensions: { [ffId]: { ...storage } } };
  return { policies };
}

/** Compila os artefatos de política de browser por canal de distribuição. */
export function compileBrowserPolicies(
  input: BrowserPolicyInput,
): CompiledBrowserPolicies {
  const storage = managedStorage(input);
  const chromeUpdateUrl = input.updateUrl ?? CHROME_WEBSTORE_UPDATE_URL;
  const edgeId = input.edgeExtensionId ?? input.extensionId;
  const edgeUpdateUrl = input.edgeUpdateUrl ?? chromeUpdateUrl;

  const windowsRegistry = [
    "Windows Registry Editor Version 5.00",
    "",
    registrySection(
      "SOFTWARE\\Policies\\Google\\Chrome",
      input.extensionId,
      chromeUpdateUrl,
      storage,
    ),
    registrySection(
      "SOFTWARE\\Policies\\Microsoft\\Edge",
      edgeId,
      edgeUpdateUrl,
      storage,
    ),
  ].join("\r\n");

  return {
    chromeLinuxPolicy: chromiumPolicy(
      input.extensionId,
      chromeUpdateUrl,
      storage,
    ),
    edgeLinuxPolicy: chromiumPolicy(edgeId, edgeUpdateUrl, storage),
    windowsRegistry,
    macMobileconfig: buildMobileconfig(
      input.extensionId,
      chromeUpdateUrl,
      edgeId,
      edgeUpdateUrl,
      storage,
    ),
    firefoxPolicies: buildFirefoxPolicies(input, storage),
  };
}
