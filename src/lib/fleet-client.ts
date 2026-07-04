import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { hostname as osHostname, userInfo } from "node:os";
import type {
  Config,
  ExtensionHeartbeat,
  MachineHeartbeatPayload,
} from "../types/index.ts";
import { centralEnabled } from "./central.ts";
import { hashConfig } from "./fleet.ts";

// ── Cliente de heartbeat da frota ─────────────────────────────────────────────
// O daemon local reporta periodicamente ao central: versão do guardian, hash
// da config managed efetiva (para detecção de tamper) e o estado da extensão
// de navegador (último ping + falhas de extractText por provider = drift).
// Best-effort: central fora do ar nunca afeta o daemon.

const FETCH_TIMEOUT_MS = 1500;

const require = createRequire(import.meta.url);

/** Caminho do managed-settings.json empurrado via MDM, por SO. */
export function managedSettingsFilePath(
  platform: NodeJS.Platform = process.platform,
): string {
  switch (platform) {
    case "darwin":
      return "/Library/Application Support/ClaudeCode/managed-settings.json";
    case "win32":
      return "C:\\ProgramData\\ClaudeCode\\managed-settings.json";
    default:
      return "/etc/claude-code/managed-settings.json";
  }
}

/**
 * Hash canônico da config managed efetiva na máquina. "" quando o arquivo não
 * existe/não parseia — o fleet trata hash vazio como divergente do esperado.
 */
export function effectiveConfigHash(
  path: string = managedSettingsFilePath(),
): string {
  try {
    return hashConfig(JSON.parse(readFileSync(path, "utf8")));
  } catch {
    return "";
  }
}

function guardianVersion(): string {
  try {
    const pkg = require("../../package.json") as { version?: string };
    return pkg.version ?? "";
  } catch {
    return "";
  }
}

export function buildMachineHeartbeat(
  extension: ExtensionHeartbeat | null,
  opts: { configHash?: string } = {},
): MachineHeartbeatPayload {
  let username = "unknown";
  try {
    username = userInfo().username;
  } catch {
    username = process.env["USER"] ?? process.env["USERNAME"] ?? "unknown";
  }
  return {
    machine: { hostname: osHostname(), username },
    guardianVersion: guardianVersion(),
    configHash: opts.configHash ?? effectiveConfigHash(),
    extension,
  };
}

/**
 * Envia o heartbeat ao central. Silencioso e com timeout curto — falha de
 * rede jamais pode afetar o daemon (mesmo contrato do reportToCentral).
 */
export async function sendMachineHeartbeat(
  config: Config,
  payload: MachineHeartbeatPayload,
): Promise<boolean> {
  if (!centralEnabled(config)) return false;
  try {
    const base = config.centralUrl.replace(/\/+$/, "");
    const res = await fetch(`${base}/api/agent/heartbeat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Guardian-Agent-Key": config.centralApiKey,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    return res.ok;
  } catch {
    return false;
  }
}
