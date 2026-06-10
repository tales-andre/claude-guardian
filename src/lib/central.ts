import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { hostname as osHostname, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  AgentIngestPayload,
  Approval,
  Config,
  DetectorFinding,
  Incident,
} from "../types/index.ts";

// ── Integração com o servidor central (modo enterprise) ───────────────────────
// Os hooks continuam decidindo 100% localmente. Quando centralUrl está
// configurado, os eventos são espelhados para o servidor central via um outbox
// em disco (store-and-forward): o hook grava o evento e dispara um processo
// destacado que faz o POST — latência adicional zero e tolerância a offline.
// Segredos brutos (rawValue) NUNCA saem da máquina.

const FETCH_TIMEOUT_MS = 1500;
const MAX_OUTBOX_FILES = 500;

export function centralEnabled(config: Config): boolean {
  return Boolean(config.centralUrl && config.centralApiKey);
}

/** Base do dashboard mostrada nas mensagens de bloqueio. */
export function dashboardBaseUrl(config: Config): string {
  if (centralEnabled(config)) return config.centralUrl.replace(/\/+$/, "");
  return `http://localhost:${config.dashboardPort}`;
}

export function outboxDir(config: Config): string {
  return join(dirname(config.dbPath), "outbox");
}

function machineInfo(): { hostname: string; username: string } {
  let username = "unknown";
  try {
    username = userInfo().username;
  } catch {
    username = process.env["USER"] ?? process.env["USERNAME"] ?? "unknown";
  }
  let hostname = "";
  try {
    hostname = osHostname();
  } catch {
    // best-effort
  }
  return { hostname, username };
}

export function buildIngestPayload(
  incident: Incident,
  findings: DetectorFinding[],
  approval: Approval | null,
  auditType: string,
): AgentIngestPayload {
  return {
    machine: machineInfo(),
    incident: {
      id: incident.id,
      timestamp: incident.timestamp,
      tool: incident.tool,
      sessionId: incident.sessionId,
      context: incident.context,
      dataTypes: incident.dataTypes,
      severities: incident.severities,
      // rawValue intencionalmente omitido — só metadados saem da máquina.
      findings: findings.map((f) => ({
        detectorId: f.detectorId,
        label: f.label,
        dataType: String(f.dataType),
        severity: f.severity,
        snippet: f.snippet,
        confidence: f.confidence,
      })),
      action: incident.action,
    },
    approval: approval
      ? {
          id: approval.id,
          scope: approval.scope,
          justification: approval.justification,
          ttlSeconds: approval.ttlSeconds,
          requestedAt: approval.requestedAt,
        }
      : null,
    auditType,
  };
}

/**
 * Grava o evento no outbox e dispara o flusher em background.
 * Nunca lança: falha de relatório jamais pode quebrar um hook.
 */
export function reportToCentral(
  config: Config,
  incident: Incident,
  findings: DetectorFinding[],
  approval: Approval | null,
  auditType: string,
): void {
  if (!centralEnabled(config)) return;
  try {
    const dir = outboxDir(config);
    mkdirSync(dir, { recursive: true });

    // Limite de segurança: servidor fora do ar por muito tempo não pode
    // encher o disco do funcionário.
    if (readdirSync(dir).length >= MAX_OUTBOX_FILES) return;

    const payload = buildIngestPayload(incident, findings, approval, auditType);
    const file = join(
      dir,
      `${Date.now()}-${randomBytes(4).toString("hex")}.json`,
    );
    writeFileSync(file, JSON.stringify(payload), "utf8");
    spawnFlusher();
  } catch {
    // best-effort
  }
}

/** Dispara o processo destacado que esvazia o outbox. */
export function spawnFlusher(): void {
  try {
    const flushScript = fileURLToPath(
      new URL("./central-flush.ts", import.meta.url),
    );
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", flushScript],
      { detached: true, stdio: "ignore" },
    );
    child.unref();
  } catch {
    // best-effort
  }
}

/**
 * Consulta o servidor central por uma aprovação ativa para o scope.
 * Timeout curto e fallback silencioso: indisponibilidade do central não pode
 * travar o hook (o comportamento local fail-safe permanece o mesmo).
 */
export async function fetchActiveCentralApproval(
  config: Config,
  scope: string,
): Promise<boolean> {
  if (!centralEnabled(config)) return false;
  try {
    const base = config.centralUrl.replace(/\/+$/, "");
    const res = await fetch(
      `${base}/api/agent/approvals/active?scope=${encodeURIComponent(scope)}`,
      {
        headers: { "X-Guardian-Agent-Key": config.centralApiKey },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      },
    );
    if (!res.ok) return false;
    const data = (await res.json()) as { approval?: unknown };
    return data.approval != null;
  } catch {
    return false;
  }
}
