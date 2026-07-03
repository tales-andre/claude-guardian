import type BetterSqlite3 from "better-sqlite3";
import type { Config, DetectorFinding, Incident } from "../types/index.ts";
import { appendAuditEntry } from "./audit.ts";
import { reportToCentral } from "./central.ts";
import { recordIncident } from "./incident.ts";

// ── Detector de evasão por troca de provider ──────────────────────────────────
// Server-managed settings são totalmente ignoradas quando o Claude Code é
// apontado para outro provider (Bedrock/Vertex/Foundry/Mantle/AWS) ou para um
// ANTHROPIC_BASE_URL customizado. Um dev com admin local pode desligar todos os
// controles gerenciados só setando uma env var — sem editar arquivo nenhum.
// Isto NÃO bloqueia o fluxo: é um sinal de evasão visível (audit + central).
// Nunca expõe o valor da env var, só o nome.

/** Flags `CLAUDE_CODE_USE_*` que desviam o tráfego para outro provider. */
const PROVIDER_FLAGS = [
  "CLAUDE_CODE_USE_BEDROCK",
  "CLAUDE_CODE_USE_VERTEX",
  "CLAUDE_CODE_USE_FOUNDRY",
  "CLAUDE_CODE_USE_MANTLE",
  "CLAUDE_CODE_USE_ANTHROPIC_AWS",
] as const;

const FALSY = new Set(["", "0", "false", "no", "off"]);

function isTruthy(value: string | undefined): boolean {
  return value != null && !FALSY.has(value.trim().toLowerCase());
}

function evasionFinding(varName: string): DetectorFinding {
  return {
    detectorId: "provider-evasion",
    label: `Provider switch — managed settings bypassed (${varName})`,
    dataType: "provider-evasion",
    severity: "high",
    snippet: varName,
    rawValue: varName,
    position: { start: 0, end: 0 },
    confidence: 1.0,
  };
}

/**
 * Inspeciona o ambiente em busca de vetores de evasão de provider.
 * Recebe `env` explicitamente para ser puro e testável (hermético).
 */
export function detectProviderEvasion(
  env: NodeJS.ProcessEnv = process.env,
): DetectorFinding[] {
  const findings: DetectorFinding[] = [];

  if (isTruthy(env["ANTHROPIC_BASE_URL"])) {
    findings.push(evasionFinding("ANTHROPIC_BASE_URL"));
  }

  for (const flag of PROVIDER_FLAGS) {
    if (isTruthy(env[flag])) findings.push(evasionFinding(flag));
  }

  return findings;
}

/**
 * Verifica o ambiente e, havendo evasão, registra um incidente (não-bloqueante),
 * grava no audit log e espelha ao central. Retorna o incidente criado ou null.
 * Best-effort: nunca lança — detecção de evasão jamais pode quebrar um hook.
 */
export function reportEvasion(
  db: BetterSqlite3.Database,
  config: Config,
  env: NodeJS.ProcessEnv = process.env,
): Incident | null {
  try {
    const findings = detectProviderEvasion(env);
    if (findings.length === 0) return null;

    // action "allow": é um alerta visível, não um bloqueio (não dá para impedir
    // um dev admin de trocar o provider — só torná-lo evidente).
    const incident = recordIncident(db, "Environment", "", findings, "allow");
    appendAuditEntry(db, "provider-evasion", {
      incidentId: incident.id,
      vars: findings.map((f) => f.snippet),
    });
    reportToCentral(config, incident, findings, null, "provider-evasion");
    return incident;
  } catch {
    return null;
  }
}
