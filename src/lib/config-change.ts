import type BetterSqlite3 from "better-sqlite3";
import type {
  Config,
  DetectorFinding,
  Incident,
  Severity,
} from "../types/index.ts";
import { appendAuditEntry } from "./audit.ts";
import { reportToCentral } from "./central.ts";
import { recordIncident } from "./incident.ts";

// ── Handler do hook ConfigChange ──────────────────────────────────────────────
// O Claude Code dispara ConfigChange quando uma fonte de configuração muda
// durante a sessão (user_settings, project_settings, local_settings,
// policy_settings, skills). Mexer nessas fontes é o caminho mais óbvio para
// remover o hook do guardian, então registramos a mudança como evento visível
// (audit + central). Auditoria-only: não bloqueia a mudança.

/** O payload do ConfigChange — campos defensivos, contrato é pouco documentado. */
export interface ConfigChangeEvent {
  session_id?: string;
  source?: string;
  config_source?: string;
  hook_event_name?: string;
}

function eventSource(event: ConfigChangeEvent): string {
  return event.source ?? event.config_source ?? "unknown";
}

// Alterar a policy gerenciada é o evento mais grave; as demais fontes são altas.
function severityForSource(source: string): Severity {
  return source === "policy_settings" ? "critical" : "high";
}

function configChangeFinding(source: string): DetectorFinding {
  return {
    detectorId: "config-change",
    label: `Config change — ${source}`,
    dataType: "config-change",
    severity: severityForSource(source),
    snippet: source,
    rawValue: source,
    position: { start: 0, end: 0 },
    confidence: 1.0,
  };
}

/**
 * Registra uma mudança de configuração como incidente + audit + espelho central.
 * Best-effort: nunca lança. Retorna o incidente criado.
 */
export function handleConfigChange(
  db: BetterSqlite3.Database,
  config: Config,
  event: ConfigChangeEvent,
): Incident | null {
  try {
    const source = eventSource(event);
    const findings = [configChangeFinding(source)];
    const incident = recordIncident(
      db,
      "ConfigChange",
      event.session_id ?? "",
      findings,
      "allow",
    );
    appendAuditEntry(db, "config-change", { incidentId: incident.id, source });
    reportToCentral(config, incident, findings, null, "config-change");
    return incident;
  } catch {
    return null;
  }
}
