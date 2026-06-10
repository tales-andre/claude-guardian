import { randomBytes } from "node:crypto";
import { hostname as osHostname, userInfo } from "node:os";
import type BetterSqlite3 from "better-sqlite3";
import { redact } from "../engine/utils.ts";
import type {
  DataType,
  DetectorFinding,
  Incident,
  PolicyAction,
  Severity,
} from "../types/index.ts";

interface StoredFinding {
  detectorId: string;
  label: string;
  dataType: string;
  severity: string;
  snippet: string;
  rawValue: string;
  confidence: number;
}

function toStoredFinding(f: DetectorFinding): StoredFinding {
  return {
    detectorId: f.detectorId,
    label: f.label,
    dataType: f.dataType,
    severity: f.severity,
    snippet: f.snippet,
    rawValue: f.rawValue,
    confidence: f.confidence,
  };
}

function getSystemUsername(): string {
  try {
    return userInfo().username;
  } catch {
    return process.env["USER"] ?? process.env["USERNAME"] ?? "unknown";
  }
}

function getSystemHostname(): string {
  try {
    return osHostname();
  } catch {
    return "";
  }
}

function contextFromFindings(
  findings: DetectorFinding[],
  tool: string,
): string {
  const types = [...new Set(findings.map((f) => f.label))].join(", ");
  return `${tool}: detected ${types}`;
}

export function recordIncident(
  db: BetterSqlite3.Database,
  tool: string,
  sessionId: string,
  findings: DetectorFinding[],
  action: PolicyAction,
  approvalId: string | null = null,
): Incident {
  const id = randomBytes(12).toString("hex");
  const timestamp = new Date().toISOString();
  const username = getSystemUsername();
  const hostname = getSystemHostname();
  const dataTypes = [...new Set(findings.map((f) => f.dataType))] as DataType[];
  const severities = [
    ...new Set(findings.map((f) => f.severity)),
  ] as Severity[];
  const context = contextFromFindings(findings, tool);
  const findingsJson = JSON.stringify(findings.map(toStoredFinding));

  db.prepare(
    `INSERT INTO incidents(id, timestamp, tool, session_id, username, hostname, context, data_types, severities, findings, action, approval_id)
     VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    timestamp,
    tool,
    sessionId,
    username,
    hostname,
    context,
    JSON.stringify(dataTypes),
    JSON.stringify(severities),
    findingsJson,
    action,
    approvalId,
  );

  return {
    id,
    timestamp,
    tool,
    sessionId,
    username,
    hostname,
    context,
    dataTypes,
    severities,
    findingsJson,
    action,
    approvalId,
  };
}

export function listIncidents(
  db: BetterSqlite3.Database,
  limit = 100,
  offset = 0,
): Incident[] {
  return (
    db
      .prepare(
        "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ? OFFSET ?",
      )
      .all(limit, offset) as Record<string, unknown>[]
  ).map(rowToIncident);
}

export function getIncidentById(
  db: BetterSqlite3.Database,
  id: string,
): Incident | null {
  const row = db
    .prepare<[string], Record<string, unknown>>(
      "SELECT * FROM incidents WHERE id = ?",
    )
    .get(id);
  return row ? rowToIncident(row) : null;
}

function rowToIncident(row: Record<string, unknown>): Incident {
  return {
    id: String(row["id"]),
    timestamp: String(row["timestamp"]),
    tool: String(row["tool"]),
    sessionId: String(row["session_id"]),
    username: String(row["username"] ?? ""),
    hostname: String(row["hostname"] ?? ""),
    context: String(row["context"]),
    dataTypes: JSON.parse(String(row["data_types"])) as DataType[],
    severities: JSON.parse(String(row["severities"])) as Severity[],
    findingsJson: String(row["findings"]),
    action: String(row["action"]) as PolicyAction,
    approvalId: row["approval_id"] != null ? String(row["approval_id"]) : null,
  };
}

// Extrai a justificativa de [request-exception: motivo] do prompt do usuário.
export function extractExceptionRequest(prompt: string): string | null {
  const m = prompt.match(/\[request-exception:\s*([^\]]{3,})\]/i);
  return m?.[1]?.trim() ?? null;
}

export function buildBlockReason(
  tool: string,
  findings: DetectorFinding[],
  incidentId: string,
  dashboardUrl = "http://localhost:7734",
): string {
  const lines = findings.map(
    (f) =>
      `  [${f.severity.toUpperCase()}] ${f.label} (${f.detectorId}): ${f.snippet}`,
  );
  return [
    `claude-guardian bloqueou: dado sensível detectado em ${tool}`,
    "",
    ...lines,
    "",
    `Incident ID: ${incidentId}`,
    "",
    "Para solicitar a liberação, acesse:",
    `  ${dashboardUrl}/request-approval/${incidentId}`,
    "",
    "Após aprovação pelo administrador, repita o prompt normalmente.",
  ].join("\n");
}

export function buildApprovalBlockReason(
  tool: string,
  findings: DetectorFinding[],
  incidentId: string,
  dashboardUrl = "http://localhost:7734",
): string {
  const lines = findings.map(
    (f) =>
      `  [${f.severity.toUpperCase()}] ${f.label} (${f.detectorId}): ${f.snippet}`,
  );
  return [
    `claude-guardian: exceção necessária para ${tool}`,
    "",
    ...lines,
    "",
    `Incident ID: ${incidentId}`,
    "",
    "Para solicitar a liberação, acesse:",
    `  ${dashboardUrl}/request-approval/${incidentId}`,
    "",
    "Após aprovação pelo administrador, repita o prompt normalmente.",
  ].join("\n");
}

export { redact };
