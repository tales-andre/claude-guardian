import { randomBytes } from "node:crypto";
import type BetterSqlite3 from "better-sqlite3";
import { getDb } from "../db/client.ts";
import {
  createApproval,
  findActiveApproval,
  generateToken,
  getApprovalById,
  listApprovals,
  resolveApproval,
} from "../lib/approval.ts";
import { appendAuditEntry, verifyAuditChain } from "../lib/audit.ts";
import { getIncidentById, listIncidents } from "../lib/incident.ts";
import type {
  AgentIngestPayload,
  AgentKeyRow,
  Approval,
  ApprovalStatus,
  AuditEntry,
  Incident,
  MachineHeartbeatPayload,
  MachineRow,
} from "../types/index.ts";
import type {
  AuditVerifyResult,
  CustomDetectorRow,
  GuardianStore,
  MetricsResult,
} from "./store.ts";

// Storage local: embrulha as mesmas funções síncronas usadas pelos hooks,
// preservando byte a byte o comportamento do modo local.
export class SqliteStore implements GuardianStore {
  readonly kind = "sqlite" as const;
  private db: BetterSqlite3.Database;

  constructor(dbPath: string) {
    this.db = getDb(dbPath);
  }

  init(): Promise<void> {
    return Promise.resolve();
  }

  close(): Promise<void> {
    return Promise.resolve();
  }

  // ── Incidents ───────────────────────────────────────────────────────────────
  listIncidents(limit: number, offset: number): Promise<Incident[]> {
    return Promise.resolve(listIncidents(this.db, limit, offset));
  }

  getIncidentById(id: string): Promise<Incident | null> {
    return Promise.resolve(getIncidentById(this.db, id));
  }

  latestIncidentMark(): Promise<number> {
    const row = this.db
      .prepare("SELECT COALESCE(MAX(rowid), 0) AS m FROM incidents")
      .get() as { m: number };
    return Promise.resolve(row.m);
  }

  // ── Approvals ───────────────────────────────────────────────────────────────
  listApprovals(status?: ApprovalStatus): Promise<Approval[]> {
    return Promise.resolve(listApprovals(this.db, status));
  }

  getApprovalById(id: string): Promise<Approval | null> {
    return Promise.resolve(getApprovalById(this.db, id));
  }

  createApproval(
    incidentId: string,
    scope: string,
    justification: string,
    ttlSeconds: number,
  ): Promise<Approval> {
    return Promise.resolve(
      createApproval(this.db, incidentId, scope, justification, ttlSeconds),
    );
  }

  resolveApproval(
    id: string,
    status: "approved" | "denied",
    resolvedBy: string,
    ttlSeconds?: number,
  ): Promise<Approval | null> {
    return Promise.resolve(
      resolveApproval(this.db, id, status, resolvedBy, ttlSeconds),
    );
  }

  findActiveApproval(scope: string): Promise<Approval | null> {
    return Promise.resolve(findActiveApproval(this.db, scope));
  }

  // ── Audit log ───────────────────────────────────────────────────────────────
  appendAuditEntry(type: string, payload: object): Promise<AuditEntry> {
    return Promise.resolve(appendAuditEntry(this.db, type, payload));
  }

  listAudit(limit: number, offset: number): Promise<Record<string, unknown>[]> {
    return Promise.resolve(
      this.db
        .prepare("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ? OFFSET ?")
        .all(limit, offset) as Record<string, unknown>[],
    );
  }

  verifyAuditChain(): Promise<AuditVerifyResult> {
    return Promise.resolve(verifyAuditChain(this.db));
  }

  // ── Metrics ─────────────────────────────────────────────────────────────────
  metrics(): Promise<MetricsResult> {
    const db = this.db;
    const total = (
      db.prepare("SELECT COUNT(*) as n FROM incidents").get() as { n: number }
    ).n;
    const byAction = db
      .prepare("SELECT action, COUNT(*) as n FROM incidents GROUP BY action")
      .all() as { action: string; n: number }[];
    const byTool = db
      .prepare(
        "SELECT tool, COUNT(*) as n FROM incidents GROUP BY tool ORDER BY n DESC LIMIT 10",
      )
      .all() as { tool: string; n: number }[];
    const cutoff = new Date(Date.now() - 30 * 86400_000).toISOString();
    const byDay = db
      .prepare(
        `SELECT substr(timestamp, 1, 10) as day, COUNT(*) as n FROM incidents
         WHERE timestamp >= ?
         GROUP BY day ORDER BY day DESC`,
      )
      .all(cutoff) as { day: string; n: number }[];
    const pending = (
      db
        .prepare("SELECT COUNT(*) as n FROM approvals WHERE status = 'pending'")
        .get() as { n: number }
    ).n;
    const auditEntries = (
      db.prepare("SELECT COUNT(*) as n FROM audit_log").get() as { n: number }
    ).n;

    return Promise.resolve({
      total,
      byAction,
      byTool,
      byDay,
      pending,
      auditEntries,
    });
  }

  // ── Custom detectors ────────────────────────────────────────────────────────
  listCustomDetectors(): Promise<CustomDetectorRow[]> {
    const rows = this.db
      .prepare("SELECT * FROM custom_detectors ORDER BY created_at DESC")
      .all() as Record<string, unknown>[];
    return Promise.resolve(
      rows.map((r) => ({
        id: String(r["id"]),
        name: String(r["name"]),
        description: String(r["description"] ?? ""),
        regex: String(r["regex"]),
        severity: String(r["severity"]),
        action: String(r["action"]),
        created_at: String(r["created_at"]),
        examples: JSON.parse(
          (r["examples_json"] as string) || "[]",
        ) as string[],
      })),
    );
  }

  findCustomDetectorIdByRegex(regex: string): Promise<string | null> {
    const row = this.db
      .prepare("SELECT id FROM custom_detectors WHERE regex = ?")
      .get(regex) as { id: string } | undefined;
    return Promise.resolve(row?.id ?? null);
  }

  createCustomDetector(row: {
    id: string;
    name: string;
    description: string;
    regex: string;
    severity: string;
    action: string;
    createdAt: string;
    examples: string[];
  }): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO custom_detectors (id, name, description, regex, severity, action, created_at, examples_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        row.id,
        row.name,
        row.description,
        row.regex,
        row.severity,
        row.action,
        row.createdAt,
        JSON.stringify(row.examples),
      );
    return Promise.resolve();
  }

  deleteCustomDetector(id: string): Promise<boolean> {
    const row = this.db
      .prepare("SELECT id FROM custom_detectors WHERE id = ?")
      .get(id);
    if (!row) return Promise.resolve(false);
    this.db.prepare("DELETE FROM custom_detectors WHERE id = ?").run(id);
    return Promise.resolve(true);
  }

  // ── Agent ingest ────────────────────────────────────────────────────────────
  ingestAgentEvent(
    payload: AgentIngestPayload,
  ): Promise<{ incidentId: string }> {
    const { machine, incident, approval, auditType } = payload;

    // A approval entra primeiro: incidents.approval_id tem FK para approvals.
    if (approval) {
      this.db
        .prepare(
          `INSERT OR IGNORE INTO approvals(id, incident_id, scope, justification, status, token, requested_at, ttl_seconds)
           VALUES(?, ?, ?, ?, 'pending', ?, ?, ?)`,
        )
        .run(
          approval.id,
          incident.id,
          approval.scope,
          approval.justification,
          generateToken(),
          approval.requestedAt,
          approval.ttlSeconds,
        );
    }

    this.db
      .prepare(
        `INSERT OR IGNORE INTO incidents(id, timestamp, tool, session_id, username, hostname, context, data_types, severities, findings, action, approval_id)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        incident.id,
        incident.timestamp,
        incident.tool,
        incident.sessionId,
        machine.username,
        machine.hostname,
        incident.context,
        JSON.stringify(incident.dataTypes),
        JSON.stringify(incident.severities),
        JSON.stringify(incident.findings),
        incident.action,
        approval?.id ?? null,
      );

    appendAuditEntry(this.db, `agent-${auditType}`, {
      incidentId: incident.id,
      hostname: machine.hostname,
      username: machine.username,
      tool: incident.tool,
      dataTypes: incident.dataTypes,
      approvalId: approval?.id ?? null,
      ingestId: randomBytes(6).toString("hex"),
    });

    return Promise.resolve({ incidentId: incident.id });
  }

  // ── Fleet ───────────────────────────────────────────────────────────────────
  upsertMachine(payload: MachineHeartbeatPayload): Promise<void> {
    const now = new Date().toISOString();
    const ext = payload.extension ?? null;
    this.db
      .prepare(
        `INSERT INTO machines(hostname, username, guardian_version, config_hash,
                              extension_version, extension_last_seen, extract_failures, last_seen)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(hostname) DO UPDATE SET
           username            = excluded.username,
           guardian_version    = excluded.guardian_version,
           config_hash         = excluded.config_hash,
           extension_version   = CASE WHEN excluded.extension_version != ''
                                      THEN excluded.extension_version
                                      ELSE machines.extension_version END,
           extension_last_seen = CASE WHEN excluded.extension_last_seen != ''
                                      THEN excluded.extension_last_seen
                                      ELSE machines.extension_last_seen END,
           extract_failures    = CASE WHEN excluded.extension_version != ''
                                      THEN excluded.extract_failures
                                      ELSE machines.extract_failures END,
           last_seen           = excluded.last_seen`,
      )
      .run(
        payload.machine.hostname,
        payload.machine.username,
        payload.guardianVersion,
        payload.configHash,
        ext?.version ?? "",
        ext ? now : "",
        JSON.stringify(ext?.extractFailures ?? {}),
        now,
      );
    return Promise.resolve();
  }

  listMachines(): Promise<MachineRow[]> {
    const rows = this.db
      .prepare("SELECT * FROM machines ORDER BY last_seen DESC")
      .all() as Record<string, unknown>[];
    return Promise.resolve(rows.map(rowToMachine));
  }

  // ── Agent keys ──────────────────────────────────────────────────────────────
  createAgentKey(row: {
    id: string;
    machineId: string;
    keyHash: string;
    createdAt: string;
  }): Promise<void> {
    this.db
      .prepare(
        "INSERT INTO agent_keys(id, machine_id, key_hash, created_at) VALUES(?, ?, ?, ?)",
      )
      .run(row.id, row.machineId, row.keyHash, row.createdAt);
    return Promise.resolve();
  }

  findAgentKeyByHash(keyHash: string): Promise<AgentKeyRow | null> {
    const row = this.db
      .prepare("SELECT * FROM agent_keys WHERE key_hash = ?")
      .get(keyHash) as Record<string, unknown> | undefined;
    return Promise.resolve(row ? rowToAgentKey(row) : null);
  }

  revokeAgentKey(id: string): Promise<boolean> {
    const result = this.db
      .prepare(
        "UPDATE agent_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
      )
      .run(new Date().toISOString(), id);
    return Promise.resolve(result.changes > 0);
  }

  listAgentKeys(): Promise<AgentKeyRow[]> {
    const rows = this.db
      .prepare("SELECT * FROM agent_keys ORDER BY created_at DESC")
      .all() as Record<string, unknown>[];
    return Promise.resolve(rows.map(rowToAgentKey));
  }
}

function rowToAgentKey(row: Record<string, unknown>): AgentKeyRow {
  return {
    id: String(row["id"]),
    machineId: String(row["machine_id"]),
    createdAt: String(row["created_at"]),
    revokedAt: row["revoked_at"] != null ? String(row["revoked_at"]) : null,
  };
}

function rowToMachine(row: Record<string, unknown>): MachineRow {
  let extractFailures: Record<string, number> = {};
  try {
    extractFailures = JSON.parse(String(row["extract_failures"] ?? "{}"));
  } catch {
    // linha corrompida não pode derrubar a listagem da frota
  }
  return {
    hostname: String(row["hostname"]),
    username: String(row["username"] ?? ""),
    guardianVersion: String(row["guardian_version"] ?? ""),
    configHash: String(row["config_hash"] ?? ""),
    extensionVersion: String(row["extension_version"] ?? ""),
    extensionLastSeen: String(row["extension_last_seen"] ?? ""),
    extractFailures,
    lastSeen: String(row["last_seen"]),
  };
}
