import { createHash, randomBytes } from "node:crypto";
import pg from "pg";
import { generateToken } from "../lib/approval.ts";
import type {
  AgentIngestPayload,
  AgentKeyRow,
  Approval,
  ApprovalStatus,
  AuditEntry,
  DataType,
  Incident,
  MachineHeartbeatPayload,
  MachineRow,
  PolicyAction,
  Severity,
} from "../types/index.ts";
import type {
  AuditVerifyResult,
  CustomDetectorRow,
  GuardianStore,
  MetricsResult,
} from "./store.ts";

const GENESIS_HASH = "0".repeat(64);

// Mesma fórmula de src/lib/audit.ts — a cadeia central é verificável com a
// mesma lógica usada no modo local.
function computeHash(
  seq: number,
  timestamp: string,
  type: string,
  payload: string,
  prevHash: string,
): string {
  const data = `${seq}|${timestamp}|${type}|${payload}|${prevHash}`;
  return createHash("sha256").update(data, "utf8").digest("hex");
}

// Schema espelhado do SQLite (src/db/schema.ts). Timestamps ficam como TEXT
// ISO-8601 para manter a mesma semântica de ordenação/comparação dos hooks.
const PG_DDL = `
CREATE TABLE IF NOT EXISTS incidents (
  rid         BIGSERIAL,
  id          TEXT PRIMARY KEY,
  timestamp   TEXT NOT NULL,
  tool        TEXT NOT NULL,
  session_id  TEXT NOT NULL DEFAULT '',
  username    TEXT NOT NULL DEFAULT '',
  hostname    TEXT NOT NULL DEFAULT '',
  context     TEXT NOT NULL,
  data_types  TEXT NOT NULL,
  severities  TEXT NOT NULL,
  findings    TEXT NOT NULL,
  action      TEXT NOT NULL,
  approval_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_action    ON incidents(action);
CREATE INDEX IF NOT EXISTS idx_incidents_tool      ON incidents(tool);

CREATE TABLE IF NOT EXISTS audit_log (
  seq       BIGINT PRIMARY KEY,
  timestamp TEXT   NOT NULL,
  type      TEXT   NOT NULL,
  payload   TEXT   NOT NULL,
  prev_hash TEXT   NOT NULL,
  hash      TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  id            TEXT    PRIMARY KEY,
  incident_id   TEXT    NOT NULL,
  scope         TEXT    NOT NULL,
  justification TEXT    NOT NULL,
  status        TEXT    NOT NULL DEFAULT 'pending',
  token         TEXT    NOT NULL UNIQUE,
  requested_at  TEXT    NOT NULL,
  resolved_at   TEXT,
  resolved_by   TEXT,
  ttl_seconds   INTEGER NOT NULL DEFAULT 3600,
  expires_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_scope_status ON approvals(scope, status);
CREATE INDEX IF NOT EXISTS idx_approvals_expires_at   ON approvals(expires_at);
CREATE INDEX IF NOT EXISTS idx_approvals_status       ON approvals(status);

CREATE TABLE IF NOT EXISTS custom_detectors (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  description   TEXT NOT NULL DEFAULT '',
  regex         TEXT NOT NULL UNIQUE,
  severity      TEXT NOT NULL DEFAULT 'high',
  action        TEXT NOT NULL DEFAULT 'block',
  created_at    TEXT NOT NULL,
  examples_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS agent_keys (
  id         TEXT PRIMARY KEY,
  machine_id TEXT NOT NULL,
  key_hash   TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_keys_hash ON agent_keys(key_hash);

CREATE TABLE IF NOT EXISTS machines (
  hostname            TEXT PRIMARY KEY,
  username            TEXT NOT NULL DEFAULT '',
  guardian_version    TEXT NOT NULL DEFAULT '',
  config_hash         TEXT NOT NULL DEFAULT '',
  extension_version   TEXT NOT NULL DEFAULT '',
  extension_last_seen TEXT NOT NULL DEFAULT '',
  extract_failures    TEXT NOT NULL DEFAULT '{}',
  last_seen           TEXT NOT NULL
);
`;

// Lock advisory usado para serializar appends na audit chain (hash depende do
// seq anterior). 7734 = porta padrão do dashboard, só para ser reconhecível.
const AUDIT_LOCK_KEY = 7734;

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

export class PgStore implements GuardianStore {
  readonly kind = "postgres" as const;
  private pool: pg.Pool;

  constructor(databaseUrl: string) {
    this.pool = new pg.Pool({ connectionString: databaseUrl, max: 10 });
  }

  async init(): Promise<void> {
    await this.pool.query(PG_DDL);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // ── Incidents ───────────────────────────────────────────────────────────────
  async listIncidents(limit: number, offset: number): Promise<Incident[]> {
    const { rows } = await this.pool.query(
      "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
      [limit, offset],
    );
    return rows.map(rowToIncident);
  }

  async getIncidentById(id: string): Promise<Incident | null> {
    const { rows } = await this.pool.query(
      "SELECT * FROM incidents WHERE id = $1",
      [id],
    );
    return rows[0] ? rowToIncident(rows[0]) : null;
  }

  async latestIncidentMark(): Promise<number> {
    const { rows } = await this.pool.query(
      "SELECT COALESCE(MAX(rid), 0) AS m FROM incidents",
    );
    return Number(rows[0]?.m ?? 0);
  }

  // ── Approvals ───────────────────────────────────────────────────────────────
  // Retorna as linhas cruas (snake_case), igual ao modo SQLite — o dashboard
  // consome esse formato.
  async listApprovals(status?: ApprovalStatus): Promise<Approval[]> {
    const { rows } = status
      ? await this.pool.query(
          "SELECT * FROM approvals WHERE status = $1 ORDER BY requested_at DESC",
          [status],
        )
      : await this.pool.query(
          "SELECT * FROM approvals ORDER BY requested_at DESC",
        );
    return rows as Approval[];
  }

  async getApprovalById(id: string): Promise<Approval | null> {
    const { rows } = await this.pool.query(
      "SELECT * FROM approvals WHERE id = $1",
      [id],
    );
    return (rows[0] as Approval | undefined) ?? null;
  }

  async createApproval(
    incidentId: string,
    scope: string,
    justification: string,
    ttlSeconds: number,
  ): Promise<Approval> {
    const id = randomBytes(12).toString("hex");
    const token = generateToken();
    const requestedAt = new Date().toISOString();
    await this.pool.query(
      `INSERT INTO approvals(id, incident_id, scope, justification, status, token, requested_at, ttl_seconds)
       VALUES($1, $2, $3, $4, 'pending', $5, $6, $7)`,
      [id, incidentId, scope, justification, token, requestedAt, ttlSeconds],
    );
    return {
      id,
      incidentId,
      scope,
      justification,
      status: "pending",
      token,
      requestedAt,
      resolvedAt: null,
      resolvedBy: null,
      ttlSeconds,
      expiresAt: null,
    };
  }

  async resolveApproval(
    id: string,
    status: "approved" | "denied",
    resolvedBy: string,
    ttlSeconds?: number,
  ): Promise<Approval | null> {
    const existing = await this.getApprovalById(id);
    if (!existing) return null;

    const row = existing as unknown as Record<string, unknown>;
    const baseTtl = Number(row["ttl_seconds"] ?? 3600);
    const resolvedAt = new Date().toISOString();
    const expiresAt =
      status === "approved"
        ? new Date(Date.now() + (ttlSeconds ?? baseTtl) * 1000).toISOString()
        : null;

    await this.pool.query(
      `UPDATE approvals SET status = $1, resolved_at = $2, resolved_by = $3, expires_at = $4
       WHERE id = $5`,
      [status, resolvedAt, resolvedBy, expiresAt, id],
    );
    return (await this.getApprovalById(id)) as Approval;
  }

  async findActiveApproval(scope: string): Promise<Approval | null> {
    const now = new Date().toISOString();
    const { rows } = await this.pool.query(
      `SELECT * FROM approvals
       WHERE scope = $1 AND status = 'approved' AND expires_at > $2
       ORDER BY expires_at DESC LIMIT 1`,
      [scope, now],
    );
    return (rows[0] as Approval | undefined) ?? null;
  }

  // ── Audit log ───────────────────────────────────────────────────────────────
  async appendAuditEntry(type: string, payload: object): Promise<AuditEntry> {
    const payloadJson = JSON.stringify(payload);
    const timestamp = new Date().toISOString();

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1)", [AUDIT_LOCK_KEY]);
      const { rows } = await client.query(
        "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1",
      );
      const last = rows[0] as
        | { seq: string | number; hash: string }
        | undefined;
      const prevHash = last?.hash ?? GENESIS_HASH;
      const seq = Number(last?.seq ?? 0) + 1;
      const hash = computeHash(seq, timestamp, type, payloadJson, prevHash);

      await client.query(
        "INSERT INTO audit_log(seq, timestamp, type, payload, prev_hash, hash) VALUES($1, $2, $3, $4, $5, $6)",
        [seq, timestamp, type, payloadJson, prevHash, hash],
      );
      await client.query("COMMIT");
      return { seq, timestamp, type, payload: payloadJson, prevHash, hash };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  async listAudit(
    limit: number,
    offset: number,
  ): Promise<Record<string, unknown>[]> {
    const { rows } = await this.pool.query(
      "SELECT * FROM audit_log ORDER BY seq DESC LIMIT $1 OFFSET $2",
      [limit, offset],
    );
    return rows as Record<string, unknown>[];
  }

  async verifyAuditChain(): Promise<AuditVerifyResult> {
    const { rows } = await this.pool.query(
      "SELECT seq, timestamp, type, payload, prev_hash, hash FROM audit_log ORDER BY seq ASC",
    );

    let expectedPrevHash = GENESIS_HASH;
    let firstTamperedSeq: number | null = null;

    for (const entry of rows as {
      seq: string | number;
      timestamp: string;
      type: string;
      payload: string;
      prev_hash: string;
      hash: string;
    }[]) {
      const seq = Number(entry.seq);
      if (entry.prev_hash !== expectedPrevHash) {
        firstTamperedSeq = seq;
        break;
      }
      const computed = computeHash(
        seq,
        entry.timestamp,
        entry.type,
        entry.payload,
        entry.prev_hash,
      );
      if (computed !== entry.hash) {
        firstTamperedSeq = seq;
        break;
      }
      expectedPrevHash = entry.hash;
    }

    return {
      valid: firstTamperedSeq === null,
      firstTamperedSeq,
      totalEntries: rows.length,
    };
  }

  // ── Metrics ─────────────────────────────────────────────────────────────────
  async metrics(): Promise<MetricsResult> {
    const cutoff = new Date(Date.now() - 30 * 86400_000).toISOString();
    const [total, byAction, byTool, byDay, pending, auditEntries] =
      await Promise.all([
        this.pool.query("SELECT COUNT(*)::int AS n FROM incidents"),
        this.pool.query(
          "SELECT action, COUNT(*)::int AS n FROM incidents GROUP BY action",
        ),
        this.pool.query(
          "SELECT tool, COUNT(*)::int AS n FROM incidents GROUP BY tool ORDER BY n DESC LIMIT 10",
        ),
        this.pool.query(
          `SELECT substr(timestamp, 1, 10) AS day, COUNT(*)::int AS n FROM incidents
           WHERE timestamp >= $1 GROUP BY day ORDER BY day DESC`,
          [cutoff],
        ),
        this.pool.query(
          "SELECT COUNT(*)::int AS n FROM approvals WHERE status = 'pending'",
        ),
        this.pool.query("SELECT COUNT(*)::int AS n FROM audit_log"),
      ]);

    return {
      total: total.rows[0].n,
      byAction: byAction.rows,
      byTool: byTool.rows,
      byDay: byDay.rows,
      pending: pending.rows[0].n,
      auditEntries: auditEntries.rows[0].n,
    };
  }

  // ── Custom detectors ────────────────────────────────────────────────────────
  async listCustomDetectors(): Promise<CustomDetectorRow[]> {
    const { rows } = await this.pool.query(
      "SELECT * FROM custom_detectors ORDER BY created_at DESC",
    );
    return (rows as Record<string, unknown>[]).map((r) => ({
      id: String(r["id"]),
      name: String(r["name"]),
      description: String(r["description"] ?? ""),
      regex: String(r["regex"]),
      severity: String(r["severity"]),
      action: String(r["action"]),
      created_at: String(r["created_at"]),
      examples: JSON.parse((r["examples_json"] as string) || "[]") as string[],
    }));
  }

  async findCustomDetectorIdByRegex(regex: string): Promise<string | null> {
    const { rows } = await this.pool.query(
      "SELECT id FROM custom_detectors WHERE regex = $1",
      [regex],
    );
    return rows[0]?.id ?? null;
  }

  async createCustomDetector(row: {
    id: string;
    name: string;
    description: string;
    regex: string;
    severity: string;
    action: string;
    createdAt: string;
    examples: string[];
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO custom_detectors (id, name, description, regex, severity, action, created_at, examples_json)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        row.id,
        row.name,
        row.description,
        row.regex,
        row.severity,
        row.action,
        row.createdAt,
        JSON.stringify(row.examples),
      ],
    );
  }

  async deleteCustomDetector(id: string): Promise<boolean> {
    const result = await this.pool.query(
      "DELETE FROM custom_detectors WHERE id = $1",
      [id],
    );
    return (result.rowCount ?? 0) > 0;
  }

  // ── Agent ingest ────────────────────────────────────────────────────────────
  async ingestAgentEvent(
    payload: AgentIngestPayload,
  ): Promise<{ incidentId: string }> {
    const { machine, incident, approval, auditType } = payload;

    // Mesma ordem do SQLite: approval antes do incidente que a referencia.
    if (approval) {
      await this.pool.query(
        `INSERT INTO approvals(id, incident_id, scope, justification, status, token, requested_at, ttl_seconds)
         VALUES($1, $2, $3, $4, 'pending', $5, $6, $7)
         ON CONFLICT (id) DO NOTHING`,
        [
          approval.id,
          incident.id,
          approval.scope,
          approval.justification,
          generateToken(),
          approval.requestedAt,
          approval.ttlSeconds,
        ],
      );
    }

    await this.pool.query(
      `INSERT INTO incidents(id, timestamp, tool, session_id, username, hostname, context, data_types, severities, findings, action, approval_id)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       ON CONFLICT (id) DO NOTHING`,
      [
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
      ],
    );

    await this.appendAuditEntry(`agent-${auditType}`, {
      incidentId: incident.id,
      hostname: machine.hostname,
      username: machine.username,
      tool: incident.tool,
      dataTypes: incident.dataTypes,
      approvalId: approval?.id ?? null,
    });

    return { incidentId: incident.id };
  }

  // ── Fleet ───────────────────────────────────────────────────────────────────
  async upsertMachine(payload: MachineHeartbeatPayload): Promise<void> {
    const now = new Date().toISOString();
    const ext = payload.extension ?? null;
    await this.pool.query(
      `INSERT INTO machines(hostname, username, guardian_version, config_hash,
                            extension_version, extension_last_seen, extract_failures, last_seen)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (hostname) DO UPDATE SET
         username            = EXCLUDED.username,
         guardian_version    = EXCLUDED.guardian_version,
         config_hash         = EXCLUDED.config_hash,
         extension_version   = CASE WHEN EXCLUDED.extension_version != ''
                                    THEN EXCLUDED.extension_version
                                    ELSE machines.extension_version END,
         extension_last_seen = CASE WHEN EXCLUDED.extension_last_seen != ''
                                    THEN EXCLUDED.extension_last_seen
                                    ELSE machines.extension_last_seen END,
         extract_failures    = CASE WHEN EXCLUDED.extension_version != ''
                                    THEN EXCLUDED.extract_failures
                                    ELSE machines.extract_failures END,
         last_seen           = EXCLUDED.last_seen`,
      [
        payload.machine.hostname,
        payload.machine.username,
        payload.guardianVersion,
        payload.configHash,
        ext?.version ?? "",
        ext ? now : "",
        JSON.stringify(ext?.extractFailures ?? {}),
        now,
      ],
    );
  }

  async listMachines(): Promise<MachineRow[]> {
    const res = await this.pool.query(
      "SELECT * FROM machines ORDER BY last_seen DESC",
    );
    return (res.rows as Record<string, unknown>[]).map((row) => {
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
    });
  }

  // ── Agent keys ──────────────────────────────────────────────────────────────
  async createAgentKey(row: {
    id: string;
    machineId: string;
    keyHash: string;
    createdAt: string;
  }): Promise<void> {
    await this.pool.query(
      "INSERT INTO agent_keys(id, machine_id, key_hash, created_at) VALUES($1, $2, $3, $4)",
      [row.id, row.machineId, row.keyHash, row.createdAt],
    );
  }

  async findAgentKeyByHash(keyHash: string): Promise<AgentKeyRow | null> {
    const { rows } = await this.pool.query(
      "SELECT * FROM agent_keys WHERE key_hash = $1",
      [keyHash],
    );
    return rows[0] ? rowToAgentKey(rows[0]) : null;
  }

  async revokeAgentKey(id: string): Promise<boolean> {
    const result = await this.pool.query(
      "UPDATE agent_keys SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL",
      [new Date().toISOString(), id],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async listAgentKeys(): Promise<AgentKeyRow[]> {
    const { rows } = await this.pool.query(
      "SELECT * FROM agent_keys ORDER BY created_at DESC",
    );
    return (rows as Record<string, unknown>[]).map(rowToAgentKey);
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
