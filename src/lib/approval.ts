import { createHash, randomBytes } from "node:crypto";
import type BetterSqlite3 from "better-sqlite3";
import type { Approval, ApprovalStatus, DataType } from "../types/index.ts";

export function buildScope(tool: string, dataTypes: DataType[]): string {
  const sorted = [...dataTypes].sort().join(",");
  return createHash("sha256")
    .update(`${tool.toLowerCase()}:${sorted}`)
    .digest("hex")
    .slice(0, 16);
}

export function generateToken(): string {
  return randomBytes(24).toString("hex");
}

export function createApproval(
  db: BetterSqlite3.Database,
  incidentId: string,
  scope: string,
  justification: string,
  ttlSeconds: number,
): Approval {
  const id = randomBytes(12).toString("hex");
  const token = generateToken();
  const requestedAt = new Date().toISOString();

  db.prepare<[string, string, string, string, string, string, number]>(
    `INSERT INTO approvals(id, incident_id, scope, justification, status, token, requested_at, ttl_seconds)
     VALUES(?, ?, ?, ?, 'pending', ?, ?, ?)`,
  ).run(id, incidentId, scope, justification, token, requestedAt, ttlSeconds);

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

export function resolveApproval(
  db: BetterSqlite3.Database,
  id: string,
  status: "approved" | "denied",
  resolvedBy: string,
  ttlSeconds?: number,
): Approval | null {
  const approval = db
    .prepare<[string], Approval>("SELECT * FROM approvals WHERE id = ?")
    .get(id);
  if (!approval) return null;

  // A linha vem crua do SQLite (snake_case), então o TTL persistido está em
  // ttl_seconds — approval.ttlSeconds só existe em objetos construídos em JS.
  const storedTtl = Number(
    (approval as unknown as Record<string, unknown>)["ttl_seconds"] ??
      approval.ttlSeconds ??
      3600,
  );
  const resolvedAt = new Date().toISOString();
  const expiresAt =
    status === "approved"
      ? new Date(Date.now() + (ttlSeconds ?? storedTtl) * 1000).toISOString()
      : null;

  db.prepare(
    `UPDATE approvals SET status = ?, resolved_at = ?, resolved_by = ?, expires_at = ?
     WHERE id = ?`,
  ).run(status, resolvedAt, resolvedBy, expiresAt, id);

  return {
    ...approval,
    status,
    resolvedAt,
    resolvedBy,
    expiresAt,
  };
}

export function findActiveApproval(
  db: BetterSqlite3.Database,
  scope: string,
): Approval | null {
  const now = new Date().toISOString();
  return (
    db
      .prepare<[string, string], Approval>(
        `SELECT * FROM approvals
         WHERE scope = ? AND status = 'approved' AND expires_at > ?
         ORDER BY expires_at DESC LIMIT 1`,
      )
      .get(scope, now) ?? null
  );
}

export function listApprovals(
  db: BetterSqlite3.Database,
  filter?: ApprovalStatus,
): Approval[] {
  if (filter) {
    return db
      .prepare<[string], Approval>(
        "SELECT * FROM approvals WHERE status = ? ORDER BY requested_at DESC",
      )
      .all(filter);
  }
  return db
    .prepare<[], Approval>("SELECT * FROM approvals ORDER BY requested_at DESC")
    .all();
}

export function getApprovalById(
  db: BetterSqlite3.Database,
  id: string,
): Approval | null {
  return (
    db
      .prepare<[string], Approval>("SELECT * FROM approvals WHERE id = ?")
      .get(id) ?? null
  );
}
