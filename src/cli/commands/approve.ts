import { loadConfig } from "../../config/loader.ts";
import { getDb } from "../../db/client.ts";
import {
  buildScope,
  createApproval,
  listApprovals,
  resolveApproval,
} from "../../lib/approval.ts";
import { appendAuditEntry } from "../../lib/audit.ts";
import { getIncidentById } from "../../lib/incident.ts";

interface ApproveOptions {
  reason: string;
  ttl?: string;
  config?: string;
}

export async function cmdApprove(
  incidentId: string,
  opts: ApproveOptions,
): Promise<void> {
  const config = loadConfig(opts.config);
  const db = getDb(config.dbPath);

  const incident = getIncidentById(db, incidentId);
  if (!incident) {
    process.stderr.write(`Error: incident '${incidentId}' not found.\n`);
    process.exit(1);
  }

  const ttlSeconds = opts.ttl ? parseInt(opts.ttl, 10) : 3600;
  const scope = buildScope(incident.tool, incident.dataTypes);

  const existing = listApprovals(db, "pending").find(
    (a) => a.incidentId === incidentId,
  );

  let approvalId: string;
  if (existing) {
    const resolved = resolveApproval(
      db,
      existing.id,
      "approved",
      "cli",
      ttlSeconds,
    );
    if (!resolved) {
      process.stderr.write("Error: failed to resolve approval.\n");
      process.exit(1);
    }
    approvalId = existing.id;
  } else {
    const approval = createApproval(
      db,
      incidentId,
      scope,
      opts.reason,
      ttlSeconds,
    );
    const resolved = resolveApproval(
      db,
      approval.id,
      "approved",
      "cli",
      ttlSeconds,
    );
    if (!resolved) {
      process.stderr.write("Error: failed to create and resolve approval.\n");
      process.exit(1);
    }
    approvalId = approval.id;
  }

  appendAuditEntry(db, "approval-granted", {
    approvalId,
    incidentId,
    scope,
    ttlSeconds,
    reason: opts.reason,
    resolvedBy: "cli",
  });

  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
  console.log(`✓ Exception approved for incident ${incidentId}`);
  console.log(`  Scope:   ${scope}`);
  console.log(`  TTL:     ${ttlSeconds}s`);
  console.log(`  Expires: ${expiresAt.toISOString()}`);
  console.log(
    "\nThe next request with the same tool and data types will be allowed.",
  );
}

interface DenyOptions {
  reason?: string;
  config?: string;
}

export async function cmdDeny(
  incidentId: string,
  opts: DenyOptions,
): Promise<void> {
  const config = loadConfig(opts.config);
  const db = getDb(config.dbPath);

  const incident = getIncidentById(db, incidentId);
  if (!incident) {
    process.stderr.write(`Error: incident '${incidentId}' not found.\n`);
    process.exit(1);
  }

  const pending = listApprovals(db, "pending").find(
    (a) => a.incidentId === incidentId,
  );

  if (!pending) {
    process.stderr.write(
      `No pending approval found for incident ${incidentId}.\n`,
    );
    process.exit(1);
  }

  const resolved = resolveApproval(db, pending.id, "denied", "cli");
  if (!resolved) {
    process.stderr.write("Error: failed to deny approval.\n");
    process.exit(1);
  }

  appendAuditEntry(db, "approval-denied", {
    approvalId: pending.id,
    incidentId,
    reason: opts.reason ?? "",
    resolvedBy: "cli",
  });

  console.log(`✓ Approval denied for incident ${incidentId}`);
}
