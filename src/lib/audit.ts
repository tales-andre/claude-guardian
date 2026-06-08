import { createHash } from "node:crypto";
import type BetterSqlite3 from "better-sqlite3";
import type { AuditEntry } from "../types/index.ts";

const GENESIS_HASH = "0".repeat(64);

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

export function appendAuditEntry(
  db: BetterSqlite3.Database,
  type: string,
  payload: object,
): AuditEntry {
  const payloadJson = JSON.stringify(payload);
  const timestamp = new Date().toISOString();

  const last = db
    .prepare<[], { seq: number; hash: string }>(
      "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1",
    )
    .get();

  const prevHash = last?.hash ?? GENESIS_HASH;

  // Use a placeholder seq to compute the hash, then insert.
  const placeholderSeq = (last?.seq ?? 0) + 1;
  const hash = computeHash(placeholderSeq, timestamp, type, payloadJson, prevHash);

  const result = db
    .prepare<[string, string, string, string, string]>(
      "INSERT INTO audit_log(timestamp, type, payload, prev_hash, hash) VALUES(?, ?, ?, ?, ?)",
    )
    .run(timestamp, type, payloadJson, prevHash, hash);

  return {
    seq: Number(result.lastInsertRowid),
    timestamp,
    type,
    payload: payloadJson,
    prevHash,
    hash,
  };
}

export function verifyAuditChain(
  db: BetterSqlite3.Database,
): { valid: boolean; firstTamperedSeq: number | null; totalEntries: number } {
  const entries = db
    .prepare<[], { seq: number; timestamp: string; type: string; payload: string; prev_hash: string; hash: string }>(
      "SELECT seq, timestamp, type, payload, prev_hash, hash FROM audit_log ORDER BY seq ASC",
    )
    .all();

  let expectedPrevHash = GENESIS_HASH;
  let firstTamperedSeq: number | null = null;

  for (const entry of entries) {
    if (entry.prev_hash !== expectedPrevHash) {
      firstTamperedSeq = entry.seq;
      break;
    }
    const computed = computeHash(
      entry.seq,
      entry.timestamp,
      entry.type,
      entry.payload,
      entry.prev_hash,
    );
    if (computed !== entry.hash) {
      firstTamperedSeq = entry.seq;
      break;
    }
    expectedPrevHash = entry.hash;
  }

  return {
    valid: firstTamperedSeq === null,
    firstTamperedSeq,
    totalEntries: entries.length,
  };
}
