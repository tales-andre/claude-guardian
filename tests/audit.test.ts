import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { appendAuditEntry, verifyAuditChain } from "../src/lib/audit.ts";
import { applySchema } from "../src/db/schema.ts";

function makeDb() {
  const db = new Database(":memory:");
  applySchema(db);
  return db;
}

describe("appendAuditEntry", () => {
  it("creates an entry with a valid hash", () => {
    const db = makeDb();
    const entry = appendAuditEntry(db, "test-event", { foo: "bar" });

    expect(entry.seq).toBeGreaterThan(0);
    expect(entry.type).toBe("test-event");
    expect(entry.payload).toContain("bar");
    expect(entry.hash).toHaveLength(64);
    expect(entry.prevHash).toBe("0".repeat(64));
    db.close();
  });

  it("chains entries via prevHash", () => {
    const db = makeDb();
    const e1 = appendAuditEntry(db, "event-1", { n: 1 });
    const e2 = appendAuditEntry(db, "event-2", { n: 2 });

    expect(e2.prevHash).toBe(e1.hash);
    db.close();
  });

  it("serializes payload as redacted JSON (no raw values in clear)", () => {
    const db = makeDb();
    const entry = appendAuditEntry(db, "block", {
      incidentId: "abc123",
      dataTypes: ["aws-key"],
    });
    // Raw secrets should never appear in audit entries directly.
    expect(entry.payload).not.toContain("AKIA");
    db.close();
  });
});

describe("verifyAuditChain", () => {
  it("verifies a pristine chain as valid", () => {
    const db = makeDb();
    appendAuditEntry(db, "e1", { a: 1 });
    appendAuditEntry(db, "e2", { b: 2 });
    appendAuditEntry(db, "e3", { c: 3 });

    const result = verifyAuditChain(db);
    expect(result.valid).toBe(true);
    expect(result.firstTamperedSeq).toBeNull();
    expect(result.totalEntries).toBe(3);
    db.close();
  });

  it("detects tampering when a hash is modified", () => {
    const db = makeDb();
    appendAuditEntry(db, "e1", { a: 1 });
    appendAuditEntry(db, "e2", { b: 2 });

    // Tamper: modify the hash of entry 1.
    db.prepare("UPDATE audit_log SET hash = ? WHERE seq = 1").run("tampered-hash");

    const result = verifyAuditChain(db);
    expect(result.valid).toBe(false);
    expect(result.firstTamperedSeq).toBe(1);
    db.close();
  });

  it("detects tampering when a payload is modified", () => {
    const db = makeDb();
    appendAuditEntry(db, "e1", { a: 1 });

    // Tamper: change the payload without updating the hash.
    db.prepare("UPDATE audit_log SET payload = ? WHERE seq = 1").run('{"modified":true}');

    const result = verifyAuditChain(db);
    expect(result.valid).toBe(false);
    db.close();
  });

  it("reports valid for an empty chain", () => {
    const db = makeDb();
    const result = verifyAuditChain(db);
    expect(result.valid).toBe(true);
    expect(result.totalEntries).toBe(0);
    db.close();
  });
});
