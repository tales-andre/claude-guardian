import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { applySchema } from "../src/db/schema.ts";
import { handleConfigChange } from "../src/lib/config-change.ts";
import type { Config } from "../src/types/index.ts";

function makeDb() {
  const db = new Database(":memory:");
  applySchema(db);
  return db;
}

const NO_CENTRAL = {
  centralUrl: "",
  centralApiKey: "",
  dbPath: ":memory:",
} as Config;

describe("handleConfigChange", () => {
  it("records an incident and a config-change audit entry capturing the source", () => {
    const db = makeDb();
    const incident = handleConfigChange(db, NO_CENTRAL, {
      source: "user_settings",
    });

    expect(incident).not.toBeNull();
    expect(incident?.context).toContain("user_settings");
    expect(
      db.prepare("SELECT * FROM audit_log WHERE type = 'config-change'").all(),
    ).toHaveLength(1);
    db.close();
  });

  it("marks a managed policy_settings change as critical", () => {
    const db = makeDb();
    const incident = handleConfigChange(db, NO_CENTRAL, {
      source: "policy_settings",
    });

    expect(incident?.severities).toContain("critical");
    db.close();
  });

  it("falls back to 'unknown' when the source is absent", () => {
    const db = makeDb();
    const incident = handleConfigChange(db, NO_CENTRAL, {});

    expect(incident?.context).toContain("unknown");
    db.close();
  });
});
