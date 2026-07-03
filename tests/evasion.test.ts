import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { applySchema } from "../src/db/schema.ts";
import { detectProviderEvasion, reportEvasion } from "../src/lib/evasion.ts";
import type { Config } from "../src/types/index.ts";

function makeDb() {
  const db = new Database(":memory:");
  applySchema(db);
  return db;
}

// Central desligado (centralUrl vazio) → reportToCentral é no-op, teste hermético.
const NO_CENTRAL = {
  centralUrl: "",
  centralApiKey: "",
  dbPath: ":memory:",
} as Config;

describe("detectProviderEvasion", () => {
  it("returns no findings for a clean environment", () => {
    expect(detectProviderEvasion({})).toEqual([]);
  });

  it("flags a custom ANTHROPIC_BASE_URL as an evasion signal", () => {
    const findings = detectProviderEvasion({
      ANTHROPIC_BASE_URL: "https://proxy.internal.example.com",
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.detectorId).toBe("provider-evasion");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.snippet).toContain("ANTHROPIC_BASE_URL");
  });

  it("flags CLAUDE_CODE_USE_BEDROCK when truthy", () => {
    const findings = detectProviderEvasion({ CLAUDE_CODE_USE_BEDROCK: "1" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.snippet).toContain("CLAUDE_CODE_USE_BEDROCK");
  });

  it("ignores a provider flag that is unset or falsy", () => {
    expect(detectProviderEvasion({ CLAUDE_CODE_USE_BEDROCK: "" })).toEqual([]);
    expect(detectProviderEvasion({ CLAUDE_CODE_USE_BEDROCK: "0" })).toEqual([]);
  });

  it("does not leak the raw env value (only the var name)", () => {
    const findings = detectProviderEvasion({
      ANTHROPIC_BASE_URL: "https://secret-proxy.example.com/abcd1234",
    });
    expect(findings[0]?.rawValue).not.toContain("abcd1234");
    expect(findings[0]?.snippet).not.toContain("abcd1234");
  });

  it("reports every active evasion vector at once", () => {
    const findings = detectProviderEvasion({
      ANTHROPIC_BASE_URL: "https://proxy.example.com",
      CLAUDE_CODE_USE_VERTEX: "true",
    });
    expect(findings).toHaveLength(2);
  });
});

describe("reportEvasion", () => {
  it("records an incident and a provider-evasion audit entry when a vector is present", () => {
    const db = makeDb();
    const incident = reportEvasion(db, NO_CENTRAL, {
      ANTHROPIC_BASE_URL: "https://x.example.com",
    });

    expect(incident).not.toBeNull();
    expect(db.prepare("SELECT * FROM incidents").all()).toHaveLength(1);
    expect(
      db
        .prepare("SELECT * FROM audit_log WHERE type = 'provider-evasion'")
        .all(),
    ).toHaveLength(1);
    db.close();
  });

  it("does nothing for a clean environment", () => {
    const db = makeDb();
    const incident = reportEvasion(db, NO_CENTRAL, {});

    expect(incident).toBeNull();
    expect(db.prepare("SELECT * FROM incidents").all()).toHaveLength(0);
    expect(db.prepare("SELECT * FROM audit_log").all()).toHaveLength(0);
    db.close();
  });
});
