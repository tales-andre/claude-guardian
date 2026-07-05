import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { getDb } from "../src/db/client.ts";
import { MCP_CALL_TOOL, scanMcp } from "../src/lib/mcp-scan.ts";
import type { Config, PolicyRule } from "../src/types/index.ts";

let tmpDir: string;
let dbPath: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-substitute-scan-"));
  dbPath = join(tmpDir, "test.db");
});
afterAll(() => rmSync(tmpDir, { recursive: true, force: true }));

const substitutePii: PolicyRule = {
  id: "sub-pii",
  name: "substitui PII por fictício",
  enabled: true,
  dataTypes: ["cpf", "email", "person-name"],
  action: "substitute",
};

function cfg(o: Partial<Config> = {}): Config {
  return {
    ...DEFAULT_CONFIG,
    dbPath,
    policies: [substitutePii],
    substitutionSalt: "test-salt",
    ...o,
  };
}

const CPF = "529.982.247-25";

describe("scanMcp — ação substitute (egress, mão única)", () => {
  it("reescreve args com fictício, mantém JSON válido e some o valor real", () => {
    const db = getDb(dbPath);
    const text = JSON.stringify({ msg: `Meu CPF é ${CPF}`, other: "ok" });
    const r = scanMcp(db, cfg(), {
      tool: MCP_CALL_TOOL,
      serverName: "http",
      toolName: "post",
      text,
    });
    expect(r.action).toBe("substitute");
    expect(r.substitutedText).toBeDefined();
    expect(r.substitutedText).not.toContain(CPF);
    // continua sendo JSON parseável (o proxy MCP reinjeta como arguments)
    const parsed = JSON.parse(r.substitutedText as string) as {
      msg: string;
      other: string;
    };
    expect(parsed.other).toBe("ok");
    expect(parsed.msg).not.toContain(CPF);
  });

  it("com entityDetection liga, substitui nome de pessoa que o regex não pega", () => {
    const db = getDb(dbPath);
    const text = JSON.stringify({ nota: "meu nome é Roberto Carlos" });
    const r = scanMcp(db, cfg({ entityDetection: true }), {
      tool: MCP_CALL_TOOL,
      serverName: "http",
      toolName: "post",
      text,
    });
    expect(r.action).toBe("substitute");
    expect(r.substitutedText).not.toContain("Roberto Carlos");
  });

  it("sem entityDetection, o nome não é detectado (comportamento local inalterado)", () => {
    const db = getDb(dbPath);
    const text = JSON.stringify({ nota: "meu nome é Roberto Carlos" });
    const r = scanMcp(db, cfg({ entityDetection: false }), {
      tool: MCP_CALL_TOOL,
      serverName: "http",
      toolName: "post",
      text,
    });
    expect(r.action).toBe("allow");
  });
});
