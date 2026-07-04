import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { getDb } from "../src/db/client.ts";
import { MCP_CALL_TOOL, MCP_RESULT_TOOL, scanMcp } from "../src/lib/mcp-scan.ts";
import type { Config } from "../src/types/index.ts";

let tmpDir: string;
let dbPath: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-mcp-scan-"));
  dbPath = join(tmpDir, "test.db");
});
afterAll(() => rmSync(tmpDir, { recursive: true, force: true }));
function cfg(o: Partial<Config> = {}): Config {
  return { ...DEFAULT_CONFIG, dbPath, ...o };
}
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

describe("scanMcp", () => {
  it("allows clean tool-call args", () => {
    const db = getDb(dbPath);
    const r = scanMcp(db, cfg(), {
      tool: MCP_CALL_TOOL,
      serverName: "fs",
      toolName: "read_file",
      text: JSON.stringify({ path: "/etc/hosts" }),
    });
    expect(r.action).toBe("allow");
    expect(r.findings).toHaveLength(0);
  });

  it("blocks a secret in tool-call args", () => {
    const db = getDb(dbPath);
    const r = scanMcp(db, cfg(), {
      tool: MCP_CALL_TOOL,
      serverName: "http",
      toolName: "post",
      text: JSON.stringify({ body: `key=${AWS_KEY}` }),
    });
    expect(r.action).toBe("block");
    expect(r.findings.some((f) => f.dataType === "aws-key")).toBe(true);
  });

  it("blocks a secret in tool results (ingress)", () => {
    const db = getDb(dbPath);
    const r = scanMcp(db, cfg(), {
      tool: MCP_RESULT_TOOL,
      serverName: "fs",
      toolName: "read_file",
      text: `content: ${AWS_KEY}`,
    });
    expect(r.action).toBe("block");
  });
});
