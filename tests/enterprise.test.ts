import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { buildServer } from "../src/server/api.ts";
import type { AgentIngestPayload, Config } from "../src/types/index.ts";

const AGENT_KEY = "agent-key-test";
const DASH_TOKEN = "dash-token-test";

let tmpDir: string;
let server: FastifyInstance;

function ingestPayload(
  overrides: Partial<AgentIngestPayload["incident"]> = {},
  approval: AgentIngestPayload["approval"] = null,
): AgentIngestPayload {
  return {
    machine: { hostname: "dev-laptop-42", username: "alice" },
    incident: {
      id: "inc-0001",
      timestamp: new Date().toISOString(),
      tool: "UserPromptSubmit",
      sessionId: "sess-1",
      context: "UserPromptSubmit: detected AWS Access Key",
      dataTypes: ["aws-key"],
      severities: ["critical"],
      findings: [
        {
          detectorId: "aws-access-key",
          label: "AWS Access Key",
          dataType: "aws-key",
          severity: "critical",
          snippet: "AKIA…REDACTED",
          confidence: 0.99,
        },
      ],
      action: "block",
      ...overrides,
    },
    approval,
    auditType: "block",
  };
}

beforeAll(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-enterprise-test-"));
  const config: Config = {
    ...DEFAULT_CONFIG,
    dbPath: join(tmpDir, "guardian.db"),
    logFile: join(tmpDir, "guardian.log"),
    dashboardToken: DASH_TOKEN,
    agentApiKey: AGENT_KEY,
  };
  server = await buildServer(config);
});

afterAll(async () => {
  await server.close();
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("agent ingest endpoint", () => {
  it("rejects requests without the agent key", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/ingest",
      payload: ingestPayload(),
    });
    expect(res.statusCode).toBe(401);
  });

  it("rejects requests with a wrong agent key", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/ingest",
      headers: { "x-guardian-agent-key": "wrong" },
      payload: ingestPayload(),
    });
    expect(res.statusCode).toBe(401);
  });

  it("accepts a valid payload and stores the incident with machine info", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/ingest",
      headers: { "x-guardian-agent-key": AGENT_KEY },
      payload: ingestPayload(),
    });
    expect(res.statusCode).toBe(201);

    const list = await server.inject({
      method: "GET",
      url: "/api/incidents",
      headers: { "x-guardian-token": DASH_TOKEN },
    });
    const incidents = list.json() as Array<Record<string, unknown>>;
    expect(incidents.length).toBe(1);
    expect(incidents[0]?.["username"]).toBe("alice");
    expect(incidents[0]?.["hostname"]).toBe("dev-laptop-42");
    // rawValue não deve existir nos findings persistidos
    expect(String(incidents[0]?.["findingsJson"])).not.toContain("rawValue");
  });

  it("is idempotent on incident id (re-delivery does not duplicate)", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/ingest",
      headers: { "x-guardian-agent-key": AGENT_KEY },
      payload: ingestPayload(),
    });
    expect(res.statusCode).toBe(201);

    const list = await server.inject({
      method: "GET",
      url: "/api/incidents",
      headers: { "x-guardian-token": DASH_TOKEN },
    });
    expect((list.json() as unknown[]).length).toBe(1);
  });

  it("rejects malformed payloads with 400", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/ingest",
      headers: { "x-guardian-agent-key": AGENT_KEY },
      payload: { foo: "bar" },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe("central approval flow", () => {
  const SCOPE = "abcdef0123456789";

  it("mirrors a pending approval from the agent", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/ingest",
      headers: { "x-guardian-agent-key": AGENT_KEY },
      payload: ingestPayload({ id: "inc-0002", action: "require-approval" }, {
        id: "appr-0001",
        scope: SCOPE,
        justification: "preciso testar a integração",
        ttlSeconds: 3600,
        requestedAt: new Date().toISOString(),
      }),
    });
    expect(res.statusCode).toBe(201);

    const pending = await server.inject({
      method: "GET",
      url: "/api/approvals?status=pending",
      headers: { "x-guardian-token": DASH_TOKEN },
    });
    const rows = pending.json() as Array<Record<string, unknown>>;
    expect(rows.some((r) => r["id"] === "appr-0001")).toBe(true);
  });

  it("returns no active approval before the admin approves", async () => {
    const res = await server.inject({
      method: "GET",
      url: `/api/agent/approvals/active?scope=${SCOPE}`,
      headers: { "x-guardian-agent-key": AGENT_KEY },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { approval: unknown }).approval).toBeNull();
  });

  it("returns the active approval after the admin approves on the dashboard", async () => {
    const resolve = await server.inject({
      method: "POST",
      url: "/api/approvals/appr-0001/resolve",
      headers: { "x-guardian-token": DASH_TOKEN },
      payload: { status: "approved", resolvedBy: "admin" },
    });
    expect(resolve.statusCode).toBe(200);

    const res = await server.inject({
      method: "GET",
      url: `/api/agent/approvals/active?scope=${SCOPE}`,
      headers: { "x-guardian-agent-key": AGENT_KEY },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { approval: unknown }).approval).not.toBeNull();
  });

  it("keeps the central audit chain valid after agent ingests", async () => {
    const res = await server.inject({
      method: "GET",
      url: "/api/audit/verify",
      headers: { "x-guardian-token": DASH_TOKEN },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { valid: boolean }).valid).toBe(true);
  });
});
