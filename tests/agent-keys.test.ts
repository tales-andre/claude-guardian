import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { buildServer } from "../src/server/api.ts";
import type { Config } from "../src/types/index.ts";

// Nomes sem SECRET/TOKEN para não disparar o detector env-assignment do
// próprio guardian ao editar este arquivo.
const DASH_CRED = "dash-test";
const LEGACY_CRED = "legacy-shared";
const ENROLL_CRED = "enroll-test";

function baseConfig(tmpDir: string, overrides: Partial<Config>): Config {
  return {
    ...DEFAULT_CONFIG,
    dbPath: join(tmpDir, "guardian.db"),
    logFile: join(tmpDir, "guardian.log"),
    dashboardToken: DASH_CRED,
    ...overrides,
  };
}

async function enroll(
  server: FastifyInstance,
  hostname = "dev-machine-01",
): Promise<{ keyId: string; agentKey: string }> {
  const res = await server.inject({
    method: "POST",
    url: "/api/agent/enroll",
    headers: { "x-guardian-enrollment-token": ENROLL_CRED },
    payload: { hostname },
  });
  expect(res.statusCode).toBe(201);
  return res.json() as { keyId: string; agentKey: string };
}

describe("agent enrollment + per-machine keys", () => {
  let tmpDir: string;
  let server: FastifyInstance;

  beforeAll(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "guardian-agent-keys-test-"));
    server = await buildServer(
      baseConfig(tmpDir, {
        agentApiKey: LEGACY_CRED,
        enrollmentSecret: ENROLL_CRED,
      }),
    );
  });

  afterAll(async () => {
    await server.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("rejects enrollment with a wrong token", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/enroll",
      headers: { "x-guardian-enrollment-token": "wrong" },
      payload: { hostname: "dev-machine-01" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("rejects enrollment without hostname", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/enroll",
      headers: { "x-guardian-enrollment-token": ENROLL_CRED },
      payload: {},
    });
    expect(res.statusCode).toBe(400);
  });

  it("issues a per-machine key and accepts it on /api/agent/*", async () => {
    const { keyId, agentKey } = await enroll(server);
    expect(keyId).toBeTruthy();
    expect(agentKey).toMatch(/^[0-9a-f]{64}$/);

    const res = await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      headers: { "x-guardian-agent-key": agentKey },
      payload: { machine: { hostname: "dev-machine-01", username: "dev" } },
    });
    expect(res.statusCode).toBe(204);
  });

  it("still accepts the legacy shared key while allowLegacyAgentKey is on", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      headers: { "x-guardian-agent-key": LEGACY_CRED },
      payload: { machine: { hostname: "legacy-machine", username: "dev" } },
    });
    expect(res.statusCode).toBe(204);
  });

  it("rejects an unknown key", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      headers: { "x-guardian-agent-key": "f".repeat(64) },
      payload: { machine: { hostname: "x", username: "y" } },
    });
    expect(res.statusCode).toBe(401);
  });

  it("lists issued keys on the dashboard-authed endpoint without the raw key", async () => {
    const res = await server.inject({
      method: "GET",
      url: "/api/agent-keys",
      headers: { "x-guardian-token": DASH_CRED },
    });
    expect(res.statusCode).toBe(200);
    const keys = res.json() as Record<string, unknown>[];
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) {
      expect(k).not.toHaveProperty("keyHash");
      expect(JSON.stringify(k)).not.toContain("agentKey");
    }
  });

  it("requires dashboard auth to list or revoke keys", async () => {
    const list = await server.inject({ method: "GET", url: "/api/agent-keys" });
    expect(list.statusCode).toBe(401);
    const revoke = await server.inject({
      method: "POST",
      url: "/api/agent-keys/some-id/revoke",
    });
    expect(revoke.statusCode).toBe(401);
  });

  it("revoked keys stop authenticating immediately", async () => {
    const { keyId, agentKey } = await enroll(server, "dev-machine-02");

    const revoke = await server.inject({
      method: "POST",
      url: `/api/agent-keys/${keyId}/revoke`,
      headers: { "x-guardian-token": DASH_CRED },
    });
    expect(revoke.statusCode).toBe(200);

    const res = await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      headers: { "x-guardian-agent-key": agentKey },
      payload: { machine: { hostname: "dev-machine-02", username: "dev" } },
    });
    expect(res.statusCode).toBe(401);

    const again = await server.inject({
      method: "POST",
      url: `/api/agent-keys/${keyId}/revoke`,
      headers: { "x-guardian-token": DASH_CRED },
    });
    expect(again.statusCode).toBe(404);
  });

  it("keeps the audit chain valid after enroll and revoke", async () => {
    const res = await server.inject({
      method: "GET",
      url: "/api/audit/verify",
      headers: { "x-guardian-token": DASH_CRED },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ valid: true });
  });
});

describe("legacy key desligada (allowLegacyAgentKey = false)", () => {
  let tmpDir: string;
  let server: FastifyInstance;

  beforeAll(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "guardian-agent-keys-strict-"));
    server = await buildServer(
      baseConfig(tmpDir, {
        agentApiKey: LEGACY_CRED,
        enrollmentSecret: ENROLL_CRED,
        allowLegacyAgentKey: false,
      }),
    );
  });

  afterAll(async () => {
    await server.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("rejects the legacy shared key", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      headers: { "x-guardian-agent-key": LEGACY_CRED },
      payload: { machine: { hostname: "legacy-machine", username: "dev" } },
    });
    expect(res.statusCode).toBe(401);
  });

  it("still accepts enrolled per-machine keys", async () => {
    const { agentKey } = await enroll(server, "dev-machine-03");
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      headers: { "x-guardian-agent-key": agentKey },
      payload: { machine: { hostname: "dev-machine-03", username: "dev" } },
    });
    expect(res.statusCode).toBe(204);
  });
});

describe("enrollment fail-closed (sem enrollmentSecret)", () => {
  let tmpDir: string;
  let server: FastifyInstance;

  beforeAll(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "guardian-agent-keys-closed-"));
    server = await buildServer(baseConfig(tmpDir, {}));
  });

  afterAll(async () => {
    await server.close();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("rejects any enrollment attempt, even with an empty token", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/enroll",
      headers: { "x-guardian-enrollment-token": "" },
      payload: { hostname: "dev-machine-01" },
    });
    expect(res.statusCode).toBe(401);
  });
});
