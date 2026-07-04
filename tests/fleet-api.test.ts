import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { buildServer } from "../src/server/api.ts";
import type { Config, MachineHeartbeatPayload } from "../src/types/index.ts";

const AGENT_KEY = "agent-key-fleet";
const DASH_TOKEN = "dash-token-fleet";

let tmpDir: string;
let server: FastifyInstance;

function heartbeat(
  overrides: Partial<MachineHeartbeatPayload> = {},
): MachineHeartbeatPayload {
  return {
    machine: { hostname: "dev-laptop-7", username: "bob" },
    guardianVersion: "1.2.3",
    configHash: "hash-esperado",
    extension: { version: "0.2.0", extractFailures: { "chatgpt.com": 2 } },
    ...overrides,
  };
}

beforeAll(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-fleet-test-"));
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

describe("POST /api/agent/heartbeat", () => {
  it("rejeita sem chave de agente", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      payload: heartbeat(),
    });
    expect(res.statusCode).toBe(401);
  });

  it("400 sem hostname", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      headers: { "x-guardian-agent-key": AGENT_KEY },
      payload: { machine: {} },
    });
    expect(res.statusCode).toBe(400);
  });

  it("registra o heartbeat (idempotente por hostname)", async () => {
    for (let i = 0; i < 2; i++) {
      const res = await server.inject({
        method: "POST",
        url: "/api/agent/heartbeat",
        headers: { "x-guardian-agent-key": AGENT_KEY },
        payload: heartbeat(),
      });
      expect(res.statusCode).toBe(204);
    }
  });
});

describe("GET /api/fleet", () => {
  it("exige token de dashboard", async () => {
    const res = await server.inject({ method: "GET", url: "/api/fleet" });
    expect(res.statusCode).toBe(401);
  });

  it("lista a máquina com status healthy quando o hash bate", async () => {
    const res = await server.inject({
      method: "GET",
      url: "/api/fleet?expectedHash=hash-esperado&extensionRequired=1",
      headers: { "x-guardian-token": DASH_TOKEN },
    });
    expect(res.statusCode).toBe(200);
    const machines = res.json();
    expect(machines).toHaveLength(1);
    expect(machines[0].hostname).toBe("dev-laptop-7");
    expect(machines[0].status).toBe("healthy");
    expect(machines[0].extractFailures["chatgpt.com"]).toBe(2);
  });

  it("marca tampered quando o hash esperado difere", async () => {
    const res = await server.inject({
      method: "GET",
      url: "/api/fleet?expectedHash=outro-hash",
      headers: { "x-guardian-token": DASH_TOKEN },
    });
    expect(res.json()[0].status).toBe("tampered");
  });

  it("marca tampered quando a extensão é exigida e a máquina não a reporta", async () => {
    await server.inject({
      method: "POST",
      url: "/api/agent/heartbeat",
      headers: { "x-guardian-agent-key": AGENT_KEY },
      payload: heartbeat({
        machine: { hostname: "sem-extensao", username: "eve" },
        extension: null,
      }),
    });
    const res = await server.inject({
      method: "GET",
      url: "/api/fleet?expectedHash=hash-esperado&extensionRequired=1",
      headers: { "x-guardian-token": DASH_TOKEN },
    });
    const machines = res.json() as Array<{ hostname: string; status: string }>;
    const m = machines.find((x) => x.hostname === "sem-extensao");
    expect(m?.status).toBe("tampered");
  });
});

describe("POST /api/extension/heartbeat (daemon local)", () => {
  it("aceita o ping da extensão e responde 204", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/extension/heartbeat",
      headers: { "x-guardian-token": DASH_TOKEN },
      payload: {
        version: "0.2.0",
        extractFailures: { "gemini.google.com": 1 },
      },
    });
    expect(res.statusCode).toBe(204);
  });

  it("400 sem version", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/extension/heartbeat",
      headers: { "x-guardian-token": DASH_TOKEN },
      payload: {},
    });
    expect(res.statusCode).toBe(400);
  });
});
