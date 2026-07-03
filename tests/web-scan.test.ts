import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { getDb } from "../src/db/client.ts";
import { outboxDir } from "../src/lib/central.ts";
import { scanWeb } from "../src/lib/web-scan.ts";
import { buildServer } from "../src/server/api.ts";
import type { Config } from "../src/types/index.ts";

let tmpDir: string;
let dbPath: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-web-test-"));
  dbPath = join(tmpDir, "test.db");
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function cfg(overrides: Partial<Config> = {}): Config {
  return { ...DEFAULT_CONFIG, dbPath, ...overrides };
}

const PRIVATE_KEY =
  "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdef\n-----END RSA PRIVATE KEY-----";

describe("scanWeb", () => {
  it("allows a clean prompt", () => {
    const db = getDb(dbPath);
    const r = scanWeb(db, cfg(), { text: "olá, qual é a capital da França?" });
    expect(r.action).toBe("allow");
    expect(r.findings).toHaveLength(0);
  });

  it("blocks a prompt containing a secret", () => {
    const db = getDb(dbPath);
    const r = scanWeb(db, cfg(), { text: `meu deploy:\n${PRIVATE_KEY}` });
    expect(r.action).toBe("block");
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.approvalUrl).toContain("/request-approval/");
  });

  it("blocks an upload by filename (.env)", () => {
    const db = getDb(dbPath);
    const r = scanWeb(db, cfg(), { files: [{ name: ".env", content: "X=1" }] });
    expect(r.action).toBe("block");
    expect(r.findings.some((f) => f.detectorId === "upload-file-name")).toBe(
      true,
    );
  });

  it("blocks an upload by extension (.pem) without reading content", () => {
    const db = getDb(dbPath);
    const r = scanWeb(db, cfg(), { files: [{ name: "server.pem" }] });
    expect(r.action).toBe("block");
  });

  it("scans text-file content uploads", () => {
    const db = getDb(dbPath);
    const r = scanWeb(db, cfg(), {
      files: [{ name: "notes.txt", content: PRIVATE_KEY }],
    });
    expect(r.action).toBe("block");
  });

  it("redacts when policy says redact and returns masked text", () => {
    const db = getDb(dbPath);
    const config = cfg({
      policies: [
        {
          id: "redact-private-key",
          name: "redact",
          enabled: true,
          dataTypes: ["private-key"],
          action: "redact",
        },
      ],
    });
    const r = scanWeb(db, config, { text: `chave: ${PRIVATE_KEY}` });
    expect(r.action).toBe("redact");
    expect(r.redactedText).toContain("[REDACTED:");
    expect(r.redactedText).not.toContain("BEGIN RSA PRIVATE KEY");
  });

  it("fails closed on engine timeout", () => {
    const db = getDb(dbPath);
    const r = scanWeb(db, cfg({ engineTimeoutMs: 0 }), { text: PRIVATE_KEY });
    expect(r.action).toBe("block");
    expect(r.reason).toMatch(/fail-closed/i);
  });

  it("uses the central dashboard URL in approvalUrl when central is configured", () => {
    const db = getDb(dbPath);
    const config = cfg({
      centralUrl: "https://guardian.example.com",
      centralApiKey: "agent-key",
    });
    const r = scanWeb(db, config, { text: PRIVATE_KEY });
    expect(r.action).toBe("block");
    expect(r.approvalUrl).toContain("https://guardian.example.com");
  });

  it("mirrors blocked incidents to the central outbox without rawValue", () => {
    const db = getDb(dbPath);
    const config = cfg({
      centralUrl: "http://127.0.0.1:1",
      centralApiKey: "agent-key",
    });
    const before = existsSync(outboxDir(config))
      ? readdirSync(outboxDir(config)).length
      : 0;
    const r = scanWeb(db, config, { text: PRIVATE_KEY });
    expect(r.action).toBe("block");

    const files = readdirSync(outboxDir(config));
    expect(files.length).toBeGreaterThan(before);
    const newest = files.sort().at(-1) as string;
    const payload = JSON.parse(
      readFileSync(join(outboxDir(config), newest), "utf8"),
    );
    expect(payload.auditType).toBe("block");
    expect(["WebPrompt", "WebUpload"]).toContain(payload.incident.tool);
    expect(JSON.stringify(payload)).not.toContain("BEGIN RSA PRIVATE KEY");
  });
});

describe("POST /api/scan-web (rota do daemon local)", () => {
  const DASH_TOKEN = "web-dash-token";
  let server: FastifyInstance;

  beforeAll(async () => {
    server = await buildServer(cfg({ dashboardToken: DASH_TOKEN }));
  });

  afterAll(async () => {
    await server.close();
  });

  it("rejects without dashboard token", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/scan-web",
      payload: { text: "oi" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("400 when neither text nor files is present", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/scan-web",
      headers: { "x-guardian-token": DASH_TOKEN },
      payload: {},
    });
    expect(res.statusCode).toBe(400);
  });

  it("blocks a secret sent through the route", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/scan-web",
      headers: { "x-guardian-token": DASH_TOKEN },
      payload: { text: PRIVATE_KEY, context: { url: "https://claude.ai/" } },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.action).toBe("block");
    expect(body.findings.length).toBeGreaterThan(0);
  });

  it("allows a clean prompt through the route", async () => {
    const res = await server.inject({
      method: "POST",
      url: "/api/scan-web",
      headers: { "x-guardian-token": DASH_TOKEN },
      payload: { text: "bom dia" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().action).toBe("allow");
  });
});
