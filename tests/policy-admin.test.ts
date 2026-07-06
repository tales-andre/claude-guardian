// Controle total das regras pelo dashboard: editar políticas (enable/action),
// gerenciar a allowlist (exceções) e os knobs do detector de entidade
// (on/off + stopwords), tudo persistido no claude-guardian.config.json e com
// efeito IMEDIATO no scan do daemon (mesmo objeto de config em memória).
//
// A persistência usa config.configPath (setado pelo loadConfig) para nunca
// gravar fora do arquivo de onde o config veio — sem isso, um teste (ou um
// daemon iniciado noutro CWD) sobrescreveria o config errado.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance, InjectOptions } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { buildServer } from "../src/server/api.ts";
import type { Config } from "../src/types/index.ts";

const TOKEN = "dash-token-admin";

let tmpDir: string;
let server: FastifyInstance;
let configPath: string;

beforeAll(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-admin-test-"));
  configPath = join(tmpDir, "claude-guardian.config.json");
  const config: Config = {
    ...structuredClone(DEFAULT_CONFIG),
    dbPath: join(tmpDir, "guardian.db"),
    logFile: join(tmpDir, "guardian.log"),
    dashboardToken: TOKEN,
    entityDetection: true,
    configPath,
  };
  // Regra de substituição para person-name (o default não cobre entidades) —
  // espelha o setup real de quem liga entityDetection.
  config.policies.push({
    id: "substitute-pii",
    name: "Substitui nomes por fictícios",
    enabled: true,
    dataTypes: ["person-name", "postal-address"],
    action: "substitute",
  });
  server = await buildServer(config);
});

afterAll(async () => {
  await server.close();
  rmSync(tmpDir, { recursive: true, force: true });
});

function inject(opts: {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  url: string;
  payload?: unknown;
  noAuth?: boolean;
}) {
  const options: InjectOptions = {
    method: opts.method,
    url: opts.url,
    headers: opts.noAuth ? {} : { "x-guardian-token": TOKEN },
  };
  if (opts.payload !== undefined) {
    options.payload = opts.payload as Record<string, unknown>;
  }
  return server.inject(options);
}

function scanWeb(text: string) {
  return inject({ method: "POST", url: "/api/scan-web", payload: { text } });
}

function savedConfig(): Record<string, unknown> {
  return JSON.parse(readFileSync(configPath, "utf8"));
}

describe("PATCH /api/policies/:id — editar políticas pelo dashboard", () => {
  it("401 sem token", async () => {
    const res = await inject({
      method: "PATCH",
      url: "/api/policies/substitute-pii",
      payload: { enabled: false },
      noAuth: true,
    });
    expect(res.statusCode).toBe(401);
  });

  it("404 para id inexistente", async () => {
    const res = await inject({
      method: "PATCH",
      url: "/api/policies/nao-existe",
      payload: { enabled: false },
    });
    expect(res.statusCode).toBe(404);
  });

  it("400 para action inválida", async () => {
    const res = await inject({
      method: "PATCH",
      url: "/api/policies/block-pii",
      payload: { action: "explodir" },
    });
    expect(res.statusCode).toBe(400);
  });

  it("muda a action e o scan reflete NA HORA (block → substitute)", async () => {
    const before = await scanWeb("fale com o cliente ci@example.com hoje");
    expect(JSON.parse(before.body).action).toBe("block");

    const res = await inject({
      method: "PATCH",
      url: "/api/policies/block-pii",
      payload: { action: "substitute" },
    });
    expect(res.statusCode).toBe(200);

    const after = await scanWeb("fale com o cliente ci@example.com hoje");
    expect(JSON.parse(after.body).action).toBe("substitute");
    // Persistiu no arquivo (hooks leem o config do disco a cada execução).
    const rules = savedConfig()["policies"] as Array<{
      id: string;
      action: string;
    }>;
    expect(rules.find((r) => r.id === "block-pii")?.action).toBe("substitute");
  });

  it("desabilita a política e o scan libera", async () => {
    const res = await inject({
      method: "PATCH",
      url: "/api/policies/block-pii",
      payload: { enabled: false },
    });
    expect(res.statusCode).toBe(200);
    const after = await scanWeb("fale com o cliente ci@example.com hoje");
    expect(JSON.parse(after.body).action).toBe("allow");
    // Restaura para os próximos testes.
    await inject({
      method: "PATCH",
      url: "/api/policies/block-pii",
      payload: { enabled: true, action: "block" },
    });
  });
});

describe("allowlist — exceções gerenciadas pelo dashboard", () => {
  it("400 sem pattern e 400 com regex inválida", async () => {
    const semPattern = await inject({
      method: "POST",
      url: "/api/allowlist",
      payload: { reason: "sem pattern" },
    });
    expect(semPattern.statusCode).toBe(400);
    const regexRuim = await inject({
      method: "POST",
      url: "/api/allowlist",
      payload: { pattern: "([", isRegex: true, reason: "regex quebrada" },
    });
    expect(regexRuim.statusCode).toBe(400);
  });

  it("cria exceção, scan libera o valor, DELETE volta a detectar", async () => {
    const blocked = await scanWeb("notifique ci-bot@example.com no deploy");
    expect(JSON.parse(blocked.body).action).toBe("block");

    const created = await inject({
      method: "POST",
      url: "/api/allowlist",
      payload: { pattern: "ci-bot@example.com", reason: "e-mail de serviço do CI" },
    });
    expect(created.statusCode).toBe(201);
    const { id } = JSON.parse(created.body) as { id: string };
    expect(id).toBeTruthy();

    const listed = await inject({ method: "GET", url: "/api/allowlist" });
    expect(
      (JSON.parse(listed.body) as Array<{ id: string }>).some(
        (e) => e.id === id,
      ),
    ).toBe(true);
    // Persistiu no arquivo.
    expect(
      (savedConfig()["allowlist"] as Array<{ id: string }>).some(
        (e) => e.id === id,
      ),
    ).toBe(true);

    const allowed = await scanWeb("notifique ci-bot@example.com no deploy");
    expect(JSON.parse(allowed.body).action).toBe("allow");

    const del = await inject({ method: "DELETE", url: `/api/allowlist/${id}` });
    expect(del.statusCode).toBe(200);
    const again = await scanWeb("notifique ci-bot@example.com no deploy");
    expect(JSON.parse(again.body).action).toBe("block");
  });
});

describe("settings — knobs do engine pelo dashboard", () => {
  it("GET expõe os knobs e NUNCA segredos", async () => {
    const res = await inject({ method: "GET", url: "/api/settings" });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body) as Record<string, unknown>;
    expect(body["entityDetection"]).toBe(true);
    expect(Array.isArray(body["entityStopwords"])).toBe(true);
    expect(body).not.toHaveProperty("substitutionSalt");
    expect(body).not.toHaveProperty("agentApiKey");
    expect(body).not.toHaveProperty("enrollmentSecret");
    expect(body).not.toHaveProperty("centralApiKey");
    expect(body).not.toHaveProperty("dashboardToken");
  });

  it("400 para tipo errado", async () => {
    const res = await inject({
      method: "PATCH",
      url: "/api/settings",
      payload: { entityStopwords: "não é array" },
    });
    expect(res.statusCode).toBe(400);
  });

  it("entityStopwords adicionadas pelo dash suprimem o falso positivo", async () => {
    const antes = await scanWeb("apresentar ao Conselho Diretor amanhã");
    expect(JSON.parse(antes.body).action).toBe("substitute");

    const res = await inject({
      method: "PATCH",
      url: "/api/settings",
      payload: { entityStopwords: ["conselho"] },
    });
    expect(res.statusCode).toBe(200);

    const depois = await scanWeb("apresentar ao Conselho Diretor amanhã");
    expect(JSON.parse(depois.body).action).toBe("allow");
    expect(savedConfig()["entityStopwords"]).toEqual(["conselho"]);
  });

  it("desligar entityDetection para de detectar nomes", async () => {
    const antes = await scanWeb("agendar com Mariana Duarte na sexta");
    expect(JSON.parse(antes.body).action).toBe("substitute");

    const res = await inject({
      method: "PATCH",
      url: "/api/settings",
      payload: { entityDetection: false },
    });
    expect(res.statusCode).toBe(200);

    const depois = await scanWeb("agendar com Mariana Duarte na sexta");
    expect(JSON.parse(depois.body).action).toBe("allow");
    expect(savedConfig()["entityDetection"]).toBe(false);
  });

  it("o arquivo persistido não vaza o configPath interno", async () => {
    expect(savedConfig()).not.toHaveProperty("configPath");
  });
});

describe("catálogo de detectores — GET /api/detectors", () => {
  it("lista built-ins com a regex REAL do scan (pattern = .source)", async () => {
    const res = await inject({ method: "GET", url: "/api/detectors" });
    expect(res.statusCode).toBe(200);
    const list = JSON.parse(res.body) as Array<Record<string, unknown>>;
    expect(list.length).toBeGreaterThan(40);

    const email = list.find((d) => d["id"] === "pii-email");
    expect(email).toBeDefined();
    expect(email?.["kind"]).toBe("regex");
    // A regex publicada deve compilar e casar o que o detector casa.
    const re = new RegExp(String(email?.["pattern"]));
    expect(re.test("fulano@empresa.com.br")).toBe(true);

    const aws = list.find((d) => d["id"] === "aws-access-key");
    expect(String(aws?.["pattern"])).toContain("AKIA");
  });

  it("todo detector kind=regex publica um pattern compilável", async () => {
    const res = await inject({ method: "GET", url: "/api/detectors" });
    const list = JSON.parse(res.body) as Array<Record<string, unknown>>;
    for (const d of list.filter((x) => x["kind"] === "regex")) {
      expect(d["pattern"], `detector ${d["id"]} sem pattern`).toBeTruthy();
      expect(() => new RegExp(String(d["pattern"]))).not.toThrow();
    }
  });

  it("heurísticos e externos aparecem com descrição no lugar do pattern", async () => {
    const res = await inject({ method: "GET", url: "/api/detectors" });
    const list = JSON.parse(res.body) as Array<Record<string, unknown>>;

    const name = list.find((d) => d["id"] === "entity-person-name");
    expect(name?.["kind"]).toBe("heuristic");
    expect(name?.["pattern"]).toBeUndefined();
    expect(String(name?.["description"]).length).toBeGreaterThan(10);

    const gl = list.find((d) => d["id"] === "gitleaks");
    expect(gl?.["kind"]).toBe("external");
    expect(gl?.["pattern"]).toBeUndefined();
  });

  it("entity reflete config.entityDetection em `active`", async () => {
    // O teste anterior de settings desligou entityDetection.
    const res = await inject({ method: "GET", url: "/api/detectors" });
    const list = JSON.parse(res.body) as Array<Record<string, unknown>>;
    const name = list.find((d) => d["id"] === "entity-person-name");
    expect(name?.["active"]).toBe(false);
  });

  it("exige o token do dashboard", async () => {
    const res = await inject({
      method: "GET",
      url: "/api/detectors",
      noAuth: true,
    });
    expect(res.statusCode).toBe(401);
  });
});

describe("restrição de modelos no navegador — blockedWebModels", () => {
  it("PATCH /api/settings aceita e persiste a lista", async () => {
    const res = await inject({
      method: "PATCH",
      url: "/api/settings",
      payload: { blockedWebModels: ["fable", "  gpt-5  ", ""] },
    });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body) as Record<string, unknown>;
    expect(body["blockedWebModels"]).toEqual(["fable", "gpt-5"]);
    expect(savedConfig()["blockedWebModels"]).toEqual(["fable", "gpt-5"]);
  });

  it("400 para tipo errado", async () => {
    const res = await inject({
      method: "PATCH",
      url: "/api/settings",
      payload: { blockedWebModels: "fable" },
    });
    expect(res.statusCode).toBe(400);
  });

  it("bloqueia envio web com modelo restrito, mesmo com texto limpo", async () => {
    const res = await inject({
      method: "POST",
      url: "/api/scan-web",
      payload: {
        text: "qual é a capital da França?",
        context: { model: "claude-fable-5" },
      },
    });
    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body) as Record<string, unknown>;
    expect(body["action"]).toBe("block");
    const findings = body["findings"] as Array<Record<string, unknown>>;
    expect(findings[0]?.["detectorId"]).toBe("blocked-model");
  });

  it("bloqueia envio só-modelo (texto vazio — restrição vale sem prompt)", async () => {
    const res = await inject({
      method: "POST",
      url: "/api/scan-web",
      payload: { text: "", context: { model: "claude-fable-5" } },
    });
    expect(JSON.parse(res.body).action).toBe("block");
  });

  it("permite modelo fora da lista", async () => {
    const res = await inject({
      method: "POST",
      url: "/api/scan-web",
      payload: {
        text: "qual é a capital da França?",
        context: { model: "claude-sonnet-5" },
      },
    });
    expect(JSON.parse(res.body).action).toBe("allow");
  });

  it("lista vazia desliga a restrição (comportamento local inalterado)", async () => {
    await inject({
      method: "PATCH",
      url: "/api/settings",
      payload: { blockedWebModels: [] },
    });
    const res = await inject({
      method: "POST",
      url: "/api/scan-web",
      payload: { text: "oi", context: { model: "claude-fable-5" } },
    });
    expect(JSON.parse(res.body).action).toBe("allow");
  });
});
