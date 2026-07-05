import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import Fastify from "fastify";
import { saveConfig } from "../config/loader.ts";
import { getDb } from "../db/client.ts";
import { buildScope } from "../lib/approval.ts";
import { computeMachineStatus } from "../lib/fleet.ts";
import {
  buildMachineHeartbeat,
  sendMachineHeartbeat,
} from "../lib/fleet-client.ts";
import { generateRegex } from "../lib/regex-generator.ts";
import { scanWeb, type WebScanRequest } from "../lib/web-scan.ts";
import type {
  AgentIngestPayload,
  ApprovalStatus,
  Config,
  ExtensionHeartbeat,
  MachineHeartbeatPayload,
  PolicyAction,
  PolicyRule,
} from "../types/index.ts";
import { createStore } from "./store.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export async function buildServer(config: Config): Promise<FastifyInstance> {
  const fastify = Fastify({ logger: false });
  // SQLite local (comportamento original) ou Postgres quando databaseUrl está
  // configurado (modo central em Docker/EKS).
  const store = await createStore(config);

  // ── Auth middleware ────────────────────────────────────────────────────────
  fastify.addHook(
    "onRequest",
    async (req: FastifyRequest, reply: FastifyReply) => {
      const url = req.url.split("?")[0] ?? req.url;

      // Enrollment: autenticado pelo segredo de enrollment no próprio handler.
      if (url === "/api/agent/enroll") return;

      // Endpoints de agente: chave por máquina (enrollment) ou, durante a
      // migração, a agentApiKey compartilhada legada (allowLegacyAgentKey).
      // Fail-closed: sem chave válida, nenhuma máquina ingere dados.
      if (url.startsWith("/api/agent/")) {
        const agentKey = req.headers["x-guardian-agent-key"] as
          | string
          | undefined;
        if (agentKey) {
          const row = await store.findAgentKeyByHash(sha256(agentKey));
          if (row && !row.revokedAt) return;
          if (
            config.allowLegacyAgentKey &&
            config.agentApiKey &&
            agentKey === config.agentApiKey
          ) {
            return;
          }
        }
        return reply.status(401).send({ error: "Unauthorized agent" });
      }

      if (
        url === "/" ||
        url === "/dashboard" ||
        url === "/health" ||
        url.startsWith("/dashboard") ||
        url.startsWith("/request-approval") ||
        (req.method === "POST" && url === "/api/approvals")
      ) {
        return;
      }
      if (!config.dashboardToken) return;
      const token =
        (req.headers["x-guardian-token"] as string | undefined) ??
        (req.query as Record<string, string>)["token"];
      if (token === config.dashboardToken) return;
      return reply.status(401).send({ error: "Unauthorized" });
    },
  );

  // ── Static dashboard ───────────────────────────────────────────────────────
  fastify.get("/", (_req, reply) => void reply.redirect(301, "/dashboard"));

  fastify.get("/dashboard", (_req, reply) => {
    try {
      const html = readFileSync(
        join(__dirname, "../../public/dashboard.html"),
        "utf8",
      );
      void reply.type("text/html").send(html);
    } catch {
      void reply
        .status(503)
        .send("Dashboard file missing. Run: claude-guardian init");
    }
  });

  fastify.get("/health", (_req, reply) => {
    void reply.send({ status: "ok", timestamp: new Date().toISOString() });
  });

  // ── User-facing approval request page ─────────────────────────────────────
  fastify.get(
    "/request-approval/:incidentId",
    async (req: FastifyRequest<{ Params: { incidentId: string } }>, reply) => {
      const incident = await store.getIncidentById(req.params.incidentId);
      if (!incident)
        return void reply.status(404).send("Incidente não encontrado.");

      const findings: Array<{
        severity: string;
        label: string;
        detectorId: string;
        snippet: string;
      }> = JSON.parse(incident.findingsJson);
      const findingRows = findings
        .map(
          (f) =>
            `<tr><td>${f.severity.toUpperCase()}</td><td>${f.label}</td><td><code>${f.snippet}</code></td></tr>`,
        )
        .join("");

      const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Solicitar Liberação — Claude Guardian</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f5f5f5; color: #1a1a1a; display: flex; justify-content: center; padding: 2rem 1rem; min-height: 100vh; }
  .card { background: #fff; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,.08); max-width: 560px; width: 100%; padding: 2rem; height: fit-content; }
  h1 { font-size: 1.25rem; margin-bottom: .25rem; }
  .subtitle { color: #666; font-size: .875rem; margin-bottom: 1.5rem; }
  .badge { display: inline-block; background: #fff3cd; color: #856404; border: 1px solid #ffc107; border-radius: 4px; padding: .2rem .5rem; font-size: .75rem; font-weight: 600; margin-bottom: 1.25rem; }
  table { width: 100%; border-collapse: collapse; font-size: .875rem; margin-bottom: 1.5rem; }
  th { text-align: left; padding: .5rem .75rem; background: #f8f8f8; border-bottom: 2px solid #e0e0e0; color: #555; font-weight: 600; }
  td { padding: .5rem .75rem; border-bottom: 1px solid #eee; }
  td:first-child { font-weight: 600; color: #c0392b; }
  code { background: #f0f0f0; padding: .1rem .35rem; border-radius: 3px; font-family: monospace; font-size: .8rem; }
  .meta { font-size: .8rem; color: #888; margin-bottom: 1.5rem; }
  label { display: block; font-size: .875rem; font-weight: 600; margin-bottom: .4rem; }
  textarea { width: 100%; border: 1px solid #d0d0d0; border-radius: 6px; padding: .65rem .75rem; font-size: .9rem; resize: vertical; min-height: 100px; outline: none; transition: border-color .2s; }
  textarea:focus { border-color: #4f46e5; }
  button { margin-top: 1rem; width: 100%; background: #4f46e5; color: #fff; border: none; border-radius: 6px; padding: .75rem 1rem; font-size: .95rem; font-weight: 600; cursor: pointer; transition: background .2s; }
  button:hover { background: #4338ca; }
  button:disabled { background: #a5b4fc; cursor: not-allowed; }
  .success { display: none; background: #d1fae5; border: 1px solid #6ee7b7; border-radius: 6px; padding: 1rem; text-align: center; color: #065f46; font-size: .9rem; margin-top: 1rem; }
  .error-msg { display: none; background: #fee2e2; border: 1px solid #fca5a5; border-radius: 6px; padding: .75rem 1rem; color: #991b1b; font-size: .875rem; margin-top: .75rem; }
</style>
</head>
<body>
<div class="card">
  <h1>Solicitar Liberação</h1>
  <p class="subtitle">Um dado sensível foi detectado no seu prompt. Envie uma justificativa para que o administrador possa avaliar.</p>
  <span class="badge">Revisão pendente</span>
  <table>
    <thead><tr><th>Severidade</th><th>Tipo</th><th>Trecho</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>
  <p class="meta">Incident ID: <code>${incident.id}</code></p>
  <form id="form">
    <label for="justification">Justificativa</label>
    <textarea id="justification" name="justification" placeholder="Descreva por que este dado precisa ser processado e qual é o contexto de uso..." required minlength="10"></textarea>
    <button type="submit" id="btn">Solicitar Liberação</button>
    <div class="error-msg" id="err"></div>
  </form>
  <div class="success" id="ok">
    Sua solicitação foi enviada com sucesso. Aguarde a aprovação do administrador e, após confirmação, repita o prompt normalmente.
  </div>
</div>
<script>
  document.getElementById('form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('btn');
    const err = document.getElementById('err');
    const ok = document.getElementById('ok');
    const justification = document.getElementById('justification').value.trim();
    if (!justification) return;
    btn.disabled = true;
    btn.textContent = 'Enviando…';
    err.style.display = 'none';
    try {
      const res = await fetch('/api/approvals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incidentId: '${incident.id}', justification }),
      });
      if (res.ok || res.status === 201) {
        document.getElementById('form').style.display = 'none';
        ok.style.display = 'block';
      } else {
        const data = await res.json().catch(() => ({}));
        err.textContent = data.error || 'Erro ao enviar solicitação. Tente novamente.';
        err.style.display = 'block';
        btn.disabled = false;
        btn.textContent = 'Solicitar Liberação';
      }
    } catch {
      err.textContent = 'Falha de conexão. Verifique se o servidor está acessível.';
      err.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Solicitar Liberação';
    }
  });
</script>
</body>
</html>`;

      void reply.type("text/html").send(html);
    },
  );

  // ── Incidents ──────────────────────────────────────────────────────────────
  fastify.get("/api/incidents", async (req, reply) => {
    const q = req.query as Record<string, string>;
    const limit = Math.min(parseInt(q["limit"] ?? "50", 10), 500);
    const offset = parseInt(q["offset"] ?? "0", 10);
    void reply.send(await store.listIncidents(limit, offset));
  });

  fastify.get(
    "/api/incidents/:id",
    async (req: FastifyRequest<{ Params: { id: string } }>, reply) => {
      const incident = await store.getIncidentById(req.params.id);
      if (!incident) return void reply.status(404).send({ error: "Not found" });
      void reply.send(incident);
    },
  );

  // ── Approvals ─────────────────────────────────────────────────────────────
  fastify.get("/api/approvals", async (req, reply) => {
    const q = req.query as Record<string, string>;
    const status = q["status"] as ApprovalStatus | undefined;
    void reply.send(await store.listApprovals(status));
  });

  fastify.get(
    "/api/approvals/:id",
    async (req: FastifyRequest<{ Params: { id: string } }>, reply) => {
      const approval = await store.getApprovalById(req.params.id);
      if (!approval) return void reply.status(404).send({ error: "Not found" });
      void reply.send(approval);
    },
  );

  fastify.post(
    "/api/approvals/:id/resolve",
    async (
      req: FastifyRequest<{
        Params: { id: string };
        Body: {
          status?: "approved" | "denied";
          resolvedBy?: string;
          ttlSeconds?: number;
        };
      }>,
      reply,
    ) => {
      const { status, resolvedBy = "dashboard", ttlSeconds } = req.body ?? {};
      if (status !== "approved" && status !== "denied") {
        return void reply
          .status(400)
          .send({ error: "status must be 'approved' or 'denied'" });
      }
      const ttl =
        typeof ttlSeconds === "number" &&
        Number.isFinite(ttlSeconds) &&
        ttlSeconds > 0
          ? ttlSeconds
          : undefined;
      const updated = await store.resolveApproval(
        req.params.id,
        status,
        resolvedBy,
        ttl,
      );
      if (!updated) return void reply.status(404).send({ error: "Not found" });
      broadcast({ type: "approval", status });
      void reply.send(updated);
    },
  );

  fastify.post(
    "/api/approvals",
    async (
      req: FastifyRequest<{
        Body: {
          incidentId?: string;
          justification?: string;
          ttlSeconds?: number;
        };
      }>,
      reply,
    ) => {
      const { incidentId, justification, ttlSeconds = 3600 } = req.body ?? {};
      if (!incidentId || !justification) {
        return void reply
          .status(400)
          .send({ error: "incidentId and justification required" });
      }
      const incident = await store.getIncidentById(incidentId);
      if (!incident)
        return void reply.status(404).send({ error: "Incident not found" });

      const scope = buildScope(incident.tool, incident.dataTypes);
      const approval = await store.createApproval(
        incidentId,
        scope,
        justification,
        ttlSeconds,
      );
      broadcast({ type: "approval", status: "pending" });
      void reply.status(201).send(approval);
    },
  );

  // ── Agent enrollment (chave por máquina) ───────────────────────────────────
  // Troca o segredo de enrollment (distribuído pelo instalador corporativo)
  // por uma chave individual da máquina. Só o sha256 da chave é armazenado;
  // o valor bruto aparece uma única vez, na resposta.
  fastify.post(
    "/api/agent/enroll",
    async (req: FastifyRequest<{ Body: { hostname?: string } }>, reply) => {
      const token = req.headers["x-guardian-enrollment-token"] as
        | string
        | undefined;
      // Fail-closed: sem enrollmentSecret configurado, ninguém se registra.
      if (!config.enrollmentSecret || token !== config.enrollmentSecret) {
        return void reply
          .status(401)
          .send({ error: "Unauthorized enrollment" });
      }
      const hostname = String(req.body?.hostname ?? "").trim();
      if (!hostname) {
        return void reply.status(400).send({ error: "hostname required" });
      }
      const agentKey = randomBytes(32).toString("hex");
      const keyId = randomBytes(8).toString("hex");
      await store.createAgentKey({
        id: keyId,
        machineId: hostname,
        keyHash: sha256(agentKey),
        createdAt: new Date().toISOString(),
      });
      await store.appendAuditEntry("agent-enroll", {
        keyId,
        machineId: hostname,
      });
      void reply.status(201).send({ keyId, agentKey });
    },
  );

  // Administração das chaves de agente (auth de dashboard — fora de /api/agent/).
  fastify.get("/api/agent-keys", async (_req, reply) => {
    void reply.send(await store.listAgentKeys());
  });

  fastify.post(
    "/api/agent-keys/:id/revoke",
    async (req: FastifyRequest<{ Params: { id: string } }>, reply) => {
      const revoked = await store.revokeAgentKey(req.params.id);
      if (!revoked) return void reply.status(404).send({ error: "Not found" });
      await store.appendAuditEntry("agent-key-revoke", {
        keyId: req.params.id,
      });
      void reply.send({ success: true });
    },
  );

  // ── Agent ingest (modo central) ────────────────────────────────────────────
  // Recebe eventos das máquinas-cliente. Findings chegam sem rawValue — o
  // cliente remove segredos brutos antes de enviar.
  fastify.post(
    "/api/agent/ingest",
    async (req: FastifyRequest<{ Body: AgentIngestPayload }>, reply) => {
      const body = req.body ?? ({} as AgentIngestPayload);
      const inc = body.incident;
      if (
        !inc?.id ||
        !inc.timestamp ||
        !inc.tool ||
        !inc.action ||
        !Array.isArray(inc.findings) ||
        !body.machine?.hostname
      ) {
        return void reply.status(400).send({ error: "invalid payload" });
      }
      // Defesa em profundidade: descarta rawValue caso um cliente antigo envie.
      const sanitized: AgentIngestPayload = {
        machine: {
          hostname: String(body.machine.hostname),
          username: String(body.machine.username ?? ""),
        },
        incident: {
          ...inc,
          sessionId: String(inc.sessionId ?? ""),
          context: String(inc.context ?? ""),
          dataTypes: Array.isArray(inc.dataTypes) ? inc.dataTypes : [],
          severities: Array.isArray(inc.severities) ? inc.severities : [],
          findings: inc.findings.map((f) => ({
            detectorId: String(f.detectorId ?? ""),
            label: String(f.label ?? ""),
            dataType: String(f.dataType ?? ""),
            severity: String(f.severity ?? ""),
            snippet: String(f.snippet ?? ""),
            confidence: Number(f.confidence ?? 0),
          })),
        },
        approval: body.approval ?? null,
        auditType: String(body.auditType ?? "event"),
      };
      const result = await store.ingestAgentEvent(sanitized);
      broadcast({ type: "incident" });
      if (sanitized.approval)
        broadcast({ type: "approval", status: "pending" });
      void reply.status(201).send(result);
    },
  );

  // Consulta de aprovação ativa pelos hooks das máquinas-cliente.
  fastify.get(
    "/api/agent/approvals/active",
    async (req: FastifyRequest<{ Querystring: { scope?: string } }>, reply) => {
      const scope = req.query?.scope ?? "";
      if (!scope)
        return void reply.status(400).send({ error: "scope required" });
      const approval = await store.findActiveApproval(scope);
      void reply.send({ approval });
    },
  );

  // ── Fleet: heartbeat das máquinas (modo central) ───────────────────────────
  fastify.post(
    "/api/agent/heartbeat",
    async (req: FastifyRequest<{ Body: MachineHeartbeatPayload }>, reply) => {
      const body = req.body ?? ({} as MachineHeartbeatPayload);
      if (!body.machine?.hostname) {
        return void reply.status(400).send({ error: "hostname required" });
      }
      await store.upsertMachine({
        machine: {
          hostname: String(body.machine.hostname),
          username: String(body.machine.username ?? ""),
        },
        guardianVersion: String(body.guardianVersion ?? ""),
        configHash: String(body.configHash ?? ""),
        extension: body.extension
          ? {
              version: String(body.extension.version ?? ""),
              extractFailures: body.extension.extractFailures ?? {},
            }
          : null,
      });
      void reply.status(204).send();
    },
  );

  // Visão da frota para o admin: status calculado por máquina.
  fastify.get(
    "/api/fleet",
    async (
      req: FastifyRequest<{
        Querystring: {
          expectedHash?: string;
          extensionRequired?: string;
          staleAfterMs?: string;
        };
      }>,
      reply,
    ) => {
      const q = req.query ?? {};
      const extensionRequired =
        q.extensionRequired === "1" || q.extensionRequired === "true";
      const staleAfterMs = q.staleAfterMs
        ? parseInt(q.staleAfterMs, 10)
        : undefined;
      const machines = await store.listMachines();
      void reply.send(
        machines.map((m) => ({
          ...m,
          status: computeMachineStatus(
            {
              configHash: m.configHash,
              lastSeen: m.lastSeen,
              ...(m.extensionLastSeen && {
                extensionLastSeen: m.extensionLastSeen,
              }),
            },
            {
              // Sem hash esperado informado, compara consigo mesmo (o sinal
              // de tamper por hash fica desativado; stale/extensão continuam).
              expectedConfigHash: q.expectedHash ?? m.configHash,
              extensionRequired,
              ...(staleAfterMs !== undefined &&
                Number.isFinite(staleAfterMs) && { staleAfterMs }),
            },
          ),
        })),
      );
    },
  );

  // ── Policies ───────────────────────────────────────────────────────────────
  fastify.get("/api/policies", (_req, reply) => {
    void reply.send(config.policies);
  });

  fastify.get("/api/policies/custom", async (_req, reply) => {
    try {
      void reply.send(await store.listCustomDetectors());
    } catch {
      void reply.send([]);
    }
  });

  fastify.post(
    "/api/policies/generate-regex",
    (req: FastifyRequest<{ Body: { examples?: string[] } }>, reply) => {
      const { examples } = req.body ?? {};
      if (!Array.isArray(examples) || examples.length < 2) {
        return void reply
          .status(400)
          .send({ error: "Mínimo de 2 exemplos necessários" });
      }
      void reply.send(generateRegex(examples));
    },
  );

  fastify.post(
    "/api/policies/custom",
    async (
      req: FastifyRequest<{
        Body: {
          name?: string;
          description?: string;
          regex?: string;
          action?: string;
          severity?: string;
          examples?: string[];
        };
      }>,
      reply,
    ) => {
      const {
        name,
        description = "",
        regex,
        action = "block",
        severity = "high",
        examples = [],
      } = req.body ?? {};

      if (!name || !regex) {
        return void reply
          .status(400)
          .send({ error: "name e regex são obrigatórios" });
      }

      try {
        new RegExp(regex);
      } catch (e) {
        return void reply
          .status(400)
          .send({ error: `Regex inválida: ${String(e)}` });
      }

      // Reject regex that matches empty string
      const emptyTest = new RegExp(regex);
      if (emptyTest.test("")) {
        return void reply
          .status(400)
          .send({ error: "A regex não pode dar match em string vazia" });
      }

      const existingId = await store.findCustomDetectorIdByRegex(regex);
      if (existingId) {
        return void reply.status(409).send({
          error: "Já existe uma regra com essa regex",
          existingId,
        });
      }

      const slug = name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "");
      const detectorId = `custom-${slug}-${Date.now().toString(36)}`;
      const ruleId = `rule-${detectorId}`;

      await store.createCustomDetector({
        id: detectorId,
        name,
        description,
        regex,
        severity,
        action,
        createdAt: new Date().toISOString(),
        examples,
      });

      const newRule: PolicyRule = {
        id: ruleId,
        name,
        enabled: true,
        detectorIds: [detectorId],
        tools: ["*"],
        action: action as PolicyAction,
      };
      config.policies.push(newRule);

      try {
        saveConfig(config);
      } catch {
        // Non-fatal — rule is active in memory even if file write fails
      }

      void reply.status(201).send({ success: true, detectorId, ruleId });
    },
  );

  fastify.delete(
    "/api/policies/custom/:id",
    async (req: FastifyRequest<{ Params: { id: string } }>, reply) => {
      const { id } = req.params;
      const deleted = await store.deleteCustomDetector(id);
      if (!deleted) return void reply.status(404).send({ error: "Not found" });

      const ruleId = `rule-${id}`;
      const idx = config.policies.findIndex((p) => p.id === ruleId);
      if (idx !== -1) config.policies.splice(idx, 1);

      try {
        saveConfig(config);
      } catch {
        // Non-fatal
      }

      void reply.status(204).send();
    },
  );

  // ── Scan da extensão de navegador ─────────────────────────────────────────
  // Registrada apenas no modo local (daemon SQLite): o texto do prompt nunca
  // chega ao servidor central — o scan roda na máquina e só metadados são
  // espelhados via outbox (dentro do scanWeb).
  if (store.kind === "sqlite") {
    fastify.post(
      "/api/scan-web",
      (req: FastifyRequest<{ Body: WebScanRequest }>, reply) => {
        const body = req.body ?? ({} as WebScanRequest);
        if (typeof body.text !== "string" && !Array.isArray(body.files)) {
          return void reply
            .status(400)
            .send({ error: "text (string) or files (array) required" });
        }
        try {
          void reply.send(scanWeb(getDb(config.dbPath), config, body));
        } catch {
          // Fail-closed: qualquer erro inesperado do servidor bloqueia o envio.
          void reply.send({
            action: "block",
            findings: [],
            reason:
              "Erro interno no guardian — bloqueado por segurança (fail-closed).",
          });
        }
      },
    );

    // ── Heartbeat da extensão de navegador ────────────────────────────────────
    // A extensão pinga o daemon local; o daemon acumula e repassa ao central
    // no heartbeat de máquina. Extensão que para de pingar com a máquina viva
    // aparece como "tampered" no fleet (extensão removida/desabilitada).
    let extensionState: ExtensionHeartbeat | null = null;

    fastify.post(
      "/api/extension/heartbeat",
      (req: FastifyRequest<{ Body: ExtensionHeartbeat }>, reply) => {
        const body = req.body ?? ({} as ExtensionHeartbeat);
        if (typeof body.version !== "string" || body.version === "") {
          return void reply.status(400).send({ error: "version required" });
        }
        const merged: Record<string, number> = {
          ...(extensionState?.extractFailures ?? {}),
        };
        for (const [host, n] of Object.entries(body.extractFailures ?? {})) {
          if (Number.isFinite(n)) merged[host] = (merged[host] ?? 0) + n;
        }
        extensionState = { version: body.version, extractFailures: merged };
        // Fire-and-forget: o ping da extensão nunca espera o central.
        void sendMachineHeartbeat(
          config,
          buildMachineHeartbeat(extensionState),
        );
        void reply.status(204).send();
      },
    );

    // Heartbeat periódico da máquina (com ou sem extensão): mantém a máquina
    // visível no fleet mesmo quando a extensão morre — é assim que o silêncio
    // dela vira sinal de tamper em vez de sumiço da máquina inteira.
    const heartbeatTimer = setInterval(() => {
      void sendMachineHeartbeat(config, buildMachineHeartbeat(extensionState));
    }, 5 * 60_000);
    heartbeatTimer.unref();
    void sendMachineHeartbeat(config, buildMachineHeartbeat(null));
    fastify.addHook("onClose", (_instance, done) => {
      clearInterval(heartbeatTimer);
      done();
    });
  }

  // ── Metrics ────────────────────────────────────────────────────────────────
  fastify.get("/api/metrics", async (_req, reply) => {
    void reply.send(await store.metrics());
  });

  // ── Audit log ──────────────────────────────────────────────────────────────
  fastify.get("/api/audit", async (req, reply) => {
    const q = req.query as Record<string, string>;
    const limit = Math.min(parseInt(q["limit"] ?? "50", 10), 500);
    const offset = parseInt(q["offset"] ?? "0", 10);
    void reply.send(await store.listAudit(limit, offset));
  });

  fastify.get("/api/audit/verify", async (_req, reply) => {
    void reply.send(await store.verifyAuditChain());
  });

  // ── SSE for real-time dashboard updates ────────────────────────────────────
  const sseClients = new Set<FastifyReply>();

  function broadcast(event: Record<string, unknown>): void {
    const payload = `data: ${JSON.stringify(event)}\n\n`;
    for (const client of sseClients) {
      try {
        client.raw.write(payload);
      } catch {
        sseClients.delete(client);
      }
    }
  }

  // Incidents are written by separate processes (local hooks) or other
  // replicas (central mode), so the server polls for new rows to feed
  // connected SSE clients.
  let lastIncidentMark = await store.latestIncidentMark();
  const incidentPoll = setInterval(() => {
    if (sseClients.size === 0) return;
    store
      .latestIncidentMark()
      .then((m) => {
        if (m !== lastIncidentMark) {
          lastIncidentMark = m;
          broadcast({ type: "incident" });
        }
      })
      .catch(() => {
        // DB momentarily unavailable — retry on next tick
      });
  }, 3000);
  incidentPoll.unref();
  fastify.addHook("onClose", (_instance, done) => {
    clearInterval(incidentPoll);
    void store.close().finally(() => done());
  });

  fastify.get("/api/events", (_req, reply) => {
    reply.raw.setHeader("Content-Type", "text/event-stream");
    reply.raw.setHeader("Cache-Control", "no-cache");
    reply.raw.setHeader("Connection", "keep-alive");
    reply.raw.setHeader("X-Accel-Buffering", "no");
    reply.raw.flushHeaders();
    reply.raw.write('data: {"type":"connected"}\n\n');

    sseClients.add(reply);
    reply.raw.on("close", () => {
      sseClients.delete(reply);
    });
  });

  return fastify;
}
