import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import Fastify from "fastify";
import { saveConfig } from "../config/loader.ts";
import { getDb } from "../db/client.ts";
import {
  buildScope,
  createApproval,
  getApprovalById,
  listApprovals,
  resolveApproval,
} from "../lib/approval.ts";
import { verifyAuditChain } from "../lib/audit.ts";
import { getIncidentById, listIncidents } from "../lib/incident.ts";
import { generateRegex } from "../lib/regex-generator.ts";
import type {
  ApprovalStatus,
  Config,
  PolicyAction,
  PolicyRule,
} from "../types/index.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

export function buildServer(config: Config): FastifyInstance {
  const fastify = Fastify({ logger: false });
  const db = getDb(config.dbPath);

  // ── Auth middleware ────────────────────────────────────────────────────────
  fastify.addHook(
    "onRequest",
    (req: FastifyRequest, reply: FastifyReply, done) => {
      const url = req.url.split("?")[0] ?? req.url;
      if (
        url === "/" ||
        url === "/dashboard" ||
        url === "/health" ||
        url.startsWith("/dashboard") ||
        url.startsWith("/request-approval") ||
        (req.method === "POST" && url === "/api/approvals")
      ) {
        done();
        return;
      }
      if (!config.dashboardToken) {
        done();
        return;
      }
      const token =
        (req.headers["x-guardian-token"] as string | undefined) ??
        (req.query as Record<string, string>)["token"];
      if (token === config.dashboardToken) {
        done();
        return;
      }
      reply.status(401).send({ error: "Unauthorized" });
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
    (req: FastifyRequest<{ Params: { incidentId: string } }>, reply) => {
      const incident = getIncidentById(db, req.params.incidentId);
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
  fastify.get("/api/incidents", (req, reply) => {
    const q = req.query as Record<string, string>;
    const limit = Math.min(parseInt(q["limit"] ?? "50", 10), 500);
    const offset = parseInt(q["offset"] ?? "0", 10);
    void reply.send(listIncidents(db, limit, offset));
  });

  fastify.get(
    "/api/incidents/:id",
    (req: FastifyRequest<{ Params: { id: string } }>, reply) => {
      const incident = getIncidentById(db, req.params.id);
      if (!incident) return void reply.status(404).send({ error: "Not found" });
      void reply.send(incident);
    },
  );

  // ── Approvals ─────────────────────────────────────────────────────────────
  fastify.get("/api/approvals", (req, reply) => {
    const q = req.query as Record<string, string>;
    const status = q["status"] as ApprovalStatus | undefined;
    void reply.send(listApprovals(db, status));
  });

  fastify.get(
    "/api/approvals/:id",
    (req: FastifyRequest<{ Params: { id: string } }>, reply) => {
      const approval = getApprovalById(db, req.params.id);
      if (!approval) return void reply.status(404).send({ error: "Not found" });
      void reply.send(approval);
    },
  );

  fastify.post(
    "/api/approvals/:id/resolve",
    (
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
      const updated = resolveApproval(
        db,
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
    (
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
      const incident = getIncidentById(db, incidentId);
      if (!incident)
        return void reply.status(404).send({ error: "Incident not found" });

      const scope = buildScope(incident.tool, incident.dataTypes);
      const approval = createApproval(
        db,
        incidentId,
        scope,
        justification,
        ttlSeconds,
      );
      broadcast({ type: "approval", status: "pending" });
      void reply.status(201).send(approval);
    },
  );

  // ── Policies ───────────────────────────────────────────────────────────────
  fastify.get("/api/policies", (_req, reply) => {
    void reply.send(config.policies);
  });

  fastify.get("/api/policies/custom", (_req, reply) => {
    try {
      const rows = db
        .prepare("SELECT * FROM custom_detectors ORDER BY created_at DESC")
        .all() as Record<string, unknown>[];
      void reply.send(
        rows.map((r) => ({
          ...r,
          examples: JSON.parse((r["examples_json"] as string) || "[]"),
        })),
      );
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
    (
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

      const existing = db
        .prepare("SELECT id FROM custom_detectors WHERE regex = ?")
        .get(regex) as { id: string } | undefined;
      if (existing) {
        return void reply.status(409).send({
          error: "Já existe uma regra com essa regex",
          existingId: existing.id,
        });
      }

      const slug = name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "");
      const detectorId = `custom-${slug}-${Date.now().toString(36)}`;
      const ruleId = `rule-${detectorId}`;

      db.prepare(
        "INSERT INTO custom_detectors (id, name, description, regex, severity, action, created_at, examples_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(
        detectorId,
        name,
        description,
        regex,
        severity,
        action,
        new Date().toISOString(),
        JSON.stringify(examples),
      );

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
    (req: FastifyRequest<{ Params: { id: string } }>, reply) => {
      const { id } = req.params;
      const row = db
        .prepare("SELECT id FROM custom_detectors WHERE id = ?")
        .get(id);
      if (!row) return void reply.status(404).send({ error: "Not found" });

      db.prepare("DELETE FROM custom_detectors WHERE id = ?").run(id);

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

  // ── Metrics ────────────────────────────────────────────────────────────────
  fastify.get("/api/metrics", (_req, reply) => {
    const total = (
      db.prepare("SELECT COUNT(*) as n FROM incidents").get() as {
        n: number;
      }
    ).n;
    const byAction = db
      .prepare("SELECT action, COUNT(*) as n FROM incidents GROUP BY action")
      .all() as { action: string; n: number }[];
    const byTool = db
      .prepare(
        "SELECT tool, COUNT(*) as n FROM incidents GROUP BY tool ORDER BY n DESC LIMIT 10",
      )
      .all() as { tool: string; n: number }[];
    const byDay = db
      .prepare(
        `SELECT DATE(timestamp) as day, COUNT(*) as n FROM incidents
         WHERE timestamp >= datetime('now', '-30 days')
         GROUP BY day ORDER BY day DESC`,
      )
      .all() as { day: string; n: number }[];
    const pending = (
      db
        .prepare("SELECT COUNT(*) as n FROM approvals WHERE status = 'pending'")
        .get() as { n: number }
    ).n;
    const auditEntries = (
      db.prepare("SELECT COUNT(*) as n FROM audit_log").get() as { n: number }
    ).n;

    void reply.send({
      total,
      byAction,
      byTool,
      byDay,
      pending,
      auditEntries,
    });
  });

  // ── Audit log ──────────────────────────────────────────────────────────────
  fastify.get("/api/audit", (req, reply) => {
    const q = req.query as Record<string, string>;
    const limit = Math.min(parseInt(q["limit"] ?? "50", 10), 500);
    const offset = parseInt(q["offset"] ?? "0", 10);
    const entries = db
      .prepare("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ? OFFSET ?")
      .all(limit, offset);
    void reply.send(entries);
  });

  fastify.get("/api/audit/verify", (_req, reply) => {
    void reply.send(verifyAuditChain(db));
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

  // Hooks write incidents directly to SQLite from separate processes, so the
  // server polls for new rows to feed connected SSE clients.
  let lastIncidentRowid = (
    db.prepare("SELECT COALESCE(MAX(rowid), 0) AS m FROM incidents").get() as {
      m: number;
    }
  ).m;
  const incidentPoll = setInterval(() => {
    if (sseClients.size === 0) return;
    try {
      const m = (
        db
          .prepare("SELECT COALESCE(MAX(rowid), 0) AS m FROM incidents")
          .get() as { m: number }
      ).m;
      if (m !== lastIncidentRowid) {
        lastIncidentRowid = m;
        broadcast({ type: "incident" });
      }
    } catch {
      // DB momentarily unavailable — retry on next tick
    }
  }, 3000);
  incidentPoll.unref();
  fastify.addHook("onClose", (_instance, done) => {
    clearInterval(incidentPoll);
    done();
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
