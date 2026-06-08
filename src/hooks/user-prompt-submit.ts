#!/usr/bin/env -S node --experimental-strip-types

import { existsSync } from "node:fs";
import { join } from "node:path";

if (existsSync(join(process.cwd(), ".guardian-bypass"))) process.exit(0);

import { loadConfig } from "../config/loader.ts";
import { getDb } from "../db/client.ts";
import { loadCustomDetectors } from "../engine/detectors/custom.ts";
import { gitleaksDetector } from "../engine/detectors/gitleaks.ts";
import { scanSync } from "../engine/index.ts";
import { appendAuditEntry } from "../lib/audit.ts";
import { buildScope, createApproval, findActiveApproval } from "../lib/approval.ts";
import {
  buildBlockReason,
  extractExceptionRequest,
  recordIncident,
} from "../lib/incident.ts";
import { evaluatePolicy, findApprovalTtl } from "../lib/policy.ts";
import type { DataType } from "../types/index.ts";

// ── Hook contract ─────────────────────────────────────────────────────────────
// Input:  JSON on stdin — { session_id?, prompt }
// Output: JSON on stdout para block — { decision: "block", reason: "..." }
//         OU para redact — { hookSpecificOutput: { updatedPrompt: "..." } }
// Exit 0: allow  |  Exit 2: block

interface HookInput {
  session_id?: string;
  prompt?: string;
}

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  const config = loadConfig();
  let data: HookInput;

  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    process.exit(0);
  }

  const prompt = data.prompt ?? "";
  const sessionId = data.session_id ?? "";

  if (!prompt) process.exit(0);

  // [allow-guardian] — bypass explícito, registra no audit log mas permite.
  if (prompt.includes("[allow-guardian]")) {
    process.exit(0);
  }

  const db = getDb(config.dbPath);
  const customDetectors = loadCustomDetectors(db);

  // gitleaksDetector runs as an extraDetector so it only fires on user prompts
  // (not on every pre-tool-use file scan), keeping per-call latency acceptable.
  const { findings, timedOut } = scanSync(prompt, {
    timeoutMs: config.engineTimeoutMs,
    allowlist: config.allowlist,
    extraDetectors: [gitleaksDetector, ...customDetectors],
  });

  if (timedOut) {
    process.stdout.write(
      JSON.stringify({
        decision: "block",
        reason: "claude-guardian: timeout ao escanear o prompt — bloqueado por segurança",
      }) + "\n",
    );
    process.exit(2);
  }

  if (findings.length === 0) process.exit(0);

  const action = evaluatePolicy(findings, "UserPromptSubmit", config.policies);
  if (action === "allow") process.exit(0);

  // ── Redact ────────────────────────────────────────────────────────────────
  if (action === "redact") {
    let redacted = prompt;
    for (const f of findings) {
      redacted = redacted.split(f.rawValue).join(`[REDACTED:${f.detectorId}]`);
    }
    process.stdout.write(
      JSON.stringify({ hookSpecificOutput: { updatedPrompt: redacted } }) + "\n",
    );
    const incident = recordIncident(db, "UserPromptSubmit", sessionId, findings, "redact");
    appendAuditEntry(db, "redact", {
      incidentId: incident.id,
      tool: "UserPromptSubmit",
      dataTypes: incident.dataTypes,
    });
    process.exit(0);
  }

  // ── Verifica aprovação ativa via scope ─────────────────────────────────────
  const dataTypes = [...new Set(findings.map((f) => f.dataType))] as DataType[];
  const scope = buildScope("UserPromptSubmit", dataTypes);
  const active = findActiveApproval(db, scope);
  if (active) process.exit(0);

  // ── [request-exception: motivo] — usuário solicita exceção inline ──────────
  const exceptionRequest = extractExceptionRequest(prompt);
  if (exceptionRequest) {
    const incident = recordIncident(db, "UserPromptSubmit", sessionId, findings, "block");
    const approval = createApproval(
      db,
      incident.id,
      scope,
      exceptionRequest,
      findApprovalTtl(findings, "UserPromptSubmit", config.policies),
    );
    appendAuditEntry(db, "approval-requested", {
      approvalId: approval.id,
      incidentId: incident.id,
      scope,
      reason: exceptionRequest,
      requestedBy: "user-prompt-tag",
    });

    const reason = [
      "claude-guardian: solicitação de exceção registrada",
      "",
      `  Dado sensível: ${findings.map((f) => f.label).join(", ")}`,
      `  Justificativa: ${exceptionRequest}`,
      `  Approval ID:   ${approval.id}`,
      "",
      "Sua solicitação foi enviada e está pendente de aprovação pelo administrador.",
      "Após a aprovação, repita o prompt normalmente.",
    ].join("\n");

    process.stdout.write(JSON.stringify({ decision: "block", reason }) + "\n");
    process.exit(2);
  }

  // ── Block normal ───────────────────────────────────────────────────────────
  const incident = recordIncident(db, "UserPromptSubmit", sessionId, findings, action);
  appendAuditEntry(db, "block", {
    incidentId: incident.id,
    tool: "UserPromptSubmit",
    dataTypes: incident.dataTypes,
    severities: incident.severities,
  });

  const reason = buildBlockReason("UserPromptSubmit", findings, incident.id, config.dashboardPort);
  process.stdout.write(JSON.stringify({ decision: "block", reason }) + "\n");
  process.exit(2);
});
