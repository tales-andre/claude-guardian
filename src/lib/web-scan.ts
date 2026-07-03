import { basename } from "node:path";
import type BetterSqlite3 from "better-sqlite3";
import { loadCustomDetectors } from "../engine/detectors/custom.ts";
import { gitleaksDetector } from "../engine/detectors/gitleaks.ts";
import type { Detector } from "../engine/detectors/types.ts";
import { scanSync } from "../engine/index.ts";
import type {
  Config,
  DataType,
  DetectorFinding,
  PolicyAction,
} from "../types/index.ts";
import { buildScope, createApproval, findActiveApproval } from "./approval.ts";
import { appendAuditEntry } from "./audit.ts";
import { dashboardBaseUrl, reportToCentral } from "./central.ts";
import { recordIncident } from "./incident.ts";
import { evaluatePolicy, findApprovalTtl } from "./policy.ts";

// ── Scan para a extensão de navegador (POST /api/scan-web) ───────────────────
// O scan roda 100% na máquina (daemon local): o texto do prompt/upload nunca
// sai daqui. Em modo enterprise, apenas metadados do incidente são espelhados
// ao central via outbox (mesmo store-and-forward dos hooks).

// Tools virtuais para que eventos de navegador possam ser casados por policy
// `tools:` separadamente dos hooks do Claude Code.
export const WEB_PROMPT_TOOL = "WebPrompt";
export const WEB_UPLOAD_TOOL = "WebUpload";

// Uploads recusados por nome/extensão — conteúdo de binários (PDF, imagens,
// archives) não é escaneável pela extensão, espelhando o block de `.env` por
// nome no pre-tool-use.
const BLOCKED_FILE_RE =
  /(^\.env($|\.)|\.(pem|key|pfx|p12|pkcs12|keystore|jks|ppk|asc|gpg)$|(^|\/)id_(rsa|dsa|ecdsa|ed25519)$)/i;

export interface WebScanFile {
  name: string;
  content?: string;
}

export interface WebScanRequest {
  text?: string;
  files?: WebScanFile[];
  context?: { url?: string; tabTitle?: string };
}

export interface WebScanFinding {
  detectorId: string;
  label: string;
  dataType: string;
  severity: string;
  snippet: string;
}

export interface WebScanResponse {
  action: PolicyAction;
  findings: WebScanFinding[];
  redactedText?: string;
  approvalUrl?: string;
  reason: string;
}

const ACTION_PRIORITY: Record<PolicyAction, number> = {
  block: 4,
  "require-approval": 3,
  redact: 2,
  allow: 1,
};

function nameBlockFinding(name: string): DetectorFinding {
  const base = basename(name);
  return {
    detectorId: "upload-file-name",
    label: "Sensitive file (name-based block)",
    dataType: "private-key",
    severity: "critical",
    snippet: base,
    rawValue: base,
    position: { start: 0, end: base.length },
    confidence: 1,
  };
}

function toWebFinding(f: DetectorFinding): WebScanFinding {
  return {
    detectorId: f.detectorId,
    label: f.label,
    dataType: f.dataType,
    severity: f.severity,
    snippet: f.snippet,
  };
}

function redactText(text: string, findings: DetectorFinding[]): string {
  let out = text;
  for (const f of findings) {
    if (!f.rawValue) continue;
    out = out.split(f.rawValue).join(`[REDACTED:${f.detectorId}]`);
  }
  return out;
}

/**
 * Core scan usado pela extensão de navegador via POST /api/scan-web.
 * Reusa o mesmo engine, policy, approval e audit dos hooks.
 * Fail-closed: timeout de scan sempre bloqueia.
 */
export function scanWeb(
  db: BetterSqlite3.Database,
  config: Config,
  req: WebScanRequest,
): WebScanResponse {
  const text = req.text ?? "";
  const files = req.files ?? [];
  const sessionId = req.context?.url ?? "web";

  const extraDetectors: Detector[] = [
    gitleaksDetector,
    ...loadCustomDetectors(db),
  ];

  // ── Scan do texto do prompt (WebPrompt) ───────────────────────────────────
  let textFindings: DetectorFinding[] = [];
  if (text) {
    const res = scanSync(text, {
      timeoutMs: config.engineTimeoutMs,
      allowlist: config.allowlist,
      extraDetectors,
    });
    if (res.timedOut) {
      return failClosed("WebPrompt");
    }
    textFindings = res.findings;
  }

  // ── Scan de uploads (WebUpload): block por nome + conteúdo de texto ────────
  const fileFindings: DetectorFinding[] = [];
  for (const file of files) {
    if (
      BLOCKED_FILE_RE.test(file.name) ||
      BLOCKED_FILE_RE.test(basename(file.name))
    ) {
      fileFindings.push(nameBlockFinding(file.name));
      continue;
    }
    if (file.content) {
      const res = scanSync(file.content, {
        timeoutMs: config.engineTimeoutMs,
        allowlist: config.allowlist,
        extraDetectors,
      });
      if (res.timedOut) {
        return failClosed("WebUpload");
      }
      fileFindings.push(...res.findings);
    }
  }

  const textAction = evaluatePolicy(
    textFindings,
    WEB_PROMPT_TOOL,
    config.policies,
  );
  const fileAction = evaluatePolicy(
    fileFindings,
    WEB_UPLOAD_TOOL,
    config.policies,
  );

  // O lado vencedor dirige a decisão, o tool do incidente e o scope da approval.
  const textWins = ACTION_PRIORITY[textAction] >= ACTION_PRIORITY[fileAction];
  const action = textWins ? textAction : fileAction;
  const tool = textWins ? WEB_PROMPT_TOOL : WEB_UPLOAD_TOOL;
  const winningFindings = textWins ? textFindings : fileFindings;
  const allFindings = [...textFindings, ...fileFindings];

  if (action === "allow" || allFindings.length === 0) {
    return {
      action: "allow",
      findings: [],
      reason: "Nenhum dado sensível detectado.",
    };
  }

  // ── Redact (somente texto) ────────────────────────────────────────────────
  if (action === "redact") {
    const incident = recordIncident(db, tool, sessionId, allFindings, "redact");
    appendAuditEntry(db, "redact", {
      incidentId: incident.id,
      tool,
      dataTypes: incident.dataTypes,
    });
    reportToCentral(config, incident, allFindings, null, "redact");
    return {
      action: "redact",
      findings: allFindings.map(toWebFinding),
      redactedText: redactText(text, textFindings),
      reason: "Dado sensível redigido. Confirme o envio do texto mascarado.",
    };
  }

  // ── Aprovação ativa dispensa block/require-approval no mesmo scope ─────────
  const dataTypes = [
    ...new Set(winningFindings.map((f) => f.dataType)),
  ] as DataType[];
  const scope = buildScope(tool, dataTypes);
  if (findActiveApproval(db, scope)) {
    return {
      action: "allow",
      findings: [],
      reason: "Liberação ativa para este escopo — envio permitido.",
    };
  }

  // ── Require approval: abre solicitação pendente e bloqueia até resolver ────
  if (action === "require-approval") {
    const incident = recordIncident(
      db,
      tool,
      sessionId,
      winningFindings,
      "require-approval",
    );
    const approval = createApproval(
      db,
      incident.id,
      scope,
      `Web: ${req.context?.url ?? "browser"}`,
      findApprovalTtl(winningFindings, tool, config.policies),
    );
    appendAuditEntry(db, "approval-requested", {
      approvalId: approval.id,
      incidentId: incident.id,
      scope,
      requestedBy: "web-extension",
    });
    reportToCentral(
      config,
      incident,
      winningFindings,
      approval,
      "approval-requested",
    );
    return {
      action: "require-approval",
      findings: allFindings.map(toWebFinding),
      approvalUrl: `${dashboardBaseUrl(config)}/request-approval/${incident.id}`,
      reason:
        "Aprovação necessária. Solicite a liberação e tente novamente após aprovação.",
    };
  }

  // ── Block ─────────────────────────────────────────────────────────────────
  const incident = recordIncident(
    db,
    tool,
    sessionId,
    winningFindings,
    "block",
  );
  appendAuditEntry(db, "block", {
    incidentId: incident.id,
    tool,
    dataTypes: incident.dataTypes,
    severities: incident.severities,
  });
  reportToCentral(config, incident, winningFindings, null, "block");
  return {
    action: "block",
    findings: allFindings.map(toWebFinding),
    approvalUrl: `${dashboardBaseUrl(config)}/request-approval/${incident.id}`,
    reason: "Envio bloqueado: dado sensível detectado.",
  };
}

function failClosed(tool: string): WebScanResponse {
  return {
    action: "block",
    findings: [
      {
        detectorId: "engine-timeout",
        label: `Scan timeout (${tool})`,
        dataType: "generic-secret",
        severity: "critical",
        snippet: "(timeout)",
      },
    ],
    reason: "Timeout ao escanear — bloqueado por segurança (fail-closed).",
  };
}
