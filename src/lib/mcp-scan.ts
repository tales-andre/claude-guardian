import type BetterSqlite3 from "better-sqlite3";
import { loadCustomDetectors } from "../engine/detectors/custom.ts";
import { entityDetectors } from "../engine/detectors/entity.ts";
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
import { substituteText } from "./substitute.ts";

// ── Scan para o proxy MCP (Claude Desktop / Kiro IDE) ────────────────────────
// Reusa o mesmo engine/policy/approval/audit dos hooks e da extensão. Roda
// in-process no shim (src/proxy/mcp-proxy.ts), sem depender do daemon para
// bloquear — igual aos hooks do Claude Code.

// Tools virtuais para casar policy `tools:` separadamente dos hooks/extensão.
export const MCP_CALL_TOOL = "McpToolCall"; // egress: argumentos que o modelo envia a um tool
export const MCP_RESULT_TOOL = "McpToolResult"; // ingress: dado que um tool devolve

export interface McpScanRequest {
  tool: typeof MCP_CALL_TOOL | typeof MCP_RESULT_TOOL;
  serverName: string;
  toolName: string;
  text: string;
}

export interface McpScanFinding {
  detectorId: string;
  label: string;
  dataType: string;
  severity: string;
  snippet: string;
}

export interface McpScanResponse {
  action: PolicyAction;
  findings: McpScanFinding[];
  redactedText?: string;
  /** Texto reescrito com dados fictícios (ação substitute). */
  substitutedText?: string;
  approvalUrl?: string;
  reason: string;
}

function toFinding(f: DetectorFinding): McpScanFinding {
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

function failClosed(tool: string): McpScanResponse {
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

/**
 * Scan de uma peça MCP (argumentos de tools/call OU conteúdo de resultado).
 * Reusa engine/policy/approval/audit dos hooks. Fail-closed no timeout.
 */
export function scanMcp(
  db: BetterSqlite3.Database,
  config: Config,
  req: McpScanRequest,
): McpScanResponse {
  const sessionId = `mcp:${req.serverName}/${req.toolName}`;
  const extraDetectors: Detector[] = [
    gitleaksDetector,
    ...loadCustomDetectors(db),
    ...(config.entityDetection ? entityDetectors : []),
  ];

  const res = scanSync(req.text, {
    timeoutMs: config.engineTimeoutMs,
    allowlist: config.allowlist,
    extraDetectors,
  });
  if (res.timedOut) return failClosed(req.tool);

  const findings = res.findings;
  const action = evaluatePolicy(findings, req.tool, config.policies);

  if (action === "allow" || findings.length === 0) {
    return { action: "allow", findings: [], reason: "Nenhum dado sensível." };
  }

  if (action === "substitute") {
    let substitutedText: string;
    try {
      substitutedText = substituteText(
        req.text,
        findings,
        config.substitutionSalt,
      );
    } catch {
      return failClosed(req.tool);
    }
    const incident = recordIncident(
      db,
      req.tool,
      sessionId,
      findings,
      "substitute",
    );
    appendAuditEntry(db, "substitute", {
      incidentId: incident.id,
      tool: req.tool,
      dataTypes: incident.dataTypes,
    });
    reportToCentral(config, incident, findings, null, "substitute");
    return {
      action: "substitute",
      findings: findings.map(toFinding),
      substitutedText,
      reason: "Dado sensível substituído por valores fictícios no tráfego MCP.",
    };
  }

  if (action === "redact") {
    const incident = recordIncident(
      db,
      req.tool,
      sessionId,
      findings,
      "redact",
    );
    appendAuditEntry(db, "redact", {
      incidentId: incident.id,
      tool: req.tool,
      dataTypes: incident.dataTypes,
    });
    reportToCentral(config, incident, findings, null, "redact");
    return {
      action: "redact",
      findings: findings.map(toFinding),
      redactedText: redactText(req.text, findings),
      reason: "Dado sensível redigido no tráfego MCP.",
    };
  }

  const dataTypes = [...new Set(findings.map((f) => f.dataType))] as DataType[];
  const scope = buildScope(req.tool, dataTypes);
  if (findActiveApproval(db, scope)) {
    return {
      action: "allow",
      findings: [],
      reason: "Liberação ativa para o escopo.",
    };
  }

  if (action === "require-approval") {
    const incident = recordIncident(
      db,
      req.tool,
      sessionId,
      findings,
      "require-approval",
    );
    const approval = createApproval(
      db,
      incident.id,
      scope,
      `MCP: ${sessionId}`,
      findApprovalTtl(findings, req.tool, config.policies),
    );
    appendAuditEntry(db, "approval-requested", {
      approvalId: approval.id,
      incidentId: incident.id,
      scope,
      requestedBy: "mcp-proxy",
    });
    reportToCentral(config, incident, findings, approval, "approval-requested");
    return {
      action: "require-approval",
      findings: findings.map(toFinding),
      approvalUrl: `${dashboardBaseUrl(config)}/request-approval/${incident.id}`,
      reason: "Aprovação necessária para o tráfego MCP.",
    };
  }

  const incident = recordIncident(db, req.tool, sessionId, findings, "block");
  appendAuditEntry(db, "block", {
    incidentId: incident.id,
    tool: req.tool,
    dataTypes: incident.dataTypes,
    severities: incident.severities,
  });
  reportToCentral(config, incident, findings, null, "block");
  return {
    action: "block",
    findings: findings.map(toFinding),
    approvalUrl: `${dashboardBaseUrl(config)}/request-approval/${incident.id}`,
    reason: "Tráfego MCP bloqueado: dado sensível detectado.",
  };
}
