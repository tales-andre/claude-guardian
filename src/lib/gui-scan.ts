import type BetterSqlite3 from "better-sqlite3";
import { loadCustomDetectors } from "../engine/detectors/custom.ts";
import { buildEntityDetectors } from "../engine/detectors/entity.ts";
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

// ── Scan para o proxy HTTPS do GUI Gateway (Claude Desktop) ──────────────────
// Espelha scanWeb/scanMcp. Recebe o corpo decifrado da request para a API da
// Anthropic e escaneia prompt + anexos, reusando engine/policy/audit/central.

export const DESKTOP_PROMPT_TOOL = "DesktopPrompt";
export const DESKTOP_UPLOAD_TOOL = "DesktopUpload";

export interface GuiScanRequest {
  bodyText: string;
  host: string;
  path: string;
}

export interface GuiScanFinding {
  detectorId: string;
  label: string;
  dataType: string;
  severity: string;
  snippet: string;
}

export interface GuiScanResponse {
  action: PolicyAction;
  findings: GuiScanFinding[];
  /** Corpo da request reescrito com dados fictícios (ação substitute). */
  substitutedText?: string;
  approvalUrl?: string;
  reason: string;
}

const ACTION_PRIORITY: Record<PolicyAction, number> = {
  block: 5,
  "require-approval": 4,
  substitute: 3,
  redact: 2,
  allow: 1,
};

function toFinding(f: DetectorFinding): GuiScanFinding {
  return {
    detectorId: f.detectorId,
    label: f.label,
    dataType: f.dataType,
    severity: f.severity,
    snippet: f.snippet,
  };
}

function parseJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

/**
 * Extrai o texto do prompt e o conteúdo dos anexos do corpo da request.
 * Best-effort para os formatos conhecidos (prompt/messages/attachments); se o
 * schema for desconhecido, devolve o corpo INTEIRO como prompt (fail-safe: nada
 * sai sem scan). Mesma leitura de attachments[].extracted_content do adapter web.
 */
export function extractGuiText(bodyText: string): {
  promptText: string;
  uploadText: string;
} {
  const json = parseJson(bodyText) as Record<string, unknown> | null;
  if (!json || typeof json !== "object") {
    return { promptText: bodyText, uploadText: "" };
  }
  const prompt: string[] = [];
  const upload: string[] = [];

  if (typeof json["prompt"] === "string") prompt.push(json["prompt"] as string);
  const messages = json["messages"];
  if (Array.isArray(messages)) {
    for (const m of messages) {
      const c = (m as { content?: unknown })?.content;
      if (typeof c === "string") prompt.push(c);
      else if (Array.isArray(c)) {
        for (const part of c) {
          const t = (part as { text?: unknown })?.text;
          if (typeof t === "string") prompt.push(t);
        }
      }
    }
  }
  const attachments = json["attachments"];
  if (Array.isArray(attachments)) {
    for (const a of attachments) {
      const ex = (a as { extracted_content?: unknown })?.extracted_content;
      const name = (a as { file_name?: unknown })?.file_name;
      if (typeof ex === "string") upload.push(ex);
      if (typeof name === "string") upload.push(name);
    }
  }

  // Se não reconhecemos nada mas o corpo tem conteúdo, escaneia o corpo inteiro
  // como prompt — melhor um falso-positivo raro do que deixar um segredo passar.
  if (prompt.length === 0 && upload.length === 0 && bodyText.trim()) {
    return { promptText: bodyText, uploadText: "" };
  }
  return { promptText: prompt.join("\n"), uploadText: upload.join("\n") };
}

function failClosed(): GuiScanResponse {
  return {
    action: "block",
    findings: [
      {
        detectorId: "engine-timeout",
        label: "Scan timeout (Desktop)",
        dataType: "generic-secret",
        severity: "critical",
        snippet: "(timeout)",
      },
    ],
    reason: "Timeout ao escanear — bloqueado por segurança (fail-closed).",
  };
}

/**
 * Core scan do proxy HTTPS (Claude Desktop). Reusa o mesmo engine/policy/audit.
 * Fail-closed no timeout.
 */
export function scanGui(
  db: BetterSqlite3.Database,
  config: Config,
  req: GuiScanRequest,
): GuiScanResponse {
  const sessionId = `desktop:${req.host}${req.path}`;
  const extraDetectors: Detector[] = [
    gitleaksDetector,
    ...loadCustomDetectors(db),
  ];
  if (config.entityDetection)
    extraDetectors.push(...buildEntityDetectors(config.entityStopwords));
  const { promptText, uploadText } = extractGuiText(req.bodyText);

  let promptFindings: DetectorFinding[] = [];
  if (promptText) {
    const r = scanSync(promptText, {
      timeoutMs: config.engineTimeoutMs,
      allowlist: config.allowlist,
      extraDetectors,
    });
    if (r.timedOut) return failClosed();
    promptFindings = r.findings;
  }
  let uploadFindings: DetectorFinding[] = [];
  if (uploadText) {
    const r = scanSync(uploadText, {
      timeoutMs: config.engineTimeoutMs,
      allowlist: config.allowlist,
      extraDetectors,
    });
    if (r.timedOut) return failClosed();
    uploadFindings = r.findings;
  }

  const promptAction = evaluatePolicy(
    promptFindings,
    DESKTOP_PROMPT_TOOL,
    config.policies,
  );
  const uploadAction = evaluatePolicy(
    uploadFindings,
    DESKTOP_UPLOAD_TOOL,
    config.policies,
  );
  const promptWins =
    ACTION_PRIORITY[promptAction] >= ACTION_PRIORITY[uploadAction];
  const action = promptWins ? promptAction : uploadAction;
  const tool = promptWins ? DESKTOP_PROMPT_TOOL : DESKTOP_UPLOAD_TOOL;
  const winningFindings = promptWins ? promptFindings : uploadFindings;
  const allFindings = [...promptFindings, ...uploadFindings];

  if (action === "allow" || allFindings.length === 0) {
    return { action: "allow", findings: [], reason: "Nenhum dado sensível." };
  }

  const dataTypes = [
    ...new Set(winningFindings.map((f) => f.dataType)),
  ] as DataType[];
  const scope = buildScope(tool, dataTypes);
  if (findActiveApproval(db, scope)) {
    return {
      action: "allow",
      findings: [],
      reason: "Liberação ativa para o escopo.",
    };
  }

  if (action === "substitute") {
    let substitutedText: string;
    try {
      // Reescreve o CORPO inteiro da request: troca cada valor sensível pelo
      // seu fake onde quer que apareça no JSON, preservando a estrutura.
      substitutedText = substituteText(
        req.bodyText,
        allFindings,
        config.substitutionSalt,
      );
    } catch {
      return failClosed();
    }
    const incident = recordIncident(
      db,
      tool,
      sessionId,
      allFindings,
      "substitute",
    );
    appendAuditEntry(db, "substitute", {
      incidentId: incident.id,
      tool,
      dataTypes: incident.dataTypes,
    });
    reportToCentral(config, incident, allFindings, null, "substitute");
    return {
      action: "substitute",
      findings: allFindings.map(toFinding),
      substitutedText,
      reason: "Dado sensível substituído por valores fictícios no envio.",
    };
  }

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
      `Desktop: ${req.host}`,
      findApprovalTtl(winningFindings, tool, config.policies),
    );
    appendAuditEntry(db, "approval-requested", {
      approvalId: approval.id,
      incidentId: incident.id,
      scope,
      requestedBy: "desktop-proxy",
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
      findings: allFindings.map(toFinding),
      approvalUrl: `${dashboardBaseUrl(config)}/request-approval/${incident.id}`,
      reason: "Aprovação necessária para o envio do Claude Desktop.",
    };
  }

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
    findings: allFindings.map(toFinding),
    approvalUrl: `${dashboardBaseUrl(config)}/request-approval/${incident.id}`,
    reason: "Envio do Claude Desktop bloqueado: dado sensível detectado.",
  };
}
