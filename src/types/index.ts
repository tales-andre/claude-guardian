// ── Core domain types ─────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low";

export type DataType =
  | "aws-key"
  | "gcp-key"
  | "github-token"
  | "gitlab-token"
  | "jwt"
  | "private-key"
  | "slack-token"
  | "stripe-key"
  | "openai-key"
  | "anthropic-key"
  | "connection-string"
  | "generic-secret"
  | "npm-token"
  | "sendgrid-key"
  | "mailgun-key"
  | "twilio-sid"
  | "discord-webhook"
  | "email"
  | "credit-card"
  | "ssn"
  | "cpf"
  | "cnpj"
  | "iban"
  | "phone-us"
  | "phone-br"
  | "phone-jp"
  | "private-ip"
  | "person-name"
  | "postal-address"
  | string;

export type PolicyAction =
  | "allow"
  | "block"
  | "require-approval"
  | "redact"
  | "substitute";

// ── Detector finding ──────────────────────────────────────────────────────────

export interface DetectorFinding {
  detectorId: string;
  label: string;
  dataType: DataType;
  severity: Severity;
  snippet: string;
  rawValue: string;
  position: { start: number; end: number };
  confidence: number;
}

// ── Scan result from the engine ───────────────────────────────────────────────

export interface ScanResult {
  findings: DetectorFinding[];
  elapsedMs: number;
  timedOut: boolean;
}

// ── Hook adapter decision ─────────────────────────────────────────────────────

export interface Decision {
  action: PolicyAction;
  findings: DetectorFinding[];
  incidentId: string | null;
  reason: string;
}

// ── Persisted incident record (no raw values) ─────────────────────────────────

export interface Incident {
  id: string;
  timestamp: string;
  tool: string;
  sessionId: string;
  username: string;
  hostname: string;
  context: string;
  dataTypes: DataType[];
  severities: Severity[];
  findingsJson: string;
  action: PolicyAction;
  approvalId: string | null;
}

// ── Agent → central server ingest payload ─────────────────────────────────────
// Enviado pelos hooks das máquinas-cliente ao servidor central. Os findings
// NUNCA incluem rawValue — segredos brutos não saem da máquina de origem.

export interface AgentIngestPayload {
  machine: { hostname: string; username: string };
  incident: {
    id: string;
    timestamp: string;
    tool: string;
    sessionId: string;
    context: string;
    dataTypes: DataType[];
    severities: Severity[];
    findings: Array<{
      detectorId: string;
      label: string;
      dataType: string;
      severity: string;
      snippet: string;
      confidence: number;
    }>;
    action: PolicyAction;
  };
  approval?: {
    id: string;
    scope: string;
    justification: string;
    ttlSeconds: number;
    requestedAt: string;
  } | null;
  auditType: string;
}

// ── Fleet heartbeat ───────────────────────────────────────────────────────────
// Enviado periodicamente por cada máquina-cliente ao central. O hash da config
// managed efetiva permite ao admin detectar adulteração (status "tampered").

export interface ExtensionHeartbeat {
  version: string;
  /** Falhas de extractText por provider (sinal de drift de endpoint). */
  extractFailures?: Record<string, number>;
}

export interface MachineHeartbeatPayload {
  machine: { hostname: string; username: string };
  guardianVersion: string;
  configHash: string;
  /** null/ausente = máquina sem extensão de navegador reportando. */
  extension?: ExtensionHeartbeat | null;
}

export interface MachineRow {
  hostname: string;
  username: string;
  guardianVersion: string;
  configHash: string;
  extensionVersion: string;
  extensionLastSeen: string;
  extractFailures: Record<string, number>;
  lastSeen: string;
}

// ── Audit log entry (chained hash) ────────────────────────────────────────────

export interface AuditEntry {
  seq: number;
  timestamp: string;
  type: string;
  payload: string;
  prevHash: string;
  hash: string;
}

// ── Approval request ──────────────────────────────────────────────────────────

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface Approval {
  id: string;
  incidentId: string;
  scope: string;
  justification: string;
  status: ApprovalStatus;
  token: string;
  requestedAt: string;
  resolvedAt: string | null;
  resolvedBy: string | null;
  ttlSeconds: number;
  expiresAt: string | null;
}

// ── Policy rule ───────────────────────────────────────────────────────────────

export interface PolicyRule {
  id: string;
  name: string;
  enabled: boolean;
  dataTypes?: DataType[];
  tools?: string[];
  detectorIds?: string[];
  minSeverity?: Severity;
  action: PolicyAction;
  ttlSeconds?: number;
}

// ── Allowlist entry ───────────────────────────────────────────────────────────

export interface AllowlistEntry {
  id: string;
  pattern: string;
  isRegex: boolean;
  detectorIds?: string[];
  reason: string;
  expiresAt?: string;
}

// ── Config ────────────────────────────────────────────────────────────────────

export interface Config {
  dbPath: string;
  logFile: string;
  logLevel: string;
  dashboardPort: number;
  dashboardToken: string;
  engineTimeoutMs: number;
  policies: PolicyRule[];
  allowlist: AllowlistEntry[];
  // ── Enterprise (opcional — vazio mantém o modo local intacto) ──────────────
  /** Servidor: URL de conexão Postgres; vazio = SQLite local. */
  databaseUrl: string;
  /** Servidor: chave compartilhada exigida nos endpoints /api/agent/*. */
  agentApiKey: string;
  /** Cliente: URL pública do servidor central (ex.: https://guardian.empresa.com). */
  centralUrl: string;
  /** Cliente: chave usada pelos hooks para reportar ao servidor central. */
  centralApiKey: string;
  // ── Substituição por placeholders fictícios (opcional) ─────────────────────
  /**
   * Salt que semeia os geradores de valores fictícios da ação `substitute`.
   * Vazio = salt público padrão (ainda determinístico). Defina um segredo por
   * instalação para evitar correlação de fakes entre organizações.
   */
  substitutionSalt: string;
  /**
   * Liga o detector de entidades (nomes/endereços) como extraDetector nas
   * superfícies de egress. Vazio/false = comportamento local inalterado.
   */
  entityDetection: boolean;
}
