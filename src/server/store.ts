import type {
  AgentIngestPayload,
  Approval,
  ApprovalStatus,
  AuditEntry,
  Config,
  Incident,
  MachineHeartbeatPayload,
  MachineRow,
} from "../types/index.ts";

// ── Camada de storage do servidor ─────────────────────────────────────────────
// O dashboard pode rodar em dois modos:
//   - local  (SQLite, mesmo arquivo usado pelos hooks — comportamento original)
//   - central (PostgreSQL via databaseUrl/DATABASE_URL — deploy em Docker/EKS)
// Os hooks NUNCA usam esta camada: continuam síncronos sobre better-sqlite3.

export interface CustomDetectorRow {
  id: string;
  name: string;
  description: string;
  regex: string;
  severity: string;
  action: string;
  created_at: string;
  examples: string[];
}

export interface MetricsResult {
  total: number;
  byAction: { action: string; n: number }[];
  byTool: { tool: string; n: number }[];
  byDay: { day: string; n: number }[];
  pending: number;
  auditEntries: number;
}

export interface AuditVerifyResult {
  valid: boolean;
  firstTamperedSeq: number | null;
  totalEntries: number;
}

export interface GuardianStore {
  readonly kind: "sqlite" | "postgres";

  init(): Promise<void>;
  close(): Promise<void>;

  // Incidents
  listIncidents(limit: number, offset: number): Promise<Incident[]>;
  getIncidentById(id: string): Promise<Incident | null>;
  /** Marcador monotônico usado pelo polling do SSE (rowid/serial máximo). */
  latestIncidentMark(): Promise<number>;

  // Approvals
  listApprovals(status?: ApprovalStatus): Promise<Approval[]>;
  getApprovalById(id: string): Promise<Approval | null>;
  createApproval(
    incidentId: string,
    scope: string,
    justification: string,
    ttlSeconds: number,
  ): Promise<Approval>;
  resolveApproval(
    id: string,
    status: "approved" | "denied",
    resolvedBy: string,
    ttlSeconds?: number,
  ): Promise<Approval | null>;
  findActiveApproval(scope: string): Promise<Approval | null>;

  // Audit log
  appendAuditEntry(type: string, payload: object): Promise<AuditEntry>;
  listAudit(limit: number, offset: number): Promise<Record<string, unknown>[]>;
  verifyAuditChain(): Promise<AuditVerifyResult>;

  // Metrics
  metrics(): Promise<MetricsResult>;

  // Custom detectors
  listCustomDetectors(): Promise<CustomDetectorRow[]>;
  findCustomDetectorIdByRegex(regex: string): Promise<string | null>;
  createCustomDetector(row: {
    id: string;
    name: string;
    description: string;
    regex: string;
    severity: string;
    action: string;
    createdAt: string;
    examples: string[];
  }): Promise<void>;
  deleteCustomDetector(id: string): Promise<boolean>;

  // Agent ingest (modo central)
  ingestAgentEvent(
    payload: AgentIngestPayload,
  ): Promise<{ incidentId: string }>;

  // Fleet (heartbeats de máquina)
  upsertMachine(payload: MachineHeartbeatPayload): Promise<void>;
  listMachines(): Promise<MachineRow[]>;
}

export async function createStore(config: Config): Promise<GuardianStore> {
  if (config.databaseUrl) {
    const { PgStore } = await import("./pg-store.ts");
    const store = new PgStore(config.databaseUrl);
    await store.init();
    return store;
  }
  const { SqliteStore } = await import("./sqlite-store.ts");
  const store = new SqliteStore(config.dbPath);
  await store.init();
  return store;
}
