import { homedir } from "node:os";
import { join } from "node:path";
import type { Config } from "../types/index.ts";

export function expandHome(p: string): string {
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

export const DEFAULT_DB_PATH = join(
  homedir(),
  ".local",
  "share",
  "claude-guardian",
  "guardian.db",
);

export const DEFAULT_LOG_FILE = join(
  homedir(),
  ".local",
  "share",
  "claude-guardian",
  "guardian.log",
);

export const DEFAULT_CONFIG_DIR = join(homedir(), ".config", "claude-guardian");
export const DEFAULT_CONFIG_PATH = join(DEFAULT_CONFIG_DIR, "config.json");

export const DEFAULT_CONFIG: Config = {
  dbPath: DEFAULT_DB_PATH,
  logFile: DEFAULT_LOG_FILE,
  logLevel: "info",
  dashboardPort: 7734,
  dashboardToken: "",
  engineTimeoutMs: 500,
  databaseUrl: "",
  agentApiKey: "",
  enrollmentSecret: "",
  allowLegacyAgentKey: true,
  centralUrl: "",
  centralApiKey: "",
  substitutionSalt: "",
  entityDetection: false,
  entityStopwords: [],
  blockedWebModels: [],
  policies: [
    {
      id: "block-critical-secrets",
      name: "Block critical secrets in all tools",
      enabled: true,
      dataTypes: [
        "aws-key",
        "private-key",
        "anthropic-key",
        "openai-key",
        "github-token",
      ],
      minSeverity: "critical",
      action: "block",
    },
    {
      id: "block-high-secrets",
      name: "Block high-severity secrets",
      enabled: true,
      dataTypes: [
        "gcp-key",
        "gitlab-token",
        "jwt",
        "stripe-key",
        "slack-token",
        "connection-string",
      ],
      minSeverity: "high",
      action: "block",
    },
    {
      id: "block-generic-secrets",
      name: "Block generic secrets and env assignments",
      enabled: true,
      dataTypes: ["generic-secret"],
      minSeverity: "medium",
      action: "block",
    },
    {
      id: "block-pii",
      name: "Block PII",
      enabled: true,
      dataTypes: [
        "email",
        "credit-card",
        "ssn",
        "cpf",
        "cnpj",
        "iban",
        "phone-br",
      ],
      action: "block",
    },
  ],
  allowlist: [],
};
