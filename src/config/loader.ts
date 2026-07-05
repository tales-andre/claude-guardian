import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import type { Config } from "../types/index.ts";
import { DEFAULT_CONFIG, DEFAULT_CONFIG_PATH, expandHome } from "./defaults.ts";

const severitySchema = z.enum(["critical", "high", "medium", "low"]);

const policyRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean().default(true),
  dataTypes: z.array(z.string()).optional(),
  tools: z.array(z.string()).optional(),
  detectorIds: z.array(z.string()).optional(),
  minSeverity: severitySchema.optional(),
  action: z.enum([
    "allow",
    "block",
    "require-approval",
    "redact",
    "substitute",
  ]),
  ttlSeconds: z.number().int().positive().optional(),
});

const allowlistEntrySchema = z.object({
  id: z.string(),
  pattern: z.string(),
  isRegex: z.boolean().default(false),
  detectorIds: z.array(z.string()).optional(),
  reason: z.string(),
  expiresAt: z.string().optional(),
});

const configSchema = z.object({
  dbPath: z.string().default(DEFAULT_CONFIG.dbPath),
  logFile: z.string().default(DEFAULT_CONFIG.logFile),
  logLevel: z.string().default("info"),
  dashboardPort: z.number().int().positive().default(7734),
  dashboardToken: z.string().default(""),
  engineTimeoutMs: z.number().int().positive().default(500),
  policies: z.array(policyRuleSchema).default(DEFAULT_CONFIG.policies),
  allowlist: z.array(allowlistEntrySchema).default([]),
  databaseUrl: z.string().default(""),
  agentApiKey: z.string().default(""),
  centralUrl: z.string().default(""),
  centralApiKey: z.string().default(""),
  substitutionSalt: z.string().default(""),
  entityDetection: z.boolean().default(false),
});

// Overrides de ambiente — permitem configurar o servidor em containers (Docker/
// EKS) sem arquivo de config, e o agente via script de instalação corporativo.
function applyEnvOverrides(config: Config): Config {
  const env = process.env;
  const port = parseInt(env["GUARDIAN_PORT"] ?? "", 10);
  return {
    ...config,
    dbPath: env["GUARDIAN_DB_PATH"] ?? config.dbPath,
    dashboardPort:
      Number.isFinite(port) && port > 0 ? port : config.dashboardPort,
    dashboardToken: env["GUARDIAN_DASHBOARD_TOKEN"] ?? config.dashboardToken,
    databaseUrl:
      env["GUARDIAN_DATABASE_URL"] ?? env["DATABASE_URL"] ?? config.databaseUrl,
    agentApiKey: env["GUARDIAN_AGENT_KEY"] ?? config.agentApiKey,
    centralUrl: env["GUARDIAN_CENTRAL_URL"] ?? config.centralUrl,
    centralApiKey: env["GUARDIAN_CENTRAL_KEY"] ?? config.centralApiKey,
    substitutionSalt:
      env["GUARDIAN_SUBSTITUTION_SALT"] ?? config.substitutionSalt,
    entityDetection:
      env["GUARDIAN_ENTITY_DETECTION"] != null
        ? env["GUARDIAN_ENTITY_DETECTION"] === "true"
        : config.entityDetection,
  };
}

export function resolveConfigPath(): string {
  const local = join(process.cwd(), "claude-guardian.config.json");
  if (existsSync(local)) return local;
  return DEFAULT_CONFIG_PATH;
}

export function saveConfig(config: Config, overridePath?: string): void {
  const path = overridePath ?? resolveConfigPath();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(config, null, 2), "utf8");
}

export function loadConfig(overridePath?: string): Config {
  const path = overridePath ?? resolveConfigPath();

  if (!existsSync(path)) return applyEnvOverrides(DEFAULT_CONFIG);

  try {
    const raw = readFileSync(path, "utf8");
    const parsed = configSchema.parse(JSON.parse(raw));
    return applyEnvOverrides({
      ...parsed,
      dbPath: expandHome(parsed.dbPath),
      logFile: expandHome(parsed.logFile),
    } as Config);
  } catch {
    return applyEnvOverrides(DEFAULT_CONFIG);
  }
}
