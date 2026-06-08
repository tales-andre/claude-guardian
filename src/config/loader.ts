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
  action: z.enum(["allow", "block", "require-approval", "redact"]),
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
});

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

  if (!existsSync(path)) return DEFAULT_CONFIG;

  try {
    const raw = readFileSync(path, "utf8");
    const parsed = configSchema.parse(JSON.parse(raw));
    return {
      ...parsed,
      dbPath: expandHome(parsed.dbPath),
      logFile: expandHome(parsed.logFile),
    } as Config;
  } catch {
    return DEFAULT_CONFIG;
  }
}
