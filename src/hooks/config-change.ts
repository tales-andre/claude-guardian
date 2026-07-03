#!/usr/bin/env -S node --experimental-strip-types

import { existsSync } from "node:fs";
import { join } from "node:path";

if (existsSync(join(process.cwd(), ".guardian-bypass"))) process.exit(0);

import { loadConfig } from "../config/loader.ts";
import { getDb } from "../db/client.ts";
import {
  type ConfigChangeEvent,
  handleConfigChange,
} from "../lib/config-change.ts";

// ConfigChange hook: audit-only, never blocks.
// Records configuration-source changes (a common way to disable the guardian)
// as visible incidents. Exit 0 always — the change proceeds.

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  let data: ConfigChangeEvent;
  try {
    data = JSON.parse(raw) as ConfigChangeEvent;
  } catch {
    process.exit(0);
  }

  try {
    const config = loadConfig();
    const db = getDb(config.dbPath);
    handleConfigChange(db, config, data);
  } catch {
    // Never let audit errors block a config change.
  }

  process.exit(0);
});
