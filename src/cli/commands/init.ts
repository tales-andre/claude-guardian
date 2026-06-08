import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { getDb } from "../../db/client.ts";
import { DEFAULT_CONFIG, DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_PATH, expandHome } from "../../config/defaults.ts";
import { loadConfig } from "../../config/loader.ts";

interface InitOptions {
  config?: string;
  showToken?: boolean;
  hooksDir?: string;
}

export async function cmdInit(opts: InitOptions): Promise<void> {
  const configPath = opts.config ?? DEFAULT_CONFIG_PATH;
  const hooksDir = opts.hooksDir ?? join(homedir(), ".claude");

  // 1. Ensure config directory exists.
  mkdirSync(dirname(configPath), { recursive: true });

  // 2. Load or create config, inject a new token if missing.
  let config = loadConfig(configPath);
  if (!config.dashboardToken) {
    config = { ...config, dashboardToken: randomBytes(24).toString("hex") };
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf8");
    console.log(`✓ Config written to ${configPath}`);
  } else {
    console.log(`✓ Using existing config at ${configPath}`);
  }

  // 3. Initialize SQLite database.
  const dbPath = expandHome(config.dbPath);
  mkdirSync(dirname(dbPath), { recursive: true });
  getDb(dbPath);
  console.log(`✓ Database initialized at ${dbPath}`);

  // 4. Register hooks in Claude Code settings.json.
  const settingsPath = join(hooksDir, "settings.json");
  mkdirSync(hooksDir, { recursive: true });

  let settings: Record<string, unknown> = {};
  if (existsSync(settingsPath)) {
    try {
      settings = JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
    } catch {
      settings = {};
    }
  }

  const packageRoot = fileURLToPath(new URL("../../../", import.meta.url));
  const preToolHook = `node --experimental-strip-types "${join(packageRoot, "src/hooks/pre-tool-use.ts")}"`;
  const promptHook = `node --experimental-strip-types "${join(packageRoot, "src/hooks/user-prompt-submit.ts")}"`;
  const postToolHook = `node --experimental-strip-types "${join(packageRoot, "src/hooks/post-tool-use.ts")}"`;

  const hooks = (settings["hooks"] as Record<string, unknown[]>) ?? {};

  const preToolEntry = { matcher: ".*", hooks: [{ type: "command", command: preToolHook }] };
  const promptEntry = { hooks: [{ type: "command", command: promptHook }] };
  const postToolEntry = { matcher: ".*", hooks: [{ type: "command", command: postToolHook }] };

  hooks["PreToolUse"] = dedupeHooks(
    [...((hooks["PreToolUse"] as unknown[]) ?? []), preToolEntry],
    preToolHook,
  );
  hooks["UserPromptSubmit"] = dedupeHooks(
    [...((hooks["UserPromptSubmit"] as unknown[]) ?? []), promptEntry],
    promptHook,
  );
  hooks["PostToolUse"] = dedupeHooks(
    [...((hooks["PostToolUse"] as unknown[]) ?? []), postToolEntry],
    postToolHook,
  );

  settings["hooks"] = hooks;
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n", "utf8");
  console.log(`✓ Hooks registered in ${settingsPath}`);

  // 5. Summary.
  console.log("");
  console.log("claude-guardian is ready.");
  console.log("");
  console.log("  Start the dashboard:  claude-guardian serve");
  console.log(`  Dashboard URL:        http://localhost:${config.dashboardPort}/dashboard`);

  if (opts.showToken || !config.dashboardToken) {
    console.log(`  Dashboard token:      ${config.dashboardToken}`);
  } else {
    console.log("  Dashboard token:      (run with --show-token to display)");
  }
  console.log("");
  console.log("Restart Claude Code to activate the hooks.");
}

type HookEntry = { hooks?: Array<{ type: string; command?: string }> };

function dedupeHooks(entries: unknown[], newCommand: string): unknown[] {
  const seen = new Set<string>();
  const result: unknown[] = [];
  for (const entry of entries) {
    const e = entry as HookEntry;
    const cmds = (e.hooks ?? []).map((h) => h.command ?? "").join("|");
    if (!seen.has(cmds)) {
      seen.add(cmds);
      result.push(entry);
    }
  }
  return result;
}
