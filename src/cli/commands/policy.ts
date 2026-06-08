import { loadConfig } from "../../config/loader.ts";

interface PolicyOptions {
  config?: string;
}

export async function cmdPolicy(_opts: PolicyOptions): Promise<void> {
  const config = loadConfig(_opts.config);

  console.log("\nActive policies:\n");
  const pad = (s: string, n: number) => s.slice(0, n).padEnd(n);

  console.log(
    `  ${"ID".padEnd(30)}  ${"NAME".padEnd(40)}  ${"ACTION".padEnd(18)}  ENABLED`,
  );
  console.log("  " + "─".repeat(100));

  for (const rule of config.policies) {
    const enabled = rule.enabled ? "yes" : "no";
    console.log(
      `  ${pad(rule.id, 30)}  ${pad(rule.name, 40)}  ${pad(rule.action, 18)}  ${enabled}`,
    );
    if (rule.dataTypes?.length) {
      console.log(`    data types: ${rule.dataTypes.join(", ")}`);
    }
    if (rule.minSeverity) {
      console.log(`    min severity: ${rule.minSeverity}`);
    }
  }

  console.log(`\nTotal: ${config.policies.length} rule(s)`);
  console.log(
    "\nEdit claude-guardian.config.json (or ~/.config/claude-guardian/config.json) to modify policies.",
  );
}
