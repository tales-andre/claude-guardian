#!/usr/bin/env -S node --experimental-strip-types

import { Command } from "commander";
import { cmdInit } from "./commands/init.ts";
import { cmdServe } from "./commands/serve.ts";
import { cmdScan } from "./commands/scan.ts";
import { cmdPolicy } from "./commands/policy.ts";
import { cmdApprove, cmdDeny } from "./commands/approve.ts";

const program = new Command();

program
  .name("claude-guardian")
  .description("Enterprise DLP platform for Claude Code")
  .version("1.0.0");

program
  .command("init")
  .description("Initialize database, generate token, and register Claude Code hooks")
  .option("--config <path>", "Config file path")
  .option("--show-token", "Print the dashboard token")
  .option("--hooks-dir <path>", "Claude Code config directory (default: ~/.claude)")
  .action(cmdInit);

program
  .command("serve")
  .description("Start the governance dashboard server")
  .option("-p, --port <number>", "Port (overrides config)")
  .option("--config <path>", "Config file path")
  .action(cmdServe);

program
  .command("scan <target>")
  .description("Scan a file or text snippet for sensitive data")
  .option("--text", "Treat <target> as literal text instead of a file path")
  .option("--config <path>", "Config file path")
  .option("--json", "Output findings as JSON")
  .action(cmdScan);

program
  .command("policy list")
  .description("List all active policy rules")
  .option("--config <path>", "Config file path")
  .action(cmdPolicy);

program
  .command("approve <incidentId>")
  .description("Approve an exception for a blocked incident")
  .requiredOption("-r, --reason <text>", "Justification for the exception")
  .option("--ttl <seconds>", "Approval TTL in seconds (default: 3600)", "3600")
  .option("--config <path>", "Config file path")
  .action(cmdApprove);

program
  .command("deny <incidentId>")
  .description("Deny an approval request for a blocked incident")
  .option("-r, --reason <text>", "Reason for denial")
  .option("--config <path>", "Config file path")
  .action(cmdDeny);

program.parseAsync(process.argv).catch((err: unknown) => {
  process.stderr.write(`Error: ${String(err)}\n`);
  process.exit(1);
});
