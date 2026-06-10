import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const PRE_TOOL_HOOK = new URL(
  "../src/hooks/pre-tool-use.ts",
  import.meta.url,
).pathname;
const USER_PROMPT_HOOK = new URL(
  "../src/hooks/user-prompt-submit.ts",
  import.meta.url,
).pathname;
const NODE_FLAGS = ["--experimental-strip-types"];

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-adapter-test-"));
  // Hooks resolve ./claude-guardian.config.json from CWD first, so spawning
  // them with cwd=tmpDir isolates the tests from the developer's real config,
  // database, and any .guardian-bypass sentinel in the repo root. Omitted
  // fields (policies etc.) fall back to schema defaults.
  writeFileSync(
    join(tmpDir, "claude-guardian.config.json"),
    JSON.stringify({
      dbPath: join(tmpDir, "guardian.db"),
      logFile: join(tmpDir, "guardian.log"),
    }),
    "utf8",
  );
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeFixture(name: string, content: string): string {
  const p = join(tmpDir, name);
  writeFileSync(p, content, "utf8");
  return p;
}

function runPreToolHook(
  toolName: string,
  toolInput: Record<string, unknown>,
  opts: { env?: Record<string, string> } = {},
) {
  const payload = JSON.stringify({
    session_id: "test-session",
    tool_name: toolName,
    tool_input: toolInput,
  });
  const result = spawnSync("node", [...NODE_FLAGS, PRE_TOOL_HOOK], {
    input: payload,
    encoding: "utf8",
    cwd: tmpDir,
    env: { ...process.env, ...opts.env },
    timeout: 10_000,
  });
  const out = result.stdout.trim();
  let decision: string | null = null;
  let reason: string | null = null;
  try {
    const parsed = JSON.parse(out) as { decision?: string; reason?: string };
    decision = parsed.decision ?? null;
    reason = parsed.reason ?? null;
  } catch {
    // allow
  }
  return { exitCode: result.status ?? -1, decision, reason, stdout: out, stderr: result.stderr };
}

function runPromptHook(prompt: string) {
  const payload = JSON.stringify({ session_id: "test-session", prompt });
  const result = spawnSync("node", [...NODE_FLAGS, USER_PROMPT_HOOK], {
    input: payload,
    encoding: "utf8",
    cwd: tmpDir,
    timeout: 10_000,
  });
  const out = result.stdout.trim();
  let decision: string | null = null;
  let reason: string | null = null;
  try {
    const parsed = JSON.parse(out) as { decision?: string; reason?: string };
    decision = parsed.decision ?? null;
    reason = parsed.reason ?? null;
  } catch {
    // allow
  }
  return { exitCode: result.status ?? -1, decision, reason, stdout: out, stderr: result.stderr };
}

// ── PreToolUse: Read tool ─────────────────────────────────────────────────────

describe("pre-tool-use hook — Read: clean file", () => {
  it("allows a clean file", () => {
    const p = writeFixture("clean.txt", "hello world");
    const { exitCode } = runPreToolHook("Read", { file_path: p });
    expect(exitCode).toBe(0);
  });

  it("allows a non-existent file (let the tool handle the error)", () => {
    const { exitCode } = runPreToolHook("Read", { file_path: "/tmp/does-not-exist-xyz.txt" });
    expect(exitCode).toBe(0);
  });
});

describe("pre-tool-use hook — Read: secrets in file", () => {
  it("blocks a file containing an AWS key", () => {
    const p = writeFixture("aws.txt", "key=AKIAIOSFODNN7EXAMPLE\n");
    const { exitCode, decision } = runPreToolHook("Read", { file_path: p });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks a file containing a credit card", () => {
    const p = writeFixture("cc.txt", "card: 4111111111111111\n");
    const { exitCode } = runPreToolHook("Read", { file_path: p });
    expect(exitCode).toBe(2);
  });

  it("reason contains the detector ID", () => {
    const p = writeFixture("aws2.txt", "key=AKIAIOSFODNN7EXAMPLE\n");
    const { reason } = runPreToolHook("Read", { file_path: p });
    expect(reason).toContain("aws-access-key");
  });

  it("reason contains the incident ID", () => {
    const p = writeFixture("aws3.txt", "key=AKIAIOSFODNN7EXAMPLE\n");
    const { reason } = runPreToolHook("Read", { file_path: p });
    expect(reason).toMatch(/Incident ID:/);
  });
});

describe("pre-tool-use hook — Read: .env name block", () => {
  it("blocks .env regardless of content", () => {
    const p = writeFixture(".env", "DEBUG=true\n");
    const { exitCode, decision } = runPreToolHook("Read", { file_path: p });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks .env.local", () => {
    const p = writeFixture(".env.local", "DEBUG=true\n");
    const { exitCode } = runPreToolHook("Read", { file_path: p });
    expect(exitCode).toBe(2);
  });
});

// ── PreToolUse: Bash tool ─────────────────────────────────────────────────────

describe("pre-tool-use hook — Bash: inline secrets", () => {
  it("allows a harmless command", () => {
    const { exitCode } = runPreToolHook("Bash", { command: "ls -la /tmp" });
    expect(exitCode).toBe(0);
  });

  it("blocks a command containing an AWS key inline", () => {
    const { exitCode, decision } = runPreToolHook("Bash", {
      command: "echo AKIAIOSFODNN7EXAMPLE",
    });
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });
});

describe("pre-tool-use hook — Bash: env var expansion", () => {
  it("blocks echo $TOKEN when TOKEN contains an AWS key", () => {
    const { exitCode } = runPreToolHook(
      "Bash",
      { command: "echo $TOKEN" },
      { env: { TOKEN: "AKIAIOSFODNN7EXAMPLE" } },
    );
    expect(exitCode).toBe(2);
  });

  it("allows echo $TOKEN when TOKEN is clean", () => {
    const { exitCode } = runPreToolHook(
      "Bash",
      { command: "echo $TOKEN" },
      { env: { TOKEN: "nothing_sensitive_here" } },
    );
    expect(exitCode).toBe(0);
  });

  it("allows echo $TOKEN when TOKEN is unset", () => {
    const { exitCode } = runPreToolHook("Bash", { command: "echo $TOKEN" });
    expect(exitCode).toBe(0);
  });
});

describe("pre-tool-use hook — Bash: file-reading commands", () => {
  it.each(["cat", "head", "tail", "bat"])(
    "blocks %s on a file with secrets",
    (cmd) => {
      const p = writeFixture(`secret-${cmd}.txt`, "key=AKIAIOSFODNN7EXAMPLE\n");
      const { exitCode } = runPreToolHook("Bash", { command: `${cmd} ${p}` });
      expect(exitCode).toBe(2);
    },
  );

  it("allows cat on a clean file", () => {
    const p = writeFixture("clean-bash.txt", "nothing sensitive here\n");
    const { exitCode } = runPreToolHook("Bash", { command: `cat ${p}` });
    expect(exitCode).toBe(0);
  });
});

// ── PreToolUse: Write/Edit tools ──────────────────────────────────────────────

describe("pre-tool-use hook — Write/Edit", () => {
  it("blocks Write with secret in content", () => {
    const { exitCode } = runPreToolHook("Write", {
      file_path: "/tmp/output.txt",
      content: "api_key=AKIAIOSFODNN7EXAMPLE\n",
    });
    expect(exitCode).toBe(2);
  });

  it("allows Write with clean content", () => {
    const { exitCode } = runPreToolHook("Write", {
      file_path: "/tmp/output.txt",
      content: "hello world\n",
    });
    expect(exitCode).toBe(0);
  });

  it("blocks Edit with secret in new_string", () => {
    const { exitCode } = runPreToolHook("Edit", {
      file_path: "/tmp/file.ts",
      old_string: "key=old",
      new_string: "key=AKIAIOSFODNN7EXAMPLE",
    });
    expect(exitCode).toBe(2);
  });
});

// ── PreToolUse: other tools ───────────────────────────────────────────────────

describe("pre-tool-use hook — unknown tool", () => {
  it("allows unknown tool types (fail-open for unknown tools)", () => {
    const { exitCode } = runPreToolHook("TodoWrite", { todos: [] });
    expect(exitCode).toBe(0);
  });
});

// ── PreToolUse: malformed input ───────────────────────────────────────────────

describe("pre-tool-use hook — malformed input", () => {
  it("exits 0 on invalid JSON (fail-open for parse errors)", () => {
    const result = spawnSync("node", [...NODE_FLAGS, PRE_TOOL_HOOK], {
      input: "not valid json",
      encoding: "utf8",
      cwd: tmpDir,
      timeout: 5000,
    });
    expect(result.status).toBe(0);
  });
});

// ── UserPromptSubmit ──────────────────────────────────────────────────────────

describe("user-prompt-submit hook", () => {
  it("allows a clean prompt", () => {
    const { exitCode } = runPromptHook("help me write a function");
    expect(exitCode).toBe(0);
  });

  it("blocks a prompt containing an AWS key", () => {
    const { exitCode, decision } = runPromptHook("my key is AKIAIOSFODNN7EXAMPLE");
    expect(exitCode).toBe(2);
    expect(decision).toBe("block");
  });

  it("blocks a prompt containing an email", () => {
    const { exitCode } = runPromptHook("email user@example.com about it");
    expect(exitCode).toBe(2);
  });

  it("reason contains the incident ID", () => {
    const { reason } = runPromptHook("my key is AKIAIOSFODNN7EXAMPLE");
    expect(reason).toMatch(/Incident ID:/);
  });

  it("[allow-guardian] bypasses the block", () => {
    const { exitCode } = runPromptHook(
      "[allow-guardian] my key is AKIAIOSFODNN7EXAMPLE",
    );
    expect(exitCode).toBe(0);
  });

  it("exits 0 on malformed JSON", () => {
    const result = spawnSync("node", [...NODE_FLAGS, USER_PROMPT_HOOK], {
      input: "bad json",
      encoding: "utf8",
      cwd: tmpDir,
      timeout: 5000,
    });
    expect(result.status).toBe(0);
  });
});
