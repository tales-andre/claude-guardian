import { describe, expect, it } from "vitest";
import {
  detectHost,
  normalizeHookInput,
  normalizeToolName,
} from "../src/hosts/index.ts";

describe("normalizeToolName", () => {
  it("maps Kiro canonical names to guardian tool names", () => {
    expect(normalizeToolName("fs_read")).toBe("Read");
    expect(normalizeToolName("fs_write")).toBe("Write");
    expect(normalizeToolName("execute_bash")).toBe("Bash");
  });

  it("maps Kiro aliases too", () => {
    expect(normalizeToolName("read")).toBe("Read");
    expect(normalizeToolName("write")).toBe("Write");
    expect(normalizeToolName("shell")).toBe("Bash");
  });

  it("passes Claude tool names through unchanged", () => {
    expect(normalizeToolName("Read")).toBe("Read");
    expect(normalizeToolName("Bash")).toBe("Bash");
    expect(normalizeToolName("Edit")).toBe("Edit");
  });

  it("passes unknown (e.g. MCP) names through unchanged", () => {
    expect(normalizeToolName("mcp__server__tool")).toBe("mcp__server__tool");
  });
});

describe("detectHost", () => {
  it("honors an explicit GUARDIAN_HOST", () => {
    expect(detectHost({ GUARDIAN_HOST: "kiro" })).toBe("kiro");
    expect(detectHost({ GUARDIAN_HOST: "claude" })).toBe("claude");
  });

  it("detects kiro from KIRO_* env markers", () => {
    expect(detectHost({ KIRO_VERSION: "1.0" })).toBe("kiro");
  });

  it("defaults to claude", () => {
    expect(detectHost({})).toBe("claude");
  });
});

describe("normalizeHookInput", () => {
  it("maps a Kiro fs_read payload to the guardian shape", () => {
    const out = normalizeHookInput(
      { tool_name: "fs_read", tool_input: { path: "/etc/passwd" } },
      "kiro",
    );
    expect(out.tool_name).toBe("Read");
    expect(out.tool_input?.file_path).toBe("/etc/passwd");
  });

  it("maps a Kiro execute_bash payload", () => {
    const out = normalizeHookInput(
      { tool_name: "execute_bash", tool_input: { command: "ls -la" } },
      "kiro",
    );
    expect(out.tool_name).toBe("Bash");
    expect(out.tool_input?.command).toBe("ls -la");
  });

  it("leaves a Claude payload unchanged", () => {
    const out = normalizeHookInput(
      {
        session_id: "s1",
        tool_name: "Read",
        tool_input: { file_path: "/x" },
      },
      "claude",
    );
    expect(out.tool_name).toBe("Read");
    expect(out.tool_input?.file_path).toBe("/x");
    expect(out.session_id).toBe("s1");
  });
});
