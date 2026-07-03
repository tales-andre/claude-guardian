import { describe, expect, it } from "vitest";
import { compileManagedSettings } from "../src/lib/managed-settings.ts";

describe("compileManagedSettings", () => {
  it("locks the guardian hook in and enforces fail-closed startup", () => {
    const out = compileManagedSettings({
      hookCommand:
        "node --experimental-strip-types /opt/guardian/pre-tool-use.ts",
    });
    expect(out.serverManaged["allowManagedHooksOnly"]).toBe(true);
    expect(out.serverManaged["forceRemoteSettingsRefresh"]).toBe(true);
  });

  it("registers the guardian PreToolUse hook with the given command", () => {
    const out = compileManagedSettings({ hookCommand: "guardian-pre" });
    const hooks = out.serverManaged["hooks"] as {
      PreToolUse: Array<{ hooks: Array<{ command: string }> }>;
    };
    expect(hooks.PreToolUse[0]?.hooks[0]?.command).toBe("guardian-pre");
  });

  it("puts the MCP allowlist as keys in the server payload (no managed-mcp.json there)", () => {
    const out = compileManagedSettings({
      hookCommand: "g",
      allowedMcpServers: ["github", "sentry"],
    });
    expect(out.serverManaged["allowedMcpServers"]).toEqual([
      "github",
      "sentry",
    ]);
    expect(out.serverManaged).not.toHaveProperty("managedMcp");
  });

  it("emits a separate managed-mcp.json for endpoint/MDM distribution", () => {
    const out = compileManagedSettings({
      hookCommand: "g",
      allowedMcpServers: ["github"],
      deniedMcpServers: ["evil"],
    });
    expect(out.managedMcp["allowedMcpServers"]).toEqual(["github"]);
    expect(out.managedMcp["deniedMcpServers"]).toEqual(["evil"]);
  });

  it("turns denyReadPaths into permission deny rules", () => {
    const out = compileManagedSettings({
      hookCommand: "g",
      denyReadPaths: ["./.env", "./secrets/**"],
    });
    const perms = out.serverManaged["permissions"] as { deny: string[] };
    expect(perms.deny).toContain("Read(./.env)");
    expect(perms.deny).toContain("Read(./secrets/**)");
  });
});
