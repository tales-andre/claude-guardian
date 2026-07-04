import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  installMcpProxy,
  installMcpProxyAt,
  isWrapped,
  type McpConfig,
  uninstallMcpProxyAt,
  wrapMcpServers,
} from "../src/lib/mcp-install.ts";

const PROXY = "/repo/src/proxy/mcp-proxy.ts";

describe("wrapMcpServers", () => {
  it("wraps each server, preserving the original command as target", () => {
    const cfg: McpConfig = {
      mcpServers: {
        fs: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
        },
      },
    };
    const out = wrapMcpServers(cfg, PROXY);
    const fs = out.mcpServers?.["fs"];
    expect(fs?.command).toBe("node");
    expect(fs?.args?.[0]).toBe("--experimental-strip-types");
    expect(fs?.args?.[1]).toBe(PROXY);
    expect(fs?.env?.["GUARDIAN_MCP_NAME"]).toBe("fs");
    const target = JSON.parse(fs?.env?.["GUARDIAN_MCP_TARGET"] ?? "{}");
    expect(target).toEqual({
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
      env: {},
    });
  });

  it("is idempotent: wrapping twice is a no-op", () => {
    const cfg = { mcpServers: { fs: { command: "foo", args: [] } } };
    const once = wrapMcpServers(cfg, PROXY);
    const twice = wrapMcpServers(once, PROXY);
    expect(twice).toEqual(once);
    expect(isWrapped(twice.mcpServers.fs, PROXY)).toBe(true);
  });

  it("leaves a config without mcpServers untouched", () => {
    expect(wrapMcpServers({}, PROXY)).toEqual({});
  });
});

describe("installMcpProxyAt", () => {
  let dir: string;
  let file: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "guardian-mcp-install-"));
    file = join(dir, "claude_desktop_config.json");
    writeFileSync(
      file,
      JSON.stringify({ mcpServers: { fs: { command: "foo", args: [] } } }),
    );
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("wraps the file and writes a .bak backup", () => {
    installMcpProxyAt(file, PROXY);
    const out = JSON.parse(readFileSync(file, "utf8"));
    expect(out.mcpServers.fs.command).toBe("node");
    const bak = JSON.parse(readFileSync(`${file}.guardian.bak`, "utf8"));
    expect(bak.mcpServers.fs.command).toBe("foo");
  });

  it("uninstall restores the original from backup", () => {
    installMcpProxyAt(file, PROXY);
    uninstallMcpProxyAt(file);
    const out = JSON.parse(readFileSync(file, "utf8"));
    expect(out.mcpServers.fs.command).toBe("foo");
  });

  it("install on a missing file is a no-op (returns false)", () => {
    expect(installMcpProxyAt(join(dir, "nope.json"), PROXY)).toBe(false);
  });
});

describe("installMcpProxy (varredura por SO)", () => {
  it("retorna [] quando nenhuma config MCP existe", () => {
    const prev = process.env["HOME"];
    const empty = mkdtempSync(join(tmpdir(), "guardian-empty-home-"));
    process.env["HOME"] = empty;
    try {
      expect(installMcpProxy(PROXY)).toEqual([]);
    } finally {
      if (prev === undefined) delete process.env["HOME"];
      else process.env["HOME"] = prev;
      rmSync(empty, { recursive: true, force: true });
    }
  });
});
