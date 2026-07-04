import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  handleClientMessage,
  handleServerMessage,
  runProxyStreams,
  type ScanFn,
} from "../src/proxy/mcp-proxy.ts";

const allow: ScanFn = () => ({ action: "allow", reason: "" });
const block: ScanFn = () => ({ action: "block", reason: "blocked" });
const redact: ScanFn = () => ({
  action: "redact",
  reason: "",
  redactedText: JSON.stringify({ body: "[REDACTED:aws-key]" }),
});

describe("handleClientMessage", () => {
  it("forwards non tools/call messages untouched", () => {
    const pending = new Map<string | number, string>();
    const msg = { jsonrpc: "2.0", id: 1, method: "initialize", params: {} };
    const out = handleClientMessage(msg, allow, pending);
    expect(out.toChild).toEqual(msg);
    expect(out.toClient).toBeUndefined();
  });

  it("forwards a clean tools/call and registers it as pending", () => {
    const pending = new Map<string | number, string>();
    const msg = {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "/x" } },
    };
    const out = handleClientMessage(msg, allow, pending);
    expect(out.toChild).toEqual(msg);
    expect(pending.get(7)).toBe("read_file");
  });

  it("blocks a dirty tools/call: replies error to client, nothing to child", () => {
    const pending = new Map<string | number, string>();
    const msg = {
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: { name: "post", arguments: { body: "secret" } },
    };
    const out = handleClientMessage(msg, block, pending);
    expect(out.toChild).toBeUndefined();
    expect(out.toClient?.error?.code).toBe(-32001);
    expect(out.toClient?.id).toBe(8);
    expect(pending.has(8)).toBe(false);
  });

  it("redacts a tools/call: rewrites arguments before forwarding", () => {
    const pending = new Map<string | number, string>();
    const msg = {
      jsonrpc: "2.0",
      id: 9,
      method: "tools/call",
      params: { name: "post", arguments: { body: "k=AKIA..." } },
    };
    const out = handleClientMessage(msg, redact, pending);
    expect(out.toChild?.params.arguments).toEqual({ body: "[REDACTED:aws-key]" });
    expect(pending.get(9)).toBe("post");
  });
});

describe("handleServerMessage", () => {
  it("passes through a response with no matching pending call", () => {
    const pending = new Map<string | number, string>();
    const msg = { jsonrpc: "2.0", id: 99, result: { content: [] } };
    const out = handleServerMessage(msg, allow, pending);
    expect(out.toClient).toEqual(msg);
  });

  it("blocks a dirty result: replaces it with an error and clears pending", () => {
    const pending = new Map<string | number, string>([[5, "read_file"]]);
    const msg = {
      jsonrpc: "2.0",
      id: 5,
      result: { content: [{ type: "text", text: "AKIA..." }] },
    };
    const out = handleServerMessage(msg, block, pending);
    expect(out.toClient.error?.code).toBe(-32001);
    expect(out.toClient.result).toBeUndefined();
    expect(pending.has(5)).toBe(false);
  });

  it("clears pending on a clean result", () => {
    const pending = new Map<string | number, string>([[6, "read_file"]]);
    const msg = {
      jsonrpc: "2.0",
      id: 6,
      result: { content: [{ type: "text", text: "hello" }] },
    };
    handleServerMessage(msg, allow, pending);
    expect(pending.has(6)).toBe(false);
  });
});

describe("runProxyStreams (integração de streams)", () => {
  it("bloqueia tools/call sujo antes de chegar ao server", async () => {
    const clientIn = new PassThrough();
    const clientOut = new PassThrough();
    const childIn = new PassThrough();
    const childOut = new PassThrough();

    const toChild: string[] = [];
    childIn.on("data", (b) => toChild.push(b.toString()));
    const toClient: string[] = [];
    clientOut.on("data", (b) => toClient.push(b.toString()));

    runProxyStreams({ clientIn, clientOut, childIn, childOut, scan: block });

    clientIn.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "post", arguments: { body: "AKIA..." } },
      })}\n`,
    );
    await new Promise((r) => setTimeout(r, 20));

    expect(toChild.join("")).toBe(""); // nada chegou ao server
    expect(toClient.join("")).toContain("-32001");
  });

  it("encaminha tools/call limpo ao server", async () => {
    const clientIn = new PassThrough();
    const clientOut = new PassThrough();
    const childIn = new PassThrough();
    const childOut = new PassThrough();
    const toChild: string[] = [];
    childIn.on("data", (b) => toChild.push(b.toString()));

    runProxyStreams({ clientIn, clientOut, childIn, childOut, scan: allow });
    clientIn.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "read_file", arguments: { path: "/x" } },
      })}\n`,
    );
    await new Promise((r) => setTimeout(r, 20));
    expect(toChild.join("")).toContain("read_file");
  });
});
