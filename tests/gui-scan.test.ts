import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config/defaults.ts";
import { getDb } from "../src/db/client.ts";
import { extractGuiText, scanGui } from "../src/lib/gui-scan.ts";
import type { Config } from "../src/types/index.ts";

let tmpDir: string;
let dbPath: string;
beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "guardian-gui-scan-"));
  dbPath = join(tmpDir, "test.db");
});
afterAll(() => rmSync(tmpDir, { recursive: true, force: true }));
function cfg(o: Partial<Config> = {}): Config {
  return { ...DEFAULT_CONFIG, dbPath, ...o };
}
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const req = (bodyText: string) => ({
  bodyText,
  host: "a-api.anthropic.com",
  path: "/v1/messages",
});

describe("extractGuiText", () => {
  it("lê prompt e attachments[].extracted_content", () => {
    const { promptText, uploadText } = extractGuiText(
      JSON.stringify({
        prompt: "oi",
        attachments: [{ file_name: "a.txt", extracted_content: "segredo" }],
      }),
    );
    expect(promptText).toContain("oi");
    expect(uploadText).toContain("segredo");
  });

  it("cai pro corpo inteiro quando o schema é desconhecido", () => {
    const { promptText } = extractGuiText('{"weird":"AKIA-xyz payload"}');
    expect(promptText).toContain("AKIA-xyz payload");
  });

  it("corpo não-JSON vira prompt inteiro", () => {
    const { promptText } = extractGuiText("texto solto com segredo");
    expect(promptText).toBe("texto solto com segredo");
  });
});

describe("scanGui", () => {
  it("bloqueia segredo no prompt", () => {
    const db = getDb(dbPath);
    const r = scanGui(db, cfg(), req(JSON.stringify({ prompt: `k=${AWS_KEY}` })));
    expect(r.action).toBe("block");
  });

  it("bloqueia segredo no anexo (extracted_content)", () => {
    const db = getDb(dbPath);
    const r = scanGui(
      db,
      cfg(),
      req(
        JSON.stringify({
          prompt: "",
          attachments: [{ file_name: "c.txt", extracted_content: `x=${AWS_KEY}` }],
        }),
      ),
    );
    expect(r.action).toBe("block");
  });

  it("bloqueia segredo em corpo de schema desconhecido (fallback)", () => {
    const db = getDb(dbPath);
    const r = scanGui(db, cfg(), req(JSON.stringify({ foo: { bar: AWS_KEY } })));
    expect(r.action).toBe("block");
  });

  it("libera corpo limpo", () => {
    const db = getDb(dbPath);
    const r = scanGui(db, cfg(), req(JSON.stringify({ prompt: "qual a capital da França?" })));
    expect(r.action).toBe("allow");
  });
});
