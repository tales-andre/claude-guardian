import { X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import forge from "node-forge";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ensureCa, issueLeaf } from "../src/lib/mitm-ca.ts";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "guardian-ca-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("ensureCa", () => {
  it("gera CA + chaves e persiste os arquivos", () => {
    const ca = ensureCa(dir);
    expect(existsSync(join(dir, "guardian-ca.crt"))).toBe(true);
    expect(existsSync(join(dir, "guardian-ca.key"))).toBe(true);
    expect(ca.fingerprint).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  });

  it("é idempotente: recarrega a mesma CA (mesmo fingerprint)", () => {
    const a = ensureCa(dir);
    const b = ensureCa(dir);
    expect(b.fingerprint).toBe(a.fingerprint);
    expect(b.caCertPem).toBe(a.caCertPem);
  });
});

describe("issueLeaf", () => {
  it("emite cert cujo SAN bate com o host e a chain valida contra a CA", () => {
    const ca = ensureCa(dir);
    const host = "a-api.anthropic.com";
    const leaf = issueLeaf(ca, host);

    const x = new X509Certificate(leaf.certPem);
    expect(x.subjectAltName).toContain(`DNS:${host}`);

    // Assinatura do leaf confere com a CA (forge).
    const leafObj = forge.pki.certificateFromPem(leaf.certPem);
    expect(ca.caCert.verify(leafObj)).toBe(true);
  });

  it("cacheia por host (mesma instância de cert)", () => {
    const ca = ensureCa(dir);
    const a = issueLeaf(ca, "api.anthropic.com");
    const b = issueLeaf(ca, "api.anthropic.com");
    expect(b.certPem).toBe(a.certPem);
  });
});
