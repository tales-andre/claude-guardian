import { describe, expect, it } from "vitest";
import { scanSync } from "../src/engine/index.ts";
import { entropy, luhn, redact, validCnpj, validCpf, validIban } from "../src/engine/utils.ts";

// ── Utility functions ──────────────────────────────────────────────────────────

describe("luhn", () => {
  it("passes a valid Visa number", () => expect(luhn("4111111111111111")).toBe(true));
  it("passes a valid Mastercard number", () => expect(luhn("5500005555555559")).toBe(true));
  it("rejects an invalid number", () => expect(luhn("1234567890123456")).toBe(false));
  it("ignores spaces and dashes", () => {
    expect(luhn("4111 1111 1111 1111")).toBe(true);
    expect(luhn("4111-1111-1111-1111")).toBe(true);
  });
  it("rejects strings that are too short", () => expect(luhn("1234")).toBe(false));
});

describe("entropy", () => {
  it("returns 0 for a single repeated character", () => expect(entropy("aaaa")).toBe(0));
  it("returns higher entropy for more varied strings", () => {
    expect(entropy("abcdefgh")).toBeGreaterThan(entropy("aaaabbbb"));
  });
  it("password entropy is below 3.0", () => expect(entropy("password")).toBeLessThan(3.0));
  it("random-looking value entropy is above 3.5", () => {
    expect(entropy("Xk9mP2qR7vL4nW1s")).toBeGreaterThan(3.5);
  });
});

describe("redact", () => {
  it("masks strings of 8 chars or fewer", () => {
    expect(redact("abc")).toBe("****");
    expect(redact("12345678")).toBe("****");
  });
  it("shows first 4 and last 4 for longer strings", () => {
    expect(redact("123456789")).toBe("1234****6789");
  });
  it("handles empty string", () => expect(redact("")).toBe("****"));
});

describe("validCpf", () => {
  it("accepts a valid CPF", () => expect(validCpf("52998224725")).toBe(true));
  it("rejects a CPF with all same digits", () => expect(validCpf("11111111111")).toBe(false));
  it("rejects an invalid CPF", () => expect(validCpf("12345678901")).toBe(false));
  it("rejects wrong length", () => expect(validCpf("1234567890")).toBe(false));
});

describe("validCnpj", () => {
  it("accepts a valid CNPJ", () => expect(validCnpj("11222333000181")).toBe(true));
  it("rejects all-same-digit CNPJ", () => expect(validCnpj("00000000000000")).toBe(false));
  it("rejects an invalid CNPJ", () => expect(validCnpj("12345678000190")).toBe(false));
});

describe("validIban", () => {
  it("accepts a valid GB IBAN", () => expect(validIban("GB82WEST12345698765432")).toBe(true));
  it("accepts a valid DE IBAN", () => expect(validIban("DE89370400440532013000")).toBe(true));
  it("rejects an invalid IBAN", () => expect(validIban("GB00WEST12345698765432")).toBe(false));
  it("accepts IBAN with spaces", () => expect(validIban("GB82 WEST 1234 5698 7654 32")).toBe(true));
});

// ── Engine: secrets ─────────────────────────────────────────────────────────

describe("scanSync — AWS", () => {
  it("detects an AWS Access Key ID", () => {
    const { findings } = scanSync("key=AKIAIOSFODNN7EXAMPLE");
    expect(findings.some((f) => f.detectorId === "aws-access-key")).toBe(true);
  });
  it("does not flag non-AWS patterns", () => {
    const { findings } = scanSync("BKIAIOSFODNN7EXAMPLE");
    expect(findings.some((f) => f.detectorId === "aws-access-key")).toBe(false);
  });
});

describe("scanSync — GCP", () => {
  it("detects a GCP API key", () => {
    const { findings } = scanSync(`AIzaSyC${"A".repeat(32)}`);
    expect(findings.some((f) => f.detectorId === "gcp-api-key")).toBe(true);
  });
  it("does not flag a short AIza string", () => {
    const { findings } = scanSync("AIzaSyC_short");
    expect(findings.some((f) => f.detectorId === "gcp-api-key")).toBe(false);
  });
});

describe("scanSync — GitHub", () => {
  it("detects a GitHub PAT (ghp_)", () => {
    const { findings } = scanSync(`ghp_${"A".repeat(36)}`);
    expect(findings.some((f) => f.detectorId === "github-pat")).toBe(true);
  });
  it("detects a GitHub fine-grained token", () => {
    const { findings } = scanSync(`github_pat_${"A".repeat(82)}`);
    expect(findings.some((f) => f.detectorId === "github-fine-grained")).toBe(true);
  });
});

describe("scanSync — GitLab", () => {
  it("detects a GitLab PAT", () => {
    const { findings } = scanSync(`glpat-${"A".repeat(20)}`);
    expect(findings.some((f) => f.detectorId === "gitlab-pat")).toBe(true);
  });
});

describe("scanSync — JWT", () => {
  it("detects a JWT", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const { findings } = scanSync(jwt);
    expect(findings.some((f) => f.detectorId === "jwt")).toBe(true);
  });
});

describe("scanSync — private key", () => {
  it("detects a PEM RSA private key header", () => {
    const { findings } = scanSync("-----BEGIN RSA PRIVATE KEY-----");
    expect(findings.some((f) => f.detectorId === "private-key")).toBe(true);
  });
  it("detects an OpenSSH private key header", () => {
    const { findings } = scanSync("-----BEGIN OPENSSH PRIVATE KEY-----");
    expect(findings.some((f) => f.detectorId === "private-key")).toBe(true);
  });
});

describe("scanSync — Stripe", () => {
  it("detects a Stripe secret key", () => {
    const { findings } = scanSync(`sk_live_${"A".repeat(24)}`);
    expect(findings.some((f) => f.detectorId === "stripe-secret-key")).toBe(true);
  });
  it("detects a Stripe restricted key", () => {
    const { findings } = scanSync(`rk_test_${"A".repeat(24)}`);
    expect(findings.some((f) => f.detectorId === "stripe-restricted-key")).toBe(true);
  });
});

describe("scanSync — OpenAI / Anthropic", () => {
  it("detects an OpenAI legacy key", () => {
    const { findings } = scanSync(`sk-${"A".repeat(48)}`);
    expect(findings.some((f) => f.detectorId === "openai-key")).toBe(true);
  });
  it("does not flag sk-proj-* as openai-key (legacy)", () => {
    const { findings } = scanSync("sk-proj-Xk9mP2qR7vL4nW1sYj3cBz8dEf5gHiKoNpQuTxMn");
    expect(findings.some((f) => f.detectorId === "openai-key")).toBe(false);
  });
  it("detects an OpenAI project key", () => {
    const { findings } = scanSync("sk-proj-Xk9mP2qR7vL4nW1sYj3cBz8dEf5gHiKoNpQuTxMn");
    expect(findings.some((f) => f.detectorId === "openai-project-key")).toBe(true);
  });
  it("detects an Anthropic key", () => {
    const { findings } = scanSync(`sk-ant-${"A".repeat(95)}`);
    expect(findings.some((f) => f.detectorId === "anthropic-key")).toBe(true);
  });
});

describe("scanSync — connection strings", () => {
  it("detects a postgres connection string with credentials", () => {
    const { findings } = scanSync("postgres://user:s3cr3tP@ss@localhost/db");
    expect(findings.some((f) => f.detectorId === "connection-string")).toBe(true);
  });
  it("does not flag a connection string without password", () => {
    const { findings } = scanSync("postgres://localhost/mydb");
    expect(findings.some((f) => f.detectorId === "connection-string")).toBe(false);
  });
});

describe("scanSync — generic secrets", () => {
  it("detects a high-entropy api_key assignment", () => {
    const { findings } = scanSync("api_key=Xk9mP2qR7vL4nW1sYj3cBz8dEf5g");
    expect(findings.some((f) => f.detectorId === "generic-secret")).toBe(true);
  });
  it("does not flag a low-entropy generic key value", () => {
    const { findings } = scanSync("api_key=placeholder");
    expect(findings.some((f) => f.detectorId === "generic-secret")).toBe(false);
  });
  it("detects a high-entropy env assignment", () => {
    const { findings } = scanSync("DATABASE_PASSWORD=Xk9mP2qR7vL4nW1s");
    expect(findings.some((f) => f.detectorId === "env-assignment")).toBe(true);
  });
  it("does not flag a low-entropy env value", () => {
    const { findings } = scanSync("DATABASE_PASSWORD=password");
    expect(findings.some((f) => f.detectorId === "env-assignment")).toBe(false);
  });
});

describe("scanSync — npm", () => {
  it("detects an npm token", () => {
    const { findings } = scanSync(`npm_${"A".repeat(36)}`);
    expect(findings.some((f) => f.detectorId === "npm-token")).toBe(true);
  });
  it("does not flag a short npm_ string", () => {
    const { findings } = scanSync("npm_shorttoken");
    expect(findings.some((f) => f.detectorId === "npm-token")).toBe(false);
  });
});

describe("scanSync — Slack", () => {
  it("detects a Slack token", () => {
    const { findings } = scanSync("xoxb-123456789012-ABCDEFGHIJ");
    expect(findings.some((f) => f.detectorId === "slack-token")).toBe(true);
  });
  it("detects a Slack webhook URL", () => {
    const { findings } = scanSync(
      `https://hooks.slack.com/services/TABCDEFGH/BABCDEFGHIJ/${"A".repeat(24)}`,
    );
    expect(findings.some((f) => f.detectorId === "slack-webhook")).toBe(true);
  });
});

// ── Engine: PII ───────────────────────────────────────────────────────────────

describe("scanSync — PII: email", () => {
  it("detects an email address", () => {
    const { findings } = scanSync("contact: user@example.com");
    expect(findings.some((f) => f.detectorId === "pii-email")).toBe(true);
  });
  it("does not flag a plain domain", () => {
    const { findings } = scanSync("visit example.com for more info");
    expect(findings.some((f) => f.detectorId === "pii-email")).toBe(false);
  });
});

describe("scanSync — PII: credit card", () => {
  it("detects a valid Visa number", () => {
    const { findings } = scanSync("card: 4111111111111111");
    expect(findings.some((f) => f.detectorId === "credit-card")).toBe(true);
  });
  it("does not flag an invalid Luhn number", () => {
    const { findings } = scanSync("card: 4111111111111112");
    expect(findings.some((f) => f.detectorId === "credit-card")).toBe(false);
  });
  it("detects a space-separated card", () => {
    const { findings } = scanSync("card: 4111 1111 1111 1111");
    expect(findings.some((f) => f.detectorId === "credit-card")).toBe(true);
  });
});

describe("scanSync — PII: SSN", () => {
  it("detects a US SSN", () => {
    const { findings } = scanSync("ssn: 123-45-6789");
    expect(findings.some((f) => f.detectorId === "pii-ssn")).toBe(true);
  });
  it("does not flag SSN with area 000", () => {
    expect(scanSync("000-45-6789").findings.some((f) => f.detectorId === "pii-ssn")).toBe(false);
  });
  it("does not flag SSN with area 666", () => {
    expect(scanSync("666-45-6789").findings.some((f) => f.detectorId === "pii-ssn")).toBe(false);
  });
  it("does not flag SSN with area 9xx", () => {
    expect(scanSync("900-45-6789").findings.some((f) => f.detectorId === "pii-ssn")).toBe(false);
  });
});

describe("scanSync — PII: CPF (Brazil)", () => {
  it("detects a valid formatted CPF", () => {
    const { findings } = scanSync("cpf: 529.982.247-25");
    expect(findings.some((f) => f.detectorId === "pii-cpf")).toBe(true);
  });
  it("does not flag an invalid CPF", () => {
    const { findings } = scanSync("cpf: 111.111.111-11");
    expect(findings.some((f) => f.detectorId === "pii-cpf")).toBe(false);
  });
});

describe("scanSync — PII: IBAN", () => {
  it("detects a valid GB IBAN", () => {
    const { findings } = scanSync("iban: GB82WEST12345698765432");
    expect(findings.some((f) => f.detectorId === "pii-iban")).toBe(true);
  });
  it("does not flag an invalid IBAN", () => {
    const { findings } = scanSync("ref: GB00WEST12345698765432");
    expect(findings.some((f) => f.detectorId === "pii-iban")).toBe(false);
  });
});

describe("scanSync — PII: private IP", () => {
  it("detects a 192.168.x.x IP", () => {
    const { findings } = scanSync("server: 192.168.1.100");
    expect(findings.some((f) => f.detectorId === "pii-private-ip")).toBe(true);
  });
  it("does not flag a public IP", () => {
    const { findings } = scanSync("dns: 8.8.8.8");
    expect(findings.some((f) => f.detectorId === "pii-private-ip")).toBe(false);
  });
});

// ── Engine: timeout ────────────────────────────────────────────────────────────

describe("scanSync — timeout", () => {
  it("returns timedOut=true when timeoutMs=0", () => {
    const result = scanSync("some text with AKIAIOSFODNN7EXAMPLE", { timeoutMs: 0 });
    expect(result.timedOut).toBe(true);
  });
  it("does not return findings when timed out", () => {
    const result = scanSync("AKIAIOSFODNN7EXAMPLE", { timeoutMs: 0 });
    expect(result.findings).toHaveLength(0);
  });
});

// ── Engine: allowlist ──────────────────────────────────────────────────────────

describe("scanSync — allowlist", () => {
  it("suppresses findings matching a literal allowlist entry", () => {
    const { findings } = scanSync("key=AKIAIOSFODNN7EXAMPLE", {
      allowlist: [{ id: "a1", pattern: "AKIAIOSFODNN7EXAMPLE", isRegex: false, reason: "test" }],
    });
    expect(findings.some((f) => f.detectorId === "aws-access-key")).toBe(false);
  });
  it("suppresses findings matching a regex allowlist entry", () => {
    const { findings } = scanSync("key=AKIAIOSFODNN7EXAMPLE", {
      allowlist: [{ id: "a2", pattern: "AKIA.*EXAMPLE", isRegex: true, reason: "test" }],
    });
    expect(findings.some((f) => f.detectorId === "aws-access-key")).toBe(false);
  });
  it("does not suppress findings with a non-matching allowlist", () => {
    const { findings } = scanSync("key=AKIAIOSFODNN7EXAMPLE", {
      allowlist: [{ id: "a3", pattern: "OTHERTHING", isRegex: false, reason: "test" }],
    });
    expect(findings.some((f) => f.detectorId === "aws-access-key")).toBe(true);
  });
  it("respects an expired allowlist entry", () => {
    const { findings } = scanSync("key=AKIAIOSFODNN7EXAMPLE", {
      allowlist: [{ id: "a4", pattern: "AKIAIOSFODNN7EXAMPLE", isRegex: false, reason: "test", expiresAt: "2000-01-01T00:00:00Z" }],
    });
    expect(findings.some((f) => f.detectorId === "aws-access-key")).toBe(true);
  });
});

// ── Engine: deduplication ─────────────────────────────────────────────────────

describe("scanSync — deduplication", () => {
  it("deduplicates the same finding across multiple matches", () => {
    const text = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE";
    const { findings } = scanSync(text);
    const awsFindings = findings.filter((f) => f.detectorId === "aws-access-key");
    expect(awsFindings.length).toBe(1);
  });
});

// ── Clean text ─────────────────────────────────────────────────────────────────

describe("scanSync — clean text", () => {
  it("returns no findings for clean text", () => {
    const { findings } = scanSync("hello world, no secrets here");
    expect(findings).toHaveLength(0);
  });
  it("returns no findings for empty text", () => {
    const { findings } = scanSync("");
    expect(findings).toHaveLength(0);
  });
});
