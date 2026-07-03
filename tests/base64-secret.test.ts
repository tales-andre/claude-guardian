import { describe, expect, it } from "vitest";
import { base64SecretDetector } from "../src/engine/detectors/base64-secret.ts";

const b64 = (s: string) => Buffer.from(s).toString("base64");

describe("base64SecretDetector", () => {
  it("detects an AWS key hidden inside a base64 blob", () => {
    const text = `payload: ${b64("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")}`;
    const findings = base64SecretDetector.scan(text);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.detectorId).toBe("base64-embedded-secret");
  });

  it("ignores a base64 blob that decodes to harmless text", () => {
    const text = `data: ${b64("the quick brown fox jumps over the lazy dog repeatedly")}`;
    expect(base64SecretDetector.scan(text)).toEqual([]);
  });

  it("ignores plain text with no base64 blob", () => {
    expect(base64SecretDetector.scan("just a normal sentence here")).toEqual(
      [],
    );
  });

  it("does not expose the decoded secret in the snippet", () => {
    const text = b64(
      "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and more padding text",
    );
    const findings = base64SecretDetector.scan(text);
    expect(findings[0]?.snippet).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });
});
