import { describe, expect, it } from "vitest";
import { evaluatePolicy, findApprovalTtl } from "../src/lib/policy.ts";
import type { DetectorFinding, PolicyRule } from "../src/types/index.ts";

function makeFinding(
  detectorId: string,
  dataType: string,
  severity: "critical" | "high" | "medium" | "low",
): DetectorFinding {
  return {
    detectorId,
    label: detectorId,
    dataType,
    severity,
    snippet: "****",
    rawValue: "raw-value",
    position: { start: 0, end: 10 },
    confidence: 0.9,
  };
}

const blockAllSecrets: PolicyRule = {
  id: "block-secrets",
  name: "Block all secrets",
  enabled: true,
  dataTypes: ["aws-key", "github-token"],
  action: "block",
};

const approvalPii: PolicyRule = {
  id: "approve-pii",
  name: "Require approval for PII",
  enabled: true,
  dataTypes: ["email"],
  action: "require-approval",
  ttlSeconds: 7200,
};

const allowLowSeverity: PolicyRule = {
  id: "allow-low",
  name: "Allow low severity",
  enabled: true,
  minSeverity: "low",
  action: "allow",
};

describe("evaluatePolicy", () => {
  it("returns allow when there are no findings", () => {
    expect(evaluatePolicy([], "Bash", [blockAllSecrets])).toBe("allow");
  });

  it("returns block for a matching rule", () => {
    const f = makeFinding("aws-access-key", "aws-key", "critical");
    expect(evaluatePolicy([f], "Bash", [blockAllSecrets])).toBe("block");
  });

  it("returns require-approval when matching that rule", () => {
    const f = makeFinding("pii-email", "email", "medium");
    expect(evaluatePolicy([f], "Bash", [approvalPii])).toBe("require-approval");
  });

  it("block takes priority over require-approval", () => {
    const findings = [
      makeFinding("aws-access-key", "aws-key", "critical"),
      makeFinding("pii-email", "email", "medium"),
    ];
    expect(evaluatePolicy(findings, "Bash", [blockAllSecrets, approvalPii])).toBe("block");
  });

  it("returns allow when no rule matches", () => {
    const f = makeFinding("pii-private-ip", "private-ip", "low");
    expect(evaluatePolicy([f], "Bash", [blockAllSecrets])).toBe("allow");
  });

  it("ignores disabled rules", () => {
    const disabledRule: PolicyRule = {
      ...blockAllSecrets,
      enabled: false,
    };
    const f = makeFinding("aws-access-key", "aws-key", "critical");
    expect(evaluatePolicy([f], "Bash", [disabledRule])).toBe("allow");
  });

  it("respects minSeverity filter — does not block low when min is high", () => {
    const highRule: PolicyRule = {
      id: "high-only",
      name: "Block high and above",
      enabled: true,
      dataTypes: ["aws-key"],
      minSeverity: "high",
      action: "block",
    };
    const lowFinding = makeFinding("aws-access-key", "aws-key", "low");
    expect(evaluatePolicy([lowFinding], "Bash", [highRule])).toBe("allow");
  });

  it("respects minSeverity filter — blocks critical when min is high", () => {
    const highRule: PolicyRule = {
      id: "high-only",
      name: "Block high and above",
      enabled: true,
      dataTypes: ["aws-key"],
      minSeverity: "high",
      action: "block",
    };
    const critFinding = makeFinding("aws-access-key", "aws-key", "critical");
    expect(evaluatePolicy([critFinding], "Bash", [highRule])).toBe("block");
  });

  it("respects tool filter — only blocks for matching tool", () => {
    const bashOnlyRule: PolicyRule = {
      id: "bash-only",
      name: "Block in Bash",
      enabled: true,
      dataTypes: ["aws-key"],
      tools: ["Bash"],
      action: "block",
    };
    const f = makeFinding("aws-access-key", "aws-key", "critical");
    expect(evaluatePolicy([f], "Bash", [bashOnlyRule])).toBe("block");
    expect(evaluatePolicy([f], "Read", [bashOnlyRule])).toBe("allow");
  });
});

describe("findApprovalTtl", () => {
  it("returns the TTL from a matching require-approval rule", () => {
    const f = makeFinding("pii-email", "email", "medium");
    expect(findApprovalTtl([f], "Bash", [approvalPii])).toBe(7200);
  });

  it("returns default 3600 when no TTL is declared", () => {
    const noTtlRule: PolicyRule = {
      id: "no-ttl",
      name: "No TTL rule",
      enabled: true,
      dataTypes: ["aws-key"],
      action: "require-approval",
    };
    const f = makeFinding("aws-access-key", "aws-key", "critical");
    expect(findApprovalTtl([f], "Bash", [noTtlRule])).toBe(3600);
  });

  it("returns 3600 when no rule matches", () => {
    const f = makeFinding("aws-access-key", "aws-key", "critical");
    expect(findApprovalTtl([f], "Bash", [approvalPii])).toBe(3600);
  });
});
