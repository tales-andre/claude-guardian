import type {
  DataType,
  DetectorFinding,
  PolicyAction,
  PolicyRule,
  Severity,
} from "../types/index.ts";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function meetsMinSeverity(
  finding: DetectorFinding,
  minSeverity: Severity,
): boolean {
  return (SEVERITY_ORDER[finding.severity] ?? 0) >= (SEVERITY_ORDER[minSeverity] ?? 0);
}

function ruleMatches(
  rule: PolicyRule,
  finding: DetectorFinding,
  tool: string,
): boolean {
  if (rule.dataTypes && !rule.dataTypes.includes(finding.dataType as DataType)) return false;
  if (rule.detectorIds && !rule.detectorIds.includes(finding.detectorId)) return false;
  if (rule.tools && !rule.tools.some((t) => t === "*" || t === tool)) return false;
  if (rule.minSeverity && !meetsMinSeverity(finding, rule.minSeverity)) return false;
  return true;
}

export function evaluatePolicy(
  findings: DetectorFinding[],
  tool: string,
  rules: PolicyRule[],
): PolicyAction {
  if (findings.length === 0) return "allow";

  const enabledRules = rules.filter((r) => r.enabled);

  const actionPriority: Record<PolicyAction, number> = {
    block: 4,
    "require-approval": 3,
    redact: 2,
    allow: 1,
  };

  let highestAction: PolicyAction = "allow";

  for (const finding of findings) {
    for (const rule of enabledRules) {
      if (!ruleMatches(rule, finding, tool)) continue;
      const current = actionPriority[rule.action] ?? 0;
      const best = actionPriority[highestAction] ?? 0;
      if (current > best) highestAction = rule.action;
      if (highestAction === "block") return "block";
    }
  }

  return highestAction;
}

// For a given action, find the TTL from the first matching rule that declares one.
export function findApprovalTtl(
  findings: DetectorFinding[],
  tool: string,
  rules: PolicyRule[],
): number {
  for (const rule of rules.filter((r) => r.enabled && r.action === "require-approval")) {
    for (const finding of findings) {
      if (ruleMatches(rule, finding, tool) && rule.ttlSeconds) {
        return rule.ttlSeconds;
      }
    }
  }
  return 3600;
}
