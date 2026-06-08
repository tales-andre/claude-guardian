import { entropy, redact } from "../utils.ts";
import { makeFinding } from "./types.ts";
import type { Detector, DetectorFinding } from "./types.ts";

const LEGACY_KEY_RE = /sk-(?!proj-|ant-)[A-Za-z0-9]{48}/g;
const PROJECT_KEY_RE = /sk-proj-[A-Za-z0-9_-]{40,}/g;
const ANTHROPIC_KEY_RE = /sk-ant-[A-Za-z0-9_-]{95}/g;

export const openAiLegacyKeyDetector: Detector = {
  id: "openai-key",
  label: "OpenAI API Key (legacy)",
  dataType: "openai-key",
  severity: "critical",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(LEGACY_KEY_RE)) {
      const raw = m[0];
      findings.push(makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.95));
    }
    return findings;
  },
};

export const openAiProjectKeyDetector: Detector = {
  id: "openai-project-key",
  label: "OpenAI Project API Key",
  dataType: "openai-key",
  severity: "critical",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(PROJECT_KEY_RE)) {
      const raw = m[0];
      if (entropy(raw) < 3.5) continue;
      findings.push(makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.95));
    }
    return findings;
  },
};

export const anthropicKeyDetector: Detector = {
  id: "anthropic-key",
  label: "Anthropic API Key",
  dataType: "anthropic-key",
  severity: "critical",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(ANTHROPIC_KEY_RE)) {
      const raw = m[0];
      findings.push(makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.97));
    }
    return findings;
  },
};
