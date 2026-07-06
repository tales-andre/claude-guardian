import { entropy, redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// Matches standalone hex strings of 40+ chars (word boundaries required).
// 40 chars = SHA-1 / git hash minimum; 64 chars = SHA-256 / common API token length.
const HEX_RE = /\b([0-9a-f]{40,})\b/gi;

// Words that, when appearing just before the hex string, indicate it's a
// legitimate hash/checksum — not a secret that was accidentally pasted.
const HASH_CONTEXT_RE =
  /(?:sha(?:256|512|1|2|3)?|md5|hash|checksum|digest|fingerprint|commit|tree|blob)\s*:?\s*$/i;

// Service-prefixed API keys that embed the key directly in the name with `_`
// separator (no `=` or `:` between prefix and value).
// Format: <service>_api_key_<hex-or-alphanum>
const N8N_RE = /\bn8n_api_key_[a-zA-Z0-9]{20,}\b/g;

// Broader: any <word>_api_key_<value> or <word>_secret_key_<value> pattern
// where the value is high entropy. Catches proprietary service key formats.
const EMBEDDED_KEY_RE =
  /\b[a-z][a-z0-9]*_(?:api_key|secret_key|auth_token|access_token)_([A-Za-z0-9\-_]{20,})\b/g;

export const hexHighEntropyDetector: Detector = {
  id: "hex-high-entropy",
  label: "High-Entropy Hex String",
  dataType: "generic-secret",
  severity: "medium",
  pattern: HEX_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(HEX_RE)) {
      const raw = m[1];
      if (!raw) continue;
      if (entropy(raw) < 3.7) continue;

      // Skip if preceded by a hash/checksum keyword (likely a legitimate digest).
      const before = text.slice(Math.max(0, (m.index ?? 0) - 30), m.index ?? 0);
      if (HASH_CONTEXT_RE.test(before)) continue;

      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index ?? 0,
          (m.index ?? 0) + raw.length,
          0.65,
        ),
      );
    }
    return findings;
  },
};

export const n8nApiKeyDetector: Detector = {
  id: "n8n-api-key",
  label: "n8n API Key",
  dataType: "generic-secret",
  severity: "high",
  pattern: N8N_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(N8N_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index ?? 0,
          (m.index ?? 0) + raw.length,
          0.95,
        ),
      );
    }
    return findings;
  },
};

export const embeddedKeyDetector: Detector = {
  id: "embedded-service-key",
  label: "Service API Key (embedded format)",
  dataType: "generic-secret",
  severity: "medium",
  pattern: EMBEDDED_KEY_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(EMBEDDED_KEY_RE)) {
      const raw = m[0];
      const value = m[1];
      if (!value || entropy(value) < 3.5) continue;
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index ?? 0,
          (m.index ?? 0) + raw.length,
          0.8,
        ),
      );
    }
    return findings;
  },
};
