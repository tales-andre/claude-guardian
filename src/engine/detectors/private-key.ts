import { makeFinding } from "./types.ts";
import type { Detector, DetectorFinding } from "./types.ts";

// PEM-encoded private keys: RSA, EC, DSA, PGP, OpenSSH.
// The header is enough to positively identify a key block.
const PEM_RE =
  /-----BEGIN[ \t]*(RSA |EC |DSA |PGP |OPENSSH )?PRIVATE KEY[-\s]/g;

export const privateKeyDetector: Detector = {
  id: "private-key",
  label: "PEM Private Key",
  dataType: "private-key",
  severity: "critical",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(PEM_RE)) {
      const raw = m[0].trim();
      findings.push(
        makeFinding(
          this,
          raw,
          "[PEM private key header]",
          m.index,
          m.index + m[0].length,
          0.99,
        ),
      );
    }
    return findings;
  },
};
