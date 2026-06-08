import { validCnpj, validCpf } from "../utils.ts";
import { makeFinding } from "./types.ts";
import type { Detector, DetectorFinding } from "./types.ts";

// CPF: nnn.nnn.nnn-nn or 11 consecutive digits.
const CPF_RE =
  /\b(?:\d{3}\.){2}\d{3}-\d{2}|\b\d{11}\b/g;

// CNPJ: nn.nnn.nnn/nnnn-nn or 14 consecutive digits.
const CNPJ_RE =
  /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}|\b\d{14}\b/g;

// Brazilian mobile / landline: (DD) 9NNNN-NNNN or (DD) NNNN-NNNN
const PHONE_BR_RE =
  /\(0?[1-9]{2}\)\s?(?:9\s?[0-9]{4}|[2-8][0-9]{3})-[0-9]{4}/g;

export const cpfDetector: Detector = {
  id: "pii-cpf",
  label: "Brazilian CPF (Individual Taxpayer Registry)",
  dataType: "cpf",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(CPF_RE)) {
      const raw = m[0];
      const digits = raw.replace(/\D/g, "");
      if (!validCpf(digits)) continue;
      findings.push(
        makeFinding(this, raw, `***.***.${digits.slice(6, 9)}-**`, m.index, m.index + raw.length, 0.97),
      );
    }
    return findings;
  },
};

export const cnpjDetector: Detector = {
  id: "pii-cnpj",
  label: "Brazilian CNPJ (Corporate Taxpayer Registry)",
  dataType: "cnpj",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(CNPJ_RE)) {
      const raw = m[0];
      const digits = raw.replace(/\D/g, "");
      if (!validCnpj(digits)) continue;
      findings.push(
        makeFinding(this, raw, `**.***.${digits.slice(5, 8)}/**-**`, m.index, m.index + raw.length, 0.97),
      );
    }
    return findings;
  },
};

export const phoneBrDetector: Detector = {
  id: "pii-phone-br",
  label: "Brazilian Phone Number",
  dataType: "phone-br",
  severity: "medium",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(PHONE_BR_RE)) {
      const raw = m[0];
      findings.push(makeFinding(this, raw, "(DD) ****-****", m.index, m.index + raw.length, 0.85));
    }
    return findings;
  },
};
