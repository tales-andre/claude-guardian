import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// ── Detecção de entidades (nomes/endereços) — "NER" leve, em processo ────────
// Recall de PII que o regex estruturado não pega: nomes de pessoa e endereços.
// É o PISO rápido e síncrono que cabe no orçamento do hook. Um modelo NER real
// (ONNX quantizado, multilíngue) é o passo seguinte e deve rodar no daemon
// persistente com o modelo "warm" — encaixá-lo aqui via a mesma interface
// Detector (dataType person-name/postal-address) mantém o resto do pipeline
// (dedup, policy, substitute) inalterado.
//
// Conservador de propósito: substituição falha ABERTA, então preferimos perder
// uma entidade duvidosa a poluir o prompt com falsos positivos. Ligado apenas
// quando `config.entityDetection` é true (extraDetector, como o gitleaks).

// Tokens capitalizados que costumam NÃO ser nomes de pessoa (reduz falso+).
const NON_NAMES = new Set([
  "O",
  "A",
  "Os",
  "As",
  "Um",
  "Uma",
  "Eu",
  "Ele",
  "Ela",
  "Você",
  "Nós",
  "Isso",
  "Este",
  "Esta",
  "Esse",
  "Essa",
  "Como",
  "Quando",
  "Onde",
  "Porque",
  "Segue",
  "Olá",
  "Oi",
  "Bom",
  "Boa",
  "Prezado",
  "Prezada",
  "Att",
  "Atenciosamente",
  "The",
  "This",
  "That",
  "Hello",
  "Hi",
  "Dear",
  "New",
  "San",
  "São",
]);

// Frases/pronomes de apresentação que ancoram um nome logo à frente (alta conf).
const ANCHOR_RE =
  /\b(?:Sr\.?|Sra\.?|Dr\.?|Dra\.?|Senhor|Senhora|meu nome é|me chamo|chamo-me|nome(?: completo)?:?)\s+([A-ZÀ-Ý][a-zà-ÿ]{1,20}(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ý][a-zà-ÿ]{1,20}){1,3})/g;

// Sequência de 2 a 4 palavras capitalizadas (Nome Sobrenome …), com conectores
// pt (da/de/do/dos). Confiança menor — filtrada pela stoplist.
const FULLNAME_RE =
  /\b[A-ZÀ-Ý][a-zà-ÿ]{1,20}(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ý][a-zà-ÿ]{1,20}){1,3}\b/g;

function pushName(
  findings: DetectorFinding[],
  seen: Set<string>,
  detector: Omit<Detector, "scan">,
  raw: string,
  start: number,
  confidence: number,
): void {
  const trimmed = raw.trim();
  if (trimmed.length < 3) return;
  const first = trimmed.split(/\s+/)[0] ?? "";
  if (NON_NAMES.has(first)) return;
  if (seen.has(trimmed)) return;
  seen.add(trimmed);
  findings.push(
    makeFinding(
      detector,
      trimmed,
      "[name]",
      start,
      start + trimmed.length,
      confidence,
    ),
  );
}

export const personNameDetector: Detector = {
  id: "entity-person-name",
  label: "Person Name",
  dataType: "person-name",
  severity: "medium",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    const seen = new Set<string>();

    for (const m of text.matchAll(ANCHOR_RE)) {
      const name = m[1];
      if (!name) continue;
      const start = m.index + m[0].lastIndexOf(name);
      pushName(findings, seen, this, name, start, 0.8);
    }
    for (const m of text.matchAll(FULLNAME_RE)) {
      pushName(findings, seen, this, m[0], m.index, 0.5);
    }
    return findings;
  },
};

// Endereços (BR): logradouro + número. Bounded para evitar ReDoS.
const ADDRESS_RE =
  /\b(?:Rua|R\.|Avenida|Av\.?|Alameda|Al\.|Travessa|Praça|Rodovia|Estrada)\s+[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ0-9.\s]{2,40}?,?\s*(?:n[º°.]?\s*)?\d{1,6}\b/g;

export const postalAddressDetector: Detector = {
  id: "entity-postal-address",
  label: "Postal Address",
  dataType: "postal-address",
  severity: "medium",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(ADDRESS_RE)) {
      const raw = m[0].trim();
      findings.push(
        makeFinding(this, raw, "[address]", m.index, m.index + raw.length, 0.6),
      );
    }
    return findings;
  },
};

// Reunidos para ligar de uma vez nas superfícies de egress (quando habilitado).
export const entityDetectors: readonly Detector[] = [
  personNameDetector,
  postalAddressDetector,
];
