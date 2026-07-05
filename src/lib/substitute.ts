import { createHash } from "node:crypto";
import type { DataType, DetectorFinding } from "../types/index.ts";

// ── Substituição por placeholders fictícios (egress, mão única) ──────────────
// Em vez de bloquear ou mascarar com [REDACTED], reescreve o dado sensível por
// um valor FICTÍCIO plausível e com formato válido, para o prompt poder seguir
// com dados falsos. O valor real NUNCA sai da máquina.
//
// Propriedades:
//  • Determinístico: hash(rawValue + salt) semeia o gerador, então o MESMO
//    valor real vira SEMPRE o mesmo fake — integridade referencial de graça
//    (dentro do prompt e entre turnos), sem armazenar mapa nenhum.
//  • Format-preserving: CPF vira CPF de formato válido (mas de ninguém real),
//    e-mail vira e-mail, cartão passa no Luhn. dataType sem gerador dedicado
//    cai no "skeleton scramble" (preserva comprimento e classe de cada char),
//    e na pior hipótese em mask — nunca deixa o valor real passar.

// Salt padrão quando o operador não configura `substitutionSalt`. Ainda gera
// fakes determinísticos; configurar um salt secreto por instalação evita que
// terceiros correlacionem fakes entre organizações.
const DEFAULT_SALT = "claude-guardian/substitute/v1";

// PRNG determinístico (mulberry32) semeado a partir do hash do valor.
function seededRng(seedHex: string): () => number {
  let a = parseInt(seedHex.slice(0, 8), 16) >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function seedFor(dataType: string, rawValue: string, salt: string): string {
  return createHash("sha256")
    .update(`${salt}:${dataType}:${rawValue}`)
    .digest("hex");
}

function pick<T>(rng: () => number, list: readonly T[]): T {
  return list[Math.floor(rng() * list.length)] as T;
}

function randomDigits(rng: () => number, n: number): number[] {
  return Array.from({ length: n }, () => Math.floor(rng() * 10));
}

const FIRST_NAMES = [
  "Ana",
  "Bruno",
  "Carla",
  "Diego",
  "Elena",
  "Felipe",
  "Gabriela",
  "Hugo",
  "Isadora",
  "João",
  "Kelly",
  "Lucas",
  "Marina",
  "Nathan",
  "Olívia",
  "Paulo",
] as const;
const LAST_NAMES = [
  "Silva",
  "Souza",
  "Costa",
  "Pereira",
  "Almeida",
  "Ferreira",
  "Rocha",
  "Barbosa",
  "Ribeiro",
  "Carvalho",
  "Gomes",
  "Martins",
  "Araujo",
  "Melo",
  "Cardoso",
  "Teixeira",
] as const;

// ── Geradores dedicados por dataType ─────────────────────────────────────────

function fakeName(rng: () => number): string {
  return `${pick(rng, FIRST_NAMES)} ${pick(rng, LAST_NAMES)}`;
}

function fakeEmail(rng: () => number): string {
  const first = pick(rng, FIRST_NAMES).toLowerCase();
  const last = pick(rng, LAST_NAMES).toLowerCase();
  const n = Math.floor(rng() * 90) + 10;
  // example.com/.org são domínios reservados (RFC 2606): nunca de alguém real.
  return `${first}.${last}${n}@example.com`;
}

function cpfCheckDigit(digits: number[], weights: number[]): number {
  let s = 0;
  for (let i = 0; i < weights.length; i++)
    s += (digits[i] ?? 0) * (weights[i] ?? 0);
  const r = (s * 10) % 11;
  return r === 10 ? 0 : r;
}

function fakeCpf(rng: () => number, formatted: boolean): string {
  let base = randomDigits(rng, 9);
  if (base.every((d) => d === base[0])) base = [1, 2, 3, 4, 5, 6, 7, 8, 9];
  const d1 = cpfCheckDigit(base, [10, 9, 8, 7, 6, 5, 4, 3, 2]);
  const d2 = cpfCheckDigit([...base, d1], [11, 10, 9, 8, 7, 6, 5, 4, 3, 2]);
  const all = [...base, d1, d2].join("");
  return formatted
    ? `${all.slice(0, 3)}.${all.slice(3, 6)}.${all.slice(6, 9)}-${all.slice(9)}`
    : all;
}

function cnpjCheckDigit(digits: number[], weights: number[]): number {
  let s = 0;
  for (let i = 0; i < weights.length; i++)
    s += (digits[i] ?? 0) * (weights[i] ?? 0);
  const r = s % 11;
  return r < 2 ? 0 : 11 - r;
}

function fakeCnpj(rng: () => number, formatted: boolean): string {
  let base = randomDigits(rng, 12);
  if (base.every((d) => d === base[0]))
    base = [1, 1, 2, 2, 2, 2, 0, 0, 0, 1, 8, 5];
  const d1 = cnpjCheckDigit(base, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const d2 = cnpjCheckDigit(
    [...base, d1],
    [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2],
  );
  const all = [...base, d1, d2].join("");
  return formatted
    ? `${all.slice(0, 2)}.${all.slice(2, 5)}.${all.slice(5, 8)}/${all.slice(8, 12)}-${all.slice(12)}`
    : all;
}

// Gera um número que passa no Luhn preservando o agrupamento (espaços/hífens)
// do original.
function fakeCreditCard(rng: () => number, raw: string): string {
  const len = raw.replace(/\D/g, "").length || 16;
  const body = [4, ...randomDigits(rng, Math.max(0, len - 2))]; // prefixo tipo Visa
  // calcula dígito de Luhn para fechar o número
  let sum = 0;
  let dbl = true; // último dígito (o de verificação) tem posição par a partir da direita
  for (let i = body.length - 1; i >= 0; i--) {
    let d = body[i] ?? 0;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  const check = (10 - (sum % 10)) % 10;
  const digits = [...body, check].join("");
  // reaplica o mesmo esqueleto de separadores do original
  let di = 0;
  return raw.replace(/\d/g, () => digits[di++] ?? "0");
}

// Fallback genérico: preserva o comprimento e a classe (dígito/minúscula/
// maiúscula) de cada caractere; separadores e prefixos-forma são mantidos.
// Garante "parece um segredo/telefone/etc." sem revelar o valor real.
function scrambleSkeleton(rng: () => number, raw: string): string {
  const digits = "0123456789";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let out = "";
  for (const ch of raw) {
    if (ch >= "0" && ch <= "9") out += pick(rng, digits.split(""));
    else if (ch >= "a" && ch <= "z") out += pick(rng, lower.split(""));
    else if (ch >= "A" && ch <= "Z") out += pick(rng, upper.split(""));
    else out += ch;
  }
  return out;
}

// Mask final para dataType sem gerador aplicável (mesma forma do redact).
function mask(str: string): string {
  if (str.length <= 8) return "****";
  return `${str.slice(0, 2)}****${str.slice(-2)}`;
}

/**
 * Gera o valor fictício determinístico para um dado sensível.
 * O mesmo (dataType, rawValue, salt) sempre produz o mesmo fake.
 */
export function generateFake(
  dataType: DataType,
  rawValue: string,
  salt = DEFAULT_SALT,
): string {
  if (!rawValue) return rawValue;
  const rng = seededRng(seedFor(dataType, rawValue, salt));

  switch (dataType) {
    case "person-name":
      return fakeName(rng);
    case "email":
      return fakeEmail(rng);
    case "cpf":
      return fakeCpf(rng, rawValue.includes("."));
    case "cnpj":
      return fakeCnpj(rng, rawValue.includes("."));
    case "credit-card":
      return fakeCreditCard(rng, rawValue);
    case "ssn":
    case "iban":
    case "phone-br":
    case "phone-us":
    case "phone-jp":
    case "private-ip":
    case "aws-key":
    case "gcp-key":
    case "github-token":
    case "gitlab-token":
    case "jwt":
    case "slack-token":
    case "stripe-key":
    case "openai-key":
    case "anthropic-key":
    case "generic-secret":
    case "connection-string":
      return scrambleSkeleton(rng, rawValue);
    default:
      // dataType desconhecido com forma alfanumérica → scramble; senão mask.
      return /[A-Za-z0-9]/.test(rawValue)
        ? scrambleSkeleton(rng, rawValue)
        : mask(rawValue);
  }
}

/**
 * Reescreve `text` trocando cada rawValue dos findings pelo seu fake
 * determinístico. Todas as ocorrências do mesmo valor recebem o mesmo fake
 * (integridade referencial). Substitui os valores mais longos primeiro para
 * evitar corromper um valor que seja substring de outro.
 */
export function substituteText(
  text: string,
  findings: DetectorFinding[],
  salt = DEFAULT_SALT,
): string {
  const seen = new Set<string>();
  const ordered = [...findings]
    .filter((f) => f.rawValue && !seen.has(f.rawValue) && seen.add(f.rawValue))
    .sort((a, b) => b.rawValue.length - a.rawValue.length);

  let out = text;
  for (const f of ordered) {
    const fake = generateFake(f.dataType, f.rawValue, salt);
    out = out.split(f.rawValue).join(fake);
  }
  return out;
}
