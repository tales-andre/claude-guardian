// Shannon entropy in bits per character (0–8 scale).
export function entropy(str: string): number {
  if (str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1;
  let h = 0;
  const n = str.length;
  for (const count of Object.values(freq)) {
    const p = count / n;
    h -= p * Math.log2(p);
  }
  return h;
}

// Luhn checksum validation for credit-card-like numbers.
export function luhn(str: string): boolean {
  const digits = str.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i] ?? "0", 10);
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// CPF digit verification (Brazilian individual taxpayer registry).
export function validCpf(digits: string): boolean {
  if (digits.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(digits)) return false;
  const calc = (d: string, weights: number[]): number => {
    let s = 0;
    for (let i = 0; i < weights.length; i++)
      s += parseInt(d[i] ?? "0", 10) * (weights[i] ?? 0);
    const r = (s * 10) % 11;
    return r === 10 ? 0 : r;
  };
  const d1 = calc(digits, [10, 9, 8, 7, 6, 5, 4, 3, 2]);
  const d2 = calc(digits, [11, 10, 9, 8, 7, 6, 5, 4, 3, 2]);
  return (
    d1 === parseInt(digits[9] ?? "", 10) &&
    d2 === parseInt(digits[10] ?? "", 10)
  );
}

// CNPJ digit verification (Brazilian corporate taxpayer registry).
export function validCnpj(digits: string): boolean {
  if (digits.length !== 14) return false;
  if (/^(\d)\1{13}$/.test(digits)) return false;
  const calc = (d: string, weights: number[]): number => {
    let s = 0;
    for (let i = 0; i < weights.length; i++)
      s += parseInt(d[i] ?? "0", 10) * (weights[i] ?? 0);
    const r = s % 11;
    return r < 2 ? 0 : 11 - r;
  };
  const d1 = calc(digits, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const d2 = calc(digits, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  return (
    d1 === parseInt(digits[12] ?? "", 10) &&
    d2 === parseInt(digits[13] ?? "", 10)
  );
}

// IBAN checksum: move first 4 chars to end, convert letters to digits, check mod 97 == 1.
export function validIban(iban: string): boolean {
  const normalized = iban.replace(/\s/g, "").toUpperCase();
  if (normalized.length < 15 || normalized.length > 34) return false;
  const rearranged = normalized.slice(4) + normalized.slice(0, 4);
  const numeric = rearranged.replace(/[A-Z]/g, (c) =>
    String(c.charCodeAt(0) - 55),
  );
  let remainder = 0;
  for (const ch of numeric) {
    remainder = (remainder * 10 + parseInt(ch, 10)) % 97;
  }
  return remainder === 1;
}

// Redact: show first 4 and last 4 chars; mask strings of 8 chars or fewer.
export function redact(str: string): string {
  if (str.length <= 8) return "****";
  return `${str.slice(0, 4)}****${str.slice(-4)}`;
}
