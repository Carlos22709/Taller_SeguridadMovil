/** Decodificador Base32 (RFC 4648 §6) para la semilla TOTP. */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Quita espacios/guiones y pasa a mayúsculas: "jbsw y3dp" -> "JBSWY3DP". */
export function normalizeBase32(input: string): string {
  return input.replace(/[\s-]/g, '').toUpperCase();
}

/** Devuelve un mensaje de error legible o null si la semilla es válida. */
export function validateBase32(input: string): string | null {
  const clean = normalizeBase32(input);
  if (clean.length === 0) return 'Ingresa la semilla Base32.';
  if (!/^[A-Z2-7]+=*$/.test(clean)) return 'Solo se permiten letras A-Z y dígitos 2-7.';
  const bits = clean.replace(/=+$/, '').length * 5;
  if (bits < 80) return 'La semilla es demasiado corta (mínimo 16 caracteres / 80 bits).';
  return null;
}

export function base32Decode(input: string): Uint8Array {
  const clean = normalizeBase32(input).replace(/=+$/, '');
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error('Base32 inválido');

  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of clean) {
    buffer = ((buffer << 5) | ALPHABET.indexOf(char)) & 0xffff; // solo se necesitan los bits recientes
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}
