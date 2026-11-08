import { hmac, type HashFn } from './hmac';

/**
 * TOTP (RFC 6238) = HOTP (RFC 4226) con contador T = floor(unix / 30).
 * Implementado desde cero: sin otplib, speakeasy ni similares.
 */
export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;

/** T = floor(UnixTimestamp / 30) */
export function timeCounter(unixMs: number, period = TOTP_PERIOD_SECONDS): number {
  return Math.floor(unixMs / 1000 / period);
}

/** Segundos que le quedan al código actual (30..1). */
export function secondsRemaining(unixMs: number, period = TOTP_PERIOD_SECONDS): number {
  return period - (Math.floor(unixMs / 1000) % period);
}

/**
 * Contador como entero de 64 bits Big-Endian (8 bytes).
 * Los operadores de bits de JS trabajan en 32 bits, así que se separa en parte alta y baja.
 */
export function counterToBytes(counter: number): Uint8Array {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('Contador inválido');
  const high = Math.floor(counter / 2 ** 32);
  const low = counter >>> 0;
  const bytes = new Uint8Array(8);
  bytes[0] = (high >>> 24) & 0xff;
  bytes[1] = (high >>> 16) & 0xff;
  bytes[2] = (high >>> 8) & 0xff;
  bytes[3] = high & 0xff;
  bytes[4] = (low >>> 24) & 0xff;
  bytes[5] = (low >>> 16) & 0xff;
  bytes[6] = (low >>> 8) & 0xff;
  bytes[7] = low & 0xff;
  return bytes;
}

/** Truncamiento dinámico (RFC 4226 §5.3). */
export function dynamicTruncate(h: Uint8Array, digits = TOTP_DIGITS): string {
  const offset = h[h.length - 1] & 0x0f; // H[19] & 0x0F para SHA-1
  const binCode =
    ((h[offset] & 0x7f) << 24) |
    ((h[offset + 1] & 0xff) << 16) |
    ((h[offset + 2] & 0xff) << 8) |
    (h[offset + 3] & 0xff);
  return String(binCode % 10 ** digits).padStart(digits, '0');
}

export async function hotp(sha1: HashFn, key: Uint8Array, counter: number, digits = TOTP_DIGITS): Promise<string> {
  const h = await hmac(sha1, key, counterToBytes(counter)); // H = HMAC-SHA1(K, T)
  return dynamicTruncate(h, digits);
}

export async function totp(sha1: HashFn, key: Uint8Array, unixMs: number, digits = TOTP_DIGITS): Promise<string> {
  return hotp(sha1, key, timeCounter(unixMs), digits);
}
