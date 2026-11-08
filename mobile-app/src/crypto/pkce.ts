import { asciiToBytes, base64UrlEncode } from './encoding';
import type { CryptoPrimitives } from './primitives';

/** Caracteres "unreserved" permitidos por RFC 7636: [A-Z] [a-z] [0-9] - . _ ~ (66 símbolos). */
const UNRESERVED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

export const VERIFIER_LENGTH = 64; // dentro de 43..128

/**
 * Cadena aleatoria uniforme sobre el alfabeto, sin sesgo de módulo (rejection sampling):
 * solo se aceptan bytes < 198 (= 66 * 3) para que cada símbolo tenga la misma probabilidad.
 */
export function randomUnreserved(crypto: CryptoPrimitives, length: number): string {
  const limit = UNRESERVED.length * Math.floor(256 / UNRESERVED.length);
  let out = '';
  while (out.length < length) {
    for (const byte of crypto.randomBytes(length)) {
      if (byte < limit && out.length < length) out += UNRESERVED[byte % UNRESERVED.length];
    }
  }
  return out;
}

/** code_challenge = BASE64URL(SHA256(ASCII(code_verifier))) sin relleno. */
export async function codeChallengeS256(crypto: CryptoPrimitives, verifier: string): Promise<string> {
  return base64UrlEncode(await crypto.sha256(asciiToBytes(verifier)));
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
}

export async function createPkcePair(crypto: CryptoPrimitives): Promise<PkcePair> {
  const codeVerifier = randomUnreserved(crypto, VERIFIER_LENGTH);
  return {
    codeVerifier,
    codeChallenge: await codeChallengeS256(crypto, codeVerifier),
    state: base64UrlEncode(crypto.randomBytes(32)), // anti-CSRF, único por solicitud
  };
}

/** Comparación en tiempo constante para el state. */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
