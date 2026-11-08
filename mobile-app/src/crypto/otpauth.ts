import { normalizeBase32, validateBase32 } from './base32';
import { TOTP_DIGITS, TOTP_PERIOD_SECONDS } from './totp';

export interface TotpAccount {
  secret: string; // Base32 normalizado
  issuer: string;
  account: string;
}

export type ParseResult = { ok: true; value: TotpAccount } | { ok: false; error: string };

function param(query: string, name: string): string | undefined {
  for (const pair of query.split('&')) {
    const [key, ...rest] = pair.split('=');
    if (decodeURIComponent(key).toLowerCase() === name) return decodeURIComponent(rest.join('=').replace(/\+/g, ' '));
  }
  return undefined;
}

/**
 * Acepta una URI "otpauth://totp/Issuer:cuenta?secret=...&issuer=..." (contenido del QR)
 * o directamente la semilla Base32 pegada a mano.
 */
export function parseTotpInput(raw: string): ParseResult {
  const input = raw.trim();
  if (!input.toLowerCase().startsWith('otpauth://')) {
    const error = validateBase32(input);
    return error
      ? { ok: false, error }
      : { ok: true, value: { secret: normalizeBase32(input), issuer: 'UniSabana', account: 'Cuenta manual' } };
  }

  const match = /^otpauth:\/\/([^/]+)\/([^?]*)\??(.*)$/i.exec(input);
  if (!match) return { ok: false, error: 'URI otpauth mal formada.' };
  const [, type, rawLabel, query] = match;
  if (type.toLowerCase() !== 'totp') return { ok: false, error: 'Solo se soportan códigos TOTP.' };

  const secret = param(query, 'secret');
  if (!secret) return { ok: false, error: 'La URI no trae el parámetro secret.' };
  const secretError = validateBase32(secret);
  if (secretError) return { ok: false, error: secretError };

  const algorithm = (param(query, 'algorithm') ?? 'SHA1').toUpperCase();
  const digits = Number(param(query, 'digits') ?? TOTP_DIGITS);
  const period = Number(param(query, 'period') ?? TOTP_PERIOD_SECONDS);
  if (algorithm !== 'SHA1' || digits !== TOTP_DIGITS || period !== TOTP_PERIOD_SECONDS) {
    return { ok: false, error: 'Solo se soporta SHA1, 6 dígitos y periodo de 30 s.' };
  }

  const label = decodeURIComponent(rawLabel);
  const [labelIssuer, labelAccount] = label.includes(':') ? label.split(/:(.*)/s) : [undefined, label];
  return {
    ok: true,
    value: {
      secret: normalizeBase32(secret),
      issuer: param(query, 'issuer') ?? labelIssuer ?? 'Desconocido',
      account: (labelAccount ?? label).trim() || 'Cuenta',
    },
  };
}
