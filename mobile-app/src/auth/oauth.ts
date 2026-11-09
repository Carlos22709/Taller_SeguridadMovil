import { makeRedirectUri } from 'expo-auth-session';
import * as WebBrowser from 'expo-web-browser';

import { API_URL, APP_SCHEME, OAUTH_CLIENT_ID } from '../config';
import { createPkcePair, safeEqual, type PkcePair } from '../crypto/pkce';
import { platformCrypto } from '../crypto/platform';

/**
 * Flujo Authorization Code + PKCE (RFC 7636) con el NAVEGADOR DEL SISTEMA:
 *  - iOS: ASWebAuthenticationSession · Android: Custom Tabs.
 * No se usa WebView embebida: la app nunca ve ni puede inyectar JS en la página de login.
 */
export interface PendingAuthorization extends PkcePair {
  redirectUri: string;
  authorizeUrl: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string; // se guarda en Keychain / Keystore
}

export class OAuthError extends Error {
  constructor(
    message: string,
    readonly kind: 'cancelled' | 'state_mismatch' | 'denied' | 'exchange_failed' | 'invalid_callback',
  ) {
    super(message);
    this.name = 'OAuthError';
  }
}

export function getRedirectUri(): string {
  // Development/production build: unisabana-auth://callback · Expo Go: exp://<ip>:8081/--/callback
  return makeRedirectUri({ native: `${APP_SCHEME}://callback`, scheme: APP_SCHEME, path: 'callback' });
}

/** Genera el par PKCE, el state y la URL de autorización (antes de que el usuario toque "Iniciar sesión"). */
export async function prepareAuthorization(): Promise<PendingAuthorization> {
  const pkce = await createPkcePair(platformCrypto);
  const redirectUri = getRedirectUri();
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: OAUTH_CLIENT_ID,
    redirect_uri: redirectUri,
    state: pkce.state,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: 'S256',
  });
  return { ...pkce, redirectUri, authorizeUrl: `${API_URL}/oauth/authorize?${query.toString()}` };
}

function parseCallback(url: string): Record<string, string> {
  const queryStart = url.indexOf('?');
  if (queryStart === -1) return {};
  const query = url.slice(queryStart + 1).split('#')[0];
  const params: Record<string, string> = {};
  for (const pair of query.split('&')) {
    if (!pair) continue;
    const [key, ...rest] = pair.split('=');
    params[decodeURIComponent(key)] = decodeURIComponent(rest.join('=').replace(/\+/g, ' '));
  }
  return params;
}

/** Abre el navegador seguro, valida el state y canjea el code por tokens. */
export async function authorize(pending: PendingAuthorization): Promise<TokenResponse> {
  const result = await WebBrowser.openAuthSessionAsync(pending.authorizeUrl, pending.redirectUri);
  if (result.type !== 'success') {
    throw new OAuthError('Inicio de sesión cancelado.', 'cancelled');
  }

  const params = parseCallback(result.url);

  // Anti-CSRF: el state que vuelve en el deep link debe ser EXACTAMENTE el generado en memoria.
  if (!params.state || !safeEqual(params.state, pending.state)) {
    throw new OAuthError('El parámetro state no coincide. Intercambio abortado (posible CSRF).', 'state_mismatch');
  }
  if (params.error) {
    throw new OAuthError(params.error === 'access_denied' ? 'Acceso denegado.' : params.error, 'denied');
  }
  if (!params.code) {
    throw new OAuthError('El callback no trae código de autorización.', 'invalid_callback');
  }

  return exchangeCode(params.code, pending);
}

async function exchangeCode(code: string, pending: PendingAuthorization): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: pending.redirectUri,
    client_id: OAUTH_CLIENT_ID,
    code_verifier: pending.codeVerifier, // el backend verifica SHA256(verifier) === challenge
  });
  const response = await fetch(`${API_URL}/auth/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString(),
  });
  const data = (await response.json().catch(() => ({}))) as Partial<TokenResponse> & { message?: string };
  if (!response.ok || !data.access_token || !data.refresh_token) {
    throw new OAuthError(data.message ?? 'No se pudo canjear el código de autorización.', 'exchange_failed');
  }
  return data as TokenResponse;
}
