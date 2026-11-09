import { ApiClient } from '../api/client';
import { NetworkError } from '../api/errors';
import { API_URL } from '../config';
import { STORAGE_KEYS, secureStorage } from '../storage/secureStorage';
import { authorize, type PendingAuthorization } from './oauth';
import { session } from './session';

interface RefreshResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
}

/** POST /auth/refresh con el refresh_token guardado en Keychain / Keystore. */
async function refreshAccessToken(): Promise<string> {
  const stored = await secureStorage.getItem(STORAGE_KEYS.refreshToken);
  if (!stored) throw new Error('refresh_failed');
  let response: Response;
  try {
    response = await fetch(`${API_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ refresh_token: stored }),
    });
  } catch (cause) {
    throw new NetworkError(cause); // offline: se conserva el refresh_token
  }
  if (!response.ok) {
    await secureStorage.deleteItem(STORAGE_KEYS.refreshToken); // vencido o revocado: se limpia
    throw new Error('refresh_failed');
  }
  const data = (await response.json()) as RefreshResponse;
  await secureStorage.setItem(STORAGE_KEYS.refreshToken, data.refresh_token); // rotación
  session.setAccessToken(data.access_token);
  return data.access_token;
}

async function revokeStoredRefreshToken() {
  const stored = await secureStorage.getItem(STORAGE_KEYS.refreshToken);
  if (!stored) return;
  await fetch(`${API_URL}/auth/logout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: stored }),
  });
}

export const api = new ApiClient({
  baseUrl: API_URL,
  getAccessToken: session.getAccessToken,
  refreshAccessToken,
  onSessionExpired: () => {
    void secureStorage.deleteItem(STORAGE_KEYS.refreshToken);
    session.signOut('Tu sesión expiró. Vuelve a iniciar sesión.');
  },
});

export const authService = {
  /** Al abrir la app: si hay refresh_token guardado se restaura la sesión en silencio. */
  async restoreSession() {
    if (!(await secureStorage.getItem(STORAGE_KEYS.refreshToken))) {
      session.signOut();
      return;
    }
    try {
      await refreshAccessToken();
    } catch (error) {
      session.signOut(error instanceof NetworkError ? 'Sin conexión: puedes usar el Authenticator offline.' : null);
    }
  },

  async login(pending: PendingAuthorization) {
    const tokens = await authorize(pending);
    await secureStorage.setItem(STORAGE_KEYS.refreshToken, tokens.refresh_token);
    session.setAccessToken(tokens.access_token); // access_token solo en memoria
  },

  async logout() {
    await revokeStoredRefreshToken().catch(() => undefined);
    await secureStorage.deleteItem(STORAGE_KEYS.refreshToken);
    session.signOut();
  },

  // ---------- Utilidades para probar el Silent Refresh ----------

  /** Reemplaza el access_token en memoria por uno inválido para forzar 401. */
  expireAccessToken() {
    session.setAccessToken('token.expirado.demo');
  },

  /** Revoca el refresh_token en el servidor sin borrarlo localmente: el próximo refresh fallará. */
  revokeOnServer: revokeStoredRefreshToken,
};
