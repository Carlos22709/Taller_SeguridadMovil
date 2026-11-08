import { ApiClient } from '../api/client';
import { NetworkError } from '../api/errors';
import { API_URL, IS_WEB } from '../config';
import { STORAGE_KEYS, secureStorage } from '../storage/secureStorage';
import { authorize, type PendingAuthorization } from './oauth';
import { session } from './session';

interface RefreshResponse {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
}

/** POST /auth/refresh. Nativo: manda el refresh_token del Keychain/Keystore. Web: va en cookie. */
async function refreshAccessToken(): Promise<string> {
  const stored = await secureStorage.getItem(STORAGE_KEYS.refreshToken);
  let response: Response;
  try {
    response = await fetch(`${API_URL}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(stored ? { refresh_token: stored } : {}),
      credentials: 'include',
    });
  } catch (cause) {
    throw new NetworkError(cause); // offline: se conserva el refresh_token
  }
  if (!response.ok) {
    await secureStorage.deleteItem(STORAGE_KEYS.refreshToken); // vencido o revocado: se limpia
    throw new Error('refresh_failed');
  }
  const data = (await response.json()) as RefreshResponse;
  if (data.refresh_token) {
    await secureStorage.setItem(STORAGE_KEYS.refreshToken, data.refresh_token); // rotación
  }
  session.setAccessToken(data.access_token);
  return data.access_token;
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
    // En nativo, sin refresh_token guardado no hay nada que restaurar. En web puede estar en la cookie.
    if (!IS_WEB && !(await secureStorage.getItem(STORAGE_KEYS.refreshToken))) {
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
    if (tokens.refresh_token) {
      await secureStorage.setItem(STORAGE_KEYS.refreshToken, tokens.refresh_token);
    }
    session.setAccessToken(tokens.access_token); // access_token solo en memoria
  },

  async logout() {
    const stored = await secureStorage.getItem(STORAGE_KEYS.refreshToken);
    await fetch(`${API_URL}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stored ? { refresh_token: stored } : {}),
      credentials: 'include',
    }).catch(() => undefined);
    await secureStorage.deleteItem(STORAGE_KEYS.refreshToken);
    session.signOut();
  },

  // ---------- Utilidades para la sustentación ----------

  /** Reemplaza el access_token en memoria por uno inválido para forzar 401. */
  expireAccessToken() {
    session.setAccessToken('token.expirado.demo');
  },

  /** Revoca el refresh_token en el servidor sin borrarlo localmente: el próximo refresh fallará. */
  async revokeOnServer() {
    const stored = await secureStorage.getItem(STORAGE_KEYS.refreshToken);
    await fetch(`${API_URL}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stored ? { refresh_token: stored } : {}),
      credentials: 'include',
    });
  },
};
