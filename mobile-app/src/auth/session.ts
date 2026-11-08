/**
 * Tokens de vida corta en MEMORIA VOLÁTIL (nunca en disco).
 * Al matar el proceso / cerrar la pestaña, desaparecen.
 *
 * Es un pequeño store externo (useSyncExternalStore) para que el cliente HTTP y React
 * lean la misma fuente de verdad.
 */
export type SessionStatus = 'loading' | 'signedOut' | 'signedIn';

export interface SessionState {
  status: SessionStatus;
  accessToken: string | null;
  elevatedToken: string | null;
  elevatedExpiresAt: number | null; // epoch ms
  signOutReason: string | null;
}

let state: SessionState = {
  status: 'loading',
  accessToken: null,
  elevatedToken: null,
  elevatedExpiresAt: null,
  signOutReason: null,
};

const listeners = new Set<() => void>();

function emit(next: Partial<SessionState>) {
  state = { ...state, ...next };
  listeners.forEach((listener) => listener());
}

export const session = {
  getState: () => state,
  subscribe(listener: () => void) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  getAccessToken: () => state.accessToken,
  setAccessToken(accessToken: string) {
    emit({ accessToken, status: 'signedIn', signOutReason: null });
  },
  getElevatedToken() {
    if (state.elevatedToken && state.elevatedExpiresAt && state.elevatedExpiresAt > Date.now()) {
      return state.elevatedToken;
    }
    return null;
  },
  setElevatedToken(token: string, expiresInSeconds: number) {
    emit({ elevatedToken: token, elevatedExpiresAt: Date.now() + expiresInSeconds * 1000 });
  },
  clearElevated() {
    emit({ elevatedToken: null, elevatedExpiresAt: null });
  },
  signOut(reason: string | null = null) {
    emit({ status: 'signedOut', accessToken: null, elevatedToken: null, elevatedExpiresAt: null, signOutReason: reason });
  },
};
