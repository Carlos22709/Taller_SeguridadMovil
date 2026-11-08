import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { base32Decode } from '../crypto/base32';
import type { TotpAccount } from '../crypto/otpauth';
import { platformCrypto } from '../crypto/platform';
import { secondsRemaining, timeCounter, totp } from '../crypto/totp';
import { totpAccountStore } from './totpAccountStore';

interface TotpContextValue {
  account: TotpAccount | null;
  ready: boolean;
  saveAccount: (account: TotpAccount) => Promise<void>;
  removeAccount: () => Promise<void>;
}

const TotpContext = createContext<TotpContextValue | null>(null);

export function TotpProvider({ children }: { children: ReactNode }) {
  const [account, setAccount] = useState<TotpAccount | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    totpAccountStore
      .load()
      .then(setAccount)
      .finally(() => setReady(true));
  }, []);

  const saveAccount = useCallback(async (next: TotpAccount) => {
    await totpAccountStore.save(next);
    setAccount(next);
  }, []);

  const removeAccount = useCallback(async () => {
    await totpAccountStore.clear();
    setAccount(null);
  }, []);

  const value = useMemo(() => ({ account, ready, saveAccount, removeAccount }), [account, ready, saveAccount, removeAccount]);
  return <TotpContext.Provider value={value}>{children}</TotpContext.Provider>;
}

export function useTotpAccount(): TotpContextValue {
  const ctx = useContext(TotpContext);
  if (!ctx) throw new Error('useTotpAccount debe usarse dentro de <TotpProvider>');
  return ctx;
}

/** Calcula un código puntual (p. ej. para autocompletar el modal 2FA). */
export async function computeCurrentCode(secret: string): Promise<string> {
  return totp(platformCrypto.sha1, base32Decode(secret), Date.now());
}

export interface LiveCode {
  code: string | null;
  secondsLeft: number;
  counter: number;
}

/**
 * Código TOTP en vivo. Solo recalcula cuando cambia la ventana T (cada 30 s); el temporizador
 * se actualiza aparte, así el código nunca parpadea. Cero llamadas de red: funciona en Modo Avión.
 */
export function useLiveTotp(secret: string | null): LiveCode {
  const [now, setNow] = useState(() => Date.now());
  const [computed, setComputed] = useState<{ secret: string; code: string } | null>(null);
  const counter = timeCounter(now);

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!secret) return;
    let cancelled = false;
    const key = base32Decode(secret);
    void totp(platformCrypto.sha1, key, counter * 30_000).then((next) => {
      if (!cancelled) setComputed({ secret, code: next });
    });
    return () => {
      cancelled = true;
    };
  }, [secret, counter]);

  // Reemplazo atómico: se muestra el código anterior hasta que el nuevo esté listo (sin parpadeo).
  const code = secret && computed?.secret === secret ? computed.code : null;
  return { code, secondsLeft: secondsRemaining(now), counter };
}
