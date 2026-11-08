import { useCallback, useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { ApiError, describeError } from '../api/errors';
import { api } from '../auth/authService';
import { session } from '../auth/session';
import { useSession } from '../auth/useSession';
import { Badge, Banner, Button, Card, CardTitle, Screen } from '../ui/components';
import { MfaModal, type MfaSuccess } from '../ui/MfaModal';
import { colors, fonts, radius, space } from '../ui/theme';

interface Vault {
  owner: string;
  elevated_until: number;
  items: { label: string; value: string; detail: string }[];
}

type VaultResult =
  | { kind: 'open'; vault: Vault }
  | { kind: 'mfa_required'; stepUpToken: string }
  | { kind: 'error'; message: string };

/** Pide la bóveda. Si el elevated_token venció (401) lo descarta y reintenta con el access_token normal. */
async function requestVault(): Promise<VaultResult> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const elevated = session.getElevatedToken();
    try {
      return { kind: 'open', vault: await api.get<Vault>('/api/boveda-critica', elevated ? { token: elevated } : {}) };
    } catch (e) {
      if (e instanceof ApiError && e.status === 401 && elevated) {
        session.clearElevated();
        continue;
      }
      if (e instanceof ApiError && e.status === 403 && e.code === 'mfa_required') {
        return { kind: 'mfa_required', stepUpToken: String(e.body.step_up_token) };
      }
      return { kind: 'error', message: describeError(e) };
    }
  }
  return { kind: 'error', message: 'No se pudo abrir la bóveda.' };
}

function useCountdown(targetMs: number | null): string | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!targetMs) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [targetMs]);
  if (!targetMs || targetMs <= now) return null;
  const s = Math.floor((targetMs - now) / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

export function VaultScreen() {
  const { elevatedExpiresAt } = useSession();
  const [loadedVault, setVault] = useState<Vault | null>(null);
  const [stepUpToken, setStepUpToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true); // al entrar a la pantalla ya se está pidiendo la bóveda
  const [lastCode, setLastCode] = useState<string | null>(null);
  const [replay, setReplay] = useState<{ tone: 'success' | 'danger'; text: string } | null>(null);
  const [replayLoading, setReplayLoading] = useState(false);
  const remaining = useCountdown(loadedVault ? elevatedExpiresAt : null);
  // Al vencer la sesión elevada la información sensible deja de mostrarse.
  const vault = remaining ? loadedVault : null;

  const applyResult = useCallback((result: VaultResult) => {
    setLoading(false);
    if (result.kind === 'open') setVault(result.vault);
    else if (result.kind === 'mfa_required') setStepUpToken(result.stepUpToken); // Step-Up: se pide el 2FA
    else setError(result.message);
  }, []);

  // Prueba 4: al abrir la pantalla se intenta leer la bóveda; el 403 abre el modal 2FA automáticamente.
  useEffect(() => {
    let alive = true;
    void requestVault().then((result) => {
      if (alive) applyResult(result);
    });
    return () => {
      alive = false;
    };
  }, [applyResult]);

  const openVault = () => {
    setLoading(true);
    setError(null);
    void requestVault().then(applyResult);
  };

  const onMfaSuccess = ({ elevatedToken, expiresIn, code }: MfaSuccess) => {
    session.setElevatedToken(elevatedToken, expiresIn); // solo en memoria
    setLastCode(code);
    setReplay(null);
    setStepUpToken(null);
    openVault();
  };

  /** Prueba 5: reenviar el MISMO código ya aceptado con un step_up_token nuevo. */
  const replayAttack = async () => {
    if (!lastCode) return;
    setReplayLoading(true);
    setReplay(null);
    try {
      let freshStepUp: string | null = null;
      try {
        await api.get('/api/boveda-critica'); // con el access_token normal => 403 + step_up_token
      } catch (e) {
        if (e instanceof ApiError && e.code === 'mfa_required') freshStepUp = String(e.body.step_up_token);
        else throw e;
      }
      if (!freshStepUp) throw new Error('No se obtuvo step_up_token.');
      await api.post('/auth/mfa/verify', { step_up_token: freshStepUp, code: lastCode }, { auth: false });
      setReplay({ tone: 'danger', text: `⚠ El servidor aceptó de nuevo ${lastCode}. ¡Anti-replay no funcionó!` });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setReplay({ tone: 'success', text: `✔ ${e.status} Conflict · ${e.message}. El código ${lastCode} no se puede reutilizar.` });
      } else {
        setReplay({ tone: 'danger', text: describeError(e) });
      }
    } finally {
      setReplayLoading(false);
    }
  };

  const lock = () => {
    session.clearElevated();
    setVault(null);
  };

  return (
    <Screen title="Bóveda Crítica" subtitle="Recurso protegido con Step-Up Authentication (2FA TOTP).">
      {error ? <Banner message={error} /> : null}

      {vault ? (
        <Card>
          <View style={styles.header}>
            <CardTitle>Datos sensibles</CardTitle>
            <Badge label={`mfa_verified · ${remaining ?? '0:00'}`} tone="success" />
          </View>
          {vault.items.map((item) => (
            <View key={item.label} style={styles.item}>
              <Text style={styles.itemLabel}>{item.label}</Text>
              <Text style={styles.itemValue}>{item.value}</Text>
              <Text style={styles.itemDetail}>{item.detail}</Text>
            </View>
          ))}
          <Button label="Bloquear bóveda" variant="secondary" onPress={lock} />
        </Card>
      ) : (
        <Card>
          <View style={styles.lockIcon}>
            <Text style={{ fontSize: 40 }}>🔒</Text>
          </View>
          <CardTitle hint="Con el access_token normal la API responde 403 mfa_required. Tras validar el TOTP obtienes un elevated_token de 10 minutos.">
            Bóveda bloqueada
          </CardTitle>
          <Button label="Abrir Bóveda Crítica" onPress={openVault} loading={loading} />
        </Card>
      )}

      {lastCode ? (
        <Card>
          <CardTitle hint={`Reenvía el código ${lastCode} recién aceptado. El backend lo tiene en su caché anti-replay (TTL 90 s).`}>
            Prueba anti-replay
          </CardTitle>
          {replay ? <Banner message={replay.text} tone={replay.tone} /> : null}
          <Button label="Reenviar el mismo código" variant="danger" onPress={() => void replayAttack()} loading={replayLoading} />
        </Card>
      ) : null}

      <MfaModal key={stepUpToken ?? 'idle'} stepUpToken={stepUpToken} onSuccess={onMfaSuccess} onCancel={() => setStepUpToken(null)} />
    </Screen>
  );
}

const styles = StyleSheet.create({
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start' },
  item: { backgroundColor: colors.surfaceAlt, borderRadius: radius.md, padding: space.md, marginBottom: space.sm },
  itemLabel: { color: colors.muted, fontSize: 12, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 0.5 },
  itemValue: { color: colors.ink, fontSize: 18, fontWeight: '700', fontFamily: fonts.mono, marginTop: 4 },
  itemDetail: { color: colors.muted, fontSize: 13, marginTop: 2 },
  lockIcon: { alignItems: 'center', marginBottom: space.sm },
});
