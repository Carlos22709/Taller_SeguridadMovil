import { useEffect, useRef, useState } from 'react';
import { Text, View } from 'react-native';

import type { ClientEvent } from '../api/client';
import { describeError } from '../api/errors';
import { api, authService } from '../auth/authService';
import { useSession } from '../auth/useSession';
import { secureStorage } from '../storage/secureStorage';
import { Banner, Button, Card, CardTitle, Row, Screen } from '../ui/components';
import { EventLog, type LogLine } from '../ui/EventLog';
import { colors } from '../ui/theme';

interface Perfil {
  id: string;
  email: string;
  name: string;
  mfa_verified: boolean;
  token_expires_at: number;
}

function describeEvent(e: ClientEvent): Omit<LogLine, 'id'> {
  switch (e.type) {
    case 'request':
      return {
        text: `${e.retry ? '↻ reintento ' : ''}${e.method} ${e.path} → ${e.status}`,
        tone: e.status === 401 ? 'warn' : e.status < 400 ? 'ok' : 'error',
      };
    case 'queued':
      return { text: `⏸ ${e.path} encolada (cola: ${e.queueSize})`, tone: 'info' };
    case 'refresh-start':
      return { text: '🔄 POST /auth/refresh (única renovación)', tone: 'info' };
    case 'refresh-success':
      return { text: `✔ access_token renovado · ${e.released} en cola liberadas`, tone: 'ok' };
    case 'refresh-failure':
      return { text: '✖ refresh rechazado → limpiar SecureStore y volver al login', tone: 'error' };
  }
}

export function HomeScreen() {
  const { accessToken } = useSession();
  const [perfil, setPerfil] = useState<Perfil | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  const [summary, setSummary] = useState<string | null>(null);
  const [busy, setBusy] = useState<'refresh' | 'revoke' | null>(null);
  const [perfilVersion, setPerfilVersion] = useState(0);
  const nextId = useRef(0);
  const loadPerfil = () => setPerfilVersion((n) => n + 1);

  useEffect(() => {
    let alive = true;
    api
      .get<Perfil>('/api/perfil')
      .then((data) => {
        if (!alive) return;
        setPerfil(data);
        setError(null);
      })
      .catch((e: unknown) => {
        if (alive) setError(describeError(e));
      });
    return () => {
      alive = false;
    };
  }, [perfilVersion]);

  const record = <T,>(run: () => Promise<T>) => {
    setLog([]);
    const unsubscribe = api.onEvent((event) => {
      setLog((prev) => [...prev, { id: nextId.current++, ...describeEvent(event) }]);
    });
    return run().finally(unsubscribe);
  };

  /** Prueba del Punto 2: token vencido + 3 peticiones simultáneas => un solo refresh. */
  const demoSilentRefresh = async () => {
    setBusy('refresh');
    setSummary(null);
    try {
      const before = await api.get<{ refresh_calls: number }>('/api/demo/stats', { auth: false });
      authService.expireAccessToken();
      await record(() => Promise.all([api.get('/api/perfil'), api.get('/api/perfil'), api.get('/api/perfil')]));
      const after = await api.get<{ refresh_calls: number }>('/api/demo/stats', { auth: false });
      setSummary(`3 peticiones con 401 → ${after.refresh_calls - before.refresh_calls} llamada(s) a /auth/refresh en el servidor.`);
      loadPerfil();
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(null);
    }
  };

  /** Refresh revocado en el servidor: la app debe limpiar y volver al login sola. */
  const demoRevoked = async () => {
    setBusy('revoke');
    try {
      await authService.revokeOnServer();
      authService.expireAccessToken();
      await record(() => api.get('/api/perfil'));
    } catch {
      // Esperado: SessionExpiredError → la app ya navegó al login.
    } finally {
      setBusy(null);
    }
  };

  return (
    <Screen title={perfil ? `Hola, ${perfil.name.split(' ')[0]}` : 'Inicio'} subtitle="Sesión iniciada con OAuth 2.0 + PKCE.">
      {error ? <Banner message={error} /> : null}

      <Card>
        <CardTitle>Tu sesión</CardTitle>
        <Row label="Usuario" value={perfil?.email ?? '…'} />
        <Row label="access_token" value={accessToken ? `en memoria · ${accessToken.length} chars` : '—'} />
        <Row label="refresh_token" value={secureStorage.backend} />
        <Row label="Expira access" value={perfil ? new Date(perfil.token_expires_at * 1000).toLocaleTimeString() : '…'} />
      </Card>

      <Card>
        <CardTitle hint="Invalida el access_token en memoria y lanza 3 peticiones a la vez. El interceptor encola y hace UN solo refresh.">
          Silent Refresh Queue
        </CardTitle>
        <Button label="Expirar token + 3 peticiones simultáneas" onPress={() => void demoSilentRefresh()} loading={busy === 'refresh'} disabled={busy !== null} />
        <Button
          label="Revocar refresh_token y forzar 401"
          variant="secondary"
          onPress={() => void demoRevoked()}
          loading={busy === 'revoke'}
          disabled={busy !== null}
        />
        {summary ? (
          <View style={{ marginTop: 12 }}>
            <Banner message={summary} tone="success" />
          </View>
        ) : null}
        <EventLog lines={log} />
      </Card>

      <Button label="Cerrar sesión" variant="ghost" onPress={() => void authService.logout()} />
      <Text style={{ color: colors.muted, fontSize: 12, textAlign: 'center', marginTop: 8 }}>
        Cerrar sesión revoca el refresh_token en el servidor y lo borra del almacenamiento seguro.
      </Text>
    </Screen>
  );
}
