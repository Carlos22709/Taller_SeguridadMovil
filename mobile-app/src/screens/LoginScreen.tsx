import { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { authService } from '../auth/authService';
import { OAuthError, prepareAuthorization, type PendingAuthorization } from '../auth/oauth';
import { useSession } from '../auth/useSession';
import { API_URL } from '../config';
import { Badge, Banner, Button, Card, CardTitle, Gap, Row, Screen } from '../ui/components';
import { colors, fonts, space } from '../ui/theme';

export function LoginScreen({ onOpenAuthenticator }: { onOpenAuthenticator: () => void }) {
  const { signOutReason } = useSession();
  const [pending, setPending] = useState<PendingAuthorization | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [attempt, setAttempt] = useState(0);

  // PKCE + state se generan antes del toque para mostrarlos en pantalla; cada intento usa un par nuevo.
  useEffect(() => {
    let alive = true;
    void prepareAuthorization().then((next) => {
      if (alive) setPending(next);
    });
    return () => {
      alive = false;
    };
  }, [attempt]);

  const login = () => {
    if (!pending) return;
    setError(null);
    setLoading(true);
    setPending(null); // un verifier/state nunca se reutiliza
    authService
      .login(pending)
      .catch((e: unknown) => {
        if (e instanceof OAuthError && e.kind === 'cancelled') return;
        setError(e instanceof Error ? e.message : 'No se pudo iniciar sesión.');
      })
      .finally(() => {
        setLoading(false);
        setAttempt((n) => n + 1); // cada intento usa verifier y state nuevos
      });
  };

  return (
    <Screen title="UniSabana Seguro" subtitle="OAuth 2.0 + PKCE · Almacenamiento seguro · Step-Up 2FA">
      {signOutReason ? <Banner message={signOutReason} tone="warning" /> : null}
      {error ? <Banner message={error} /> : null}

      <Card>
        <CardTitle hint="Se abre el navegador del sistema (no una WebView). Tus credenciales nunca pasan por la app.">
          Iniciar sesión
        </CardTitle>
        <Button label="Iniciar sesión con UniSabana" onPress={login} loading={loading} disabled={!pending} />
      </Card>

      <Card>
        <CardTitle hint="Generado localmente para esta solicitud (RFC 7636).">Parámetros PKCE</CardTitle>
        {pending ? (
          <View>
            <Row label="code_challenge_method" value="S256" />
            <Row label="redirect_uri" value={pending.redirectUri} />
            <Text style={styles.label}>code_verifier ({pending.codeVerifier.length} chars, solo en memoria)</Text>
            <Text style={styles.mono}>{`${pending.codeVerifier.slice(0, 12)}…${pending.codeVerifier.slice(-6)}`}</Text>
            <Text style={styles.label}>code_challenge = BASE64URL(SHA256(verifier))</Text>
            <Text style={styles.mono}>{pending.codeChallenge}</Text>
            <Text style={styles.label}>state (anti-CSRF)</Text>
            <Text style={styles.mono}>{pending.state}</Text>
          </View>
        ) : (
          <Text style={styles.label}>Generando…</Text>
        )}
      </Card>

      <Card>
        <CardTitle hint="Funciona sin sesión y sin internet (Modo Avión).">Authenticator</CardTitle>
        <Button label="Abrir Authenticator offline" variant="secondary" onPress={onOpenAuthenticator} />
      </Card>

      <Gap size={space.sm} />
      <Badge label={`Servidor: ${API_URL}`} />
    </Screen>
  );
}

const styles = StyleSheet.create({
  label: { color: colors.muted, fontSize: 12, marginTop: space.md },
  mono: { fontFamily: fonts.mono, fontSize: 13, color: colors.ink, marginTop: 2 },
});
