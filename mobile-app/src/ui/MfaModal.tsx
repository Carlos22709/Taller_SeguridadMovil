import { useState } from 'react';
import { KeyboardAvoidingView, Modal, Platform, StyleSheet, Text, View } from 'react-native';

import { ApiError, describeError } from '../api/errors';
import { api } from '../auth/authService';
import { computeCurrentCode, useTotpAccount } from '../totp/TotpContext';
import { CodeInput } from './CodeInput';
import { Badge, Banner, Button } from './components';
import { colors, radius, space } from './theme';

export interface MfaSuccess {
  elevatedToken: string;
  expiresIn: number;
  code: string;
}

interface VerifyResponse {
  elevated_token: string;
  expires_in: number;
  mfa_verified: true;
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'invalid_code': {
        const left = error.body.attempts_left;
        return `Código incorrecto.${typeof left === 'number' ? ` Te quedan ${left} intento(s).` : ''}`;
      }
      case 'replay_attack_detected':
        return '409 · Replay Attack Detected: este código ya se usó. Espera el siguiente.';
      case 'too_many_attempts':
        return 'Demasiados intentos fallidos. Cierra y vuelve a abrir la bóveda.';
      case 'invalid_step_up_token':
        return 'La solicitud de verificación expiró. Cierra y vuelve a abrir la bóveda.';
      default:
        return error.message;
    }
  }
  return describeError(error);
}

/**
 * Modal de Step-Up: pide el TOTP y lo canjea (con el step_up_token) por un elevated_token.
 * El padre lo monta con key={stepUpToken} para que cada solicitud empiece con el estado limpio.
 */
export function MfaModal({
  stepUpToken,
  onSuccess,
  onCancel,
}: {
  stepUpToken: string | null;
  onSuccess: (result: MfaSuccess) => void;
  onCancel: () => void;
}) {
  const { account } = useTotpAccount();
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const submit = async (value: string) => {
    if (!stepUpToken || value.length !== 6 || loading) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.post<VerifyResponse>('/auth/mfa/verify', { step_up_token: stepUpToken, code: value }, { auth: false });
      onSuccess({ elevatedToken: res.elevated_token, expiresIn: res.expires_in, code: value });
    } catch (e) {
      setError(messageFor(e));
      setCode('');
    } finally {
      setLoading(false);
    }
  };

  const autofill = async () => {
    if (!account) return;
    const current = await computeCurrentCode(account.secret);
    setCode(current);
    void submit(current);
  };

  return (
    <Modal visible={stepUpToken !== null} transparent animationType="fade" onRequestClose={onCancel}>
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : undefined} style={styles.backdrop}>
        <View style={styles.sheet}>
          <Badge label="403 · mfa_required" tone="warning" />
          <Text style={styles.title}>Verificación en dos pasos</Text>
          <Text style={styles.text}>
            La Bóveda Crítica exige un segundo factor. Ingresa el código de 6 dígitos de tu Authenticator.
          </Text>
          {error ? <Banner message={error} tone={error.startsWith('409') ? 'warning' : 'danger'} /> : null}
          <CodeInput value={code} onChange={setCode} onComplete={(v) => void submit(v)} disabled={loading} />
          <Button label="Verificar" onPress={() => void submit(code)} loading={loading} disabled={code.length !== 6} />
          {account ? (
            <Button label={`Usar código de mi Authenticator (${account.issuer})`} variant="secondary" onPress={() => void autofill()} disabled={loading} />
          ) : null}
          <Button label="Cancelar" variant="ghost" onPress={onCancel} disabled={loading} />
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, backgroundColor: 'rgba(15,27,51,0.55)', justifyContent: 'center', padding: space.lg },
  sheet: { backgroundColor: colors.surface, borderRadius: radius.lg, padding: space.xl, width: '100%', maxWidth: 440, alignSelf: 'center' },
  title: { fontSize: 22, fontWeight: '700', color: colors.ink, marginTop: space.md },
  text: { color: colors.muted, marginTop: space.xs, marginBottom: space.lg, lineHeight: 20 },
});
