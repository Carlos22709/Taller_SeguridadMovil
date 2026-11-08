import { useState } from 'react';
import { Linking, StyleSheet, Text, TextInput, View } from 'react-native';

import { API_URL, IS_WEB } from '../config';
import { bytesToHex } from '../crypto/encoding';
import { parseTotpInput } from '../crypto/otpauth';
import { counterToBytes } from '../crypto/totp';
import { secureStorage } from '../storage/secureStorage';
import { useLiveTotp, useTotpAccount } from '../totp/TotpContext';
import { Badge, Banner, Button, Card, CardTitle, Row, Screen } from '../ui/components';
import { QrScannerModal } from '../ui/QrScannerModal';
import { TotpDisplay } from '../ui/TotpDisplay';
import { colors, fonts, radius, space } from '../ui/theme';

export function AuthenticatorScreen({ onBack }: { onBack?: () => void }) {
  const { account, ready, saveAccount, removeAccount } = useTotpAccount();
  const live = useLiveTotp(account?.secret ?? null);

  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  const enroll = async (raw: string) => {
    const parsed = parseTotpInput(raw);
    if (!parsed.ok) {
      setError(parsed.error);
      return;
    }
    setError(null);
    setInput('');
    await saveAccount(parsed.value);
  };

  return (
    <Screen title="Authenticator" subtitle="TOTP RFC 6238 calculado en el dispositivo: HMAC-SHA1 + truncamiento dinámico.">
      {onBack ? <Button label="← Volver" variant="ghost" onPress={onBack} /> : null}

      {!ready ? null : account ? (
        <>
          <Card>
            <View style={styles.header}>
              <View style={{ flexShrink: 1 }}>
                <Text style={styles.issuer}>{account.issuer}</Text>
                <Text style={styles.account} numberOfLines={1}>
                  {account.account}
                </Text>
              </View>
              <Badge label="Offline · 0 peticiones" tone="success" />
            </View>
            <TotpDisplay code={live.code} counter={live.counter} secondsLeft={live.secondsLeft} />
          </Card>

          <Card>
            <CardTitle hint="Lo que se calcula cada 30 segundos, sin red.">Cómo se obtiene el código</CardTitle>
            <Row label="T = floor(unix / 30)" value={String(live.counter)} />
            <Row label="T (64 bits big-endian)" value={`0x${bytesToHex(counterToBytes(live.counter)).toUpperCase()}`} />
            <Row label="H = HMAC-SHA1(K, T)" value="20 bytes" />
            <Row label="offset = H[19] & 0x0F" value="truncamiento" />
            <Row label="código = bin_code % 10⁶" value={live.code ?? '…'} />
            <Row label="Semilla guardada en" value={secureStorage.backend} />
          </Card>

          <Button label="Eliminar cuenta del Authenticator" variant="danger" onPress={() => void removeAccount()} />
        </>
      ) : (
        <Card>
          <CardTitle hint="Escanea el QR o pega la semilla Base32 / URI otpauth:// (útil en emuladores).">
            Agregar cuenta
          </CardTitle>
          {error ? <Banner message={error} /> : null}
          <TextInput
            value={input}
            onChangeText={(t) => {
              setInput(t);
              if (error) setError(null);
            }}
            placeholder="JBSWY3DPEHPK3PXP  u  otpauth://totp/…"
            placeholderTextColor={colors.muted}
            autoCapitalize="characters"
            autoCorrect={false}
            spellCheck={false}
            style={styles.input}
            accessibilityLabel="Semilla Base32 o URI otpauth"
          />
          <Button label="Guardar semilla" onPress={() => void enroll(input)} disabled={!input.trim()} />
          <Button label="Escanear QR con la cámara" variant="secondary" onPress={() => setScanning(true)} />
          <Button
            label="Ver QR de enrolamiento del servidor"
            variant="ghost"
            onPress={() => void Linking.openURL(`${API_URL}/mfa/qr`)}
          />
          {IS_WEB ? (
            <Text style={styles.note}>En web la semilla vive solo en memoria de la pestaña (no hay Keychain en el navegador).</Text>
          ) : null}
        </Card>
      )}

      <QrScannerModal
        visible={scanning}
        onClose={() => setScanning(false)}
        onScanned={(data) => {
          setScanning(false);
          void enroll(data);
        }}
      />
    </Screen>
  );
}

const styles = StyleSheet.create({
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start', gap: space.md },
  issuer: { fontSize: 18, fontWeight: '700', color: colors.ink },
  account: { fontSize: 14, color: colors.muted, marginTop: 2 },
  input: {
    borderWidth: 1,
    borderColor: colors.line,
    borderRadius: radius.md,
    paddingHorizontal: space.md,
    paddingVertical: space.md,
    fontFamily: fonts.mono,
    fontSize: 15,
    color: colors.ink,
    backgroundColor: colors.surface,
  },
  note: { color: colors.muted, fontSize: 12, marginTop: space.md, lineHeight: 17 },
});
