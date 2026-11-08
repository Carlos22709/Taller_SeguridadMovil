import { useEffect, useState } from 'react';
import { Animated, Easing, StyleSheet, Text, View } from 'react-native';

import { TOTP_PERIOD_SECONDS } from '../crypto/totp';
import { colors, fonts, radius, space } from './theme';

const PERIOD_MS = TOTP_PERIOD_SECONDS * 1000;

/** Código grande monoespaciado + barra regresiva continua de 30 s → 0 s. */
export function TotpDisplay({ code, counter, secondsLeft }: { code: string | null; counter: number; secondsLeft: number }) {
  const [progress] = useState(() => new Animated.Value(1));

  useEffect(() => {
    // Al iniciar cada ventana T se reinicia la barra y se anima linealmente hasta 0.
    const remainingMs = Math.max((counter + 1) * PERIOD_MS - Date.now(), 0);
    progress.setValue(remainingMs / PERIOD_MS);
    const animation = Animated.timing(progress, {
      toValue: 0,
      duration: remainingMs,
      easing: Easing.linear,
      useNativeDriver: false,
    });
    animation.start();
    return () => animation.stop();
  }, [counter, progress]);

  const urgent = secondsLeft <= 5;
  const width = progress.interpolate({ inputRange: [0, 1], outputRange: ['0%', '100%'] });
  const formatted = code ? `${code.slice(0, 3)} ${code.slice(3)}` : '••• •••';

  return (
    <View accessible accessibilityLabel={code ? `Código ${code.split('').join(' ')}, expira en ${secondsLeft} segundos` : 'Calculando código'}>
      <Text style={[styles.code, urgent && { color: colors.danger }]} selectable>
        {formatted}
      </Text>
      <View style={styles.track}>
        <Animated.View style={[styles.bar, { width, backgroundColor: urgent ? colors.danger : colors.accent }]} />
      </View>
      <View style={styles.meta}>
        <Text style={styles.metaText}>Nuevo código en</Text>
        <Text style={[styles.seconds, urgent && { color: colors.danger }]}>{secondsLeft}s</Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  code: {
    fontFamily: fonts.mono,
    fontSize: 52,
    fontWeight: '700',
    letterSpacing: 4,
    color: colors.ink,
    textAlign: 'center',
    fontVariant: ['tabular-nums'],
    marginVertical: space.md,
  },
  track: { height: 8, borderRadius: radius.pill, backgroundColor: colors.surfaceAlt, overflow: 'hidden' },
  bar: { height: '100%', borderRadius: radius.pill },
  meta: { flexDirection: 'row', justifyContent: 'space-between', marginTop: space.sm },
  metaText: { color: colors.muted, fontSize: 13 },
  seconds: { fontFamily: fonts.mono, fontSize: 13, fontWeight: '700', color: colors.ink, fontVariant: ['tabular-nums'] },
});
