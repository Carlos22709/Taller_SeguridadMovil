import { StyleSheet, Text, View } from 'react-native';

import { colors, fonts, radius, space } from './theme';

export interface LogLine {
  id: number;
  text: string;
  tone?: 'ok' | 'warn' | 'error' | 'info';
}

const toneColor = { ok: colors.success, warn: colors.warning, error: colors.danger, info: colors.ink } as const;

export function EventLog({ lines }: { lines: LogLine[] }) {
  if (lines.length === 0) return null;
  return (
    <View style={styles.box} accessibilityLabel="Registro de eventos">
      {lines.map((line) => (
        <Text key={line.id} style={[styles.line, { color: toneColor[line.tone ?? 'info'] }]}>
          {line.text}
        </Text>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  box: { backgroundColor: colors.surfaceAlt, borderRadius: radius.md, padding: space.md, marginTop: space.md, gap: 4 },
  line: { fontFamily: fonts.mono, fontSize: 12, lineHeight: 17 },
});
