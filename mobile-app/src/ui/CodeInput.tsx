import { useRef, type ComponentRef } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';

import { colors, fonts, radius } from './theme';

const LENGTH = 6;

/** 6 casillas sobre un TextInput oculto con teclado numérico (y autocompletado de OTP del sistema). */
export function CodeInput({
  value,
  onChange,
  onComplete,
  disabled,
}: {
  value: string;
  onChange: (value: string) => void;
  onComplete?: (value: string) => void;
  disabled?: boolean;
}) {
  const inputRef = useRef<ComponentRef<typeof TextInput>>(null);

  const handleChange = (text: string) => {
    const digits = text.replace(/\D/g, '').slice(0, LENGTH);
    onChange(digits);
    if (digits.length === LENGTH) onComplete?.(digits);
  };

  return (
    <Pressable onPress={() => inputRef.current?.focus()} accessibilityLabel="Código de 6 dígitos">
      <View style={styles.row}>
        {Array.from({ length: LENGTH }, (_, i) => {
          const active = i === value.length && !disabled;
          return (
            <View key={i} style={[styles.box, active && styles.boxActive, value[i] !== undefined && styles.boxFilled]}>
              <Text style={styles.digit}>{value[i] ?? ''}</Text>
            </View>
          );
        })}
      </View>
      <TextInput
        ref={inputRef}
        value={value}
        onChangeText={handleChange}
        keyboardType="number-pad"
        inputMode="numeric"
        textContentType="oneTimeCode"
        autoComplete="one-time-code"
        maxLength={LENGTH}
        autoFocus
        editable={!disabled}
        caretHidden
        style={styles.hidden}
      />
    </Pressable>
  );
}

const styles = StyleSheet.create({
  row: { flexDirection: 'row', justifyContent: 'space-between', gap: 8 },
  box: {
    flex: 1,
    aspectRatio: 0.85,
    maxWidth: 56,
    borderRadius: radius.md,
    borderWidth: 1.5,
    borderColor: colors.line,
    backgroundColor: colors.surfaceAlt,
    alignItems: 'center',
    justifyContent: 'center',
  },
  boxActive: { borderColor: colors.accent, backgroundColor: colors.surface },
  boxFilled: { backgroundColor: colors.surface },
  digit: { fontFamily: fonts.mono, fontSize: 26, fontWeight: '700', color: colors.ink },
  hidden: { position: 'absolute', opacity: 0, width: 1, height: 1 },
});
