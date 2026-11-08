import { Platform } from 'react-native';

export const colors = {
  bg: '#F3F5FA',
  surface: '#FFFFFF',
  surfaceAlt: '#EEF2F9',
  ink: '#0F1B33',
  muted: '#5B6884',
  line: '#DCE2EE',
  brand: '#0B3A73',
  brandSoft: '#E3ECF8',
  accent: '#1D6FE8',
  success: '#127A4B',
  successSoft: '#E2F4EA',
  warning: '#A15C00',
  warningSoft: '#FFF2DC',
  danger: '#B42318',
  dangerSoft: '#FDE8E6',
  onBrand: '#FFFFFF',
} as const;

export const space = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32 } as const;
export const radius = { sm: 8, md: 12, lg: 16, pill: 999 } as const;

export const fonts = {
  mono: Platform.select({
    ios: 'Menlo',
    android: 'monospace',
    default: 'ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace',
  }),
};

export const shadow = Platform.select({
  web: { boxShadow: '0 1px 2px rgba(15,27,51,.06), 0 6px 20px rgba(15,27,51,.06)' },
  default: { shadowColor: '#0F1B33', shadowOpacity: 0.08, shadowRadius: 12, shadowOffset: { width: 0, height: 4 }, elevation: 2 },
});
