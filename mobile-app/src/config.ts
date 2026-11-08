import { Platform } from 'react-native';

function resolveApiUrl(): string {
  if (Platform.OS === 'web') {
    // En producción la app web la sirve el mismo backend: mismo origen, sin CORS.
    // En desarrollo (expo start --web en :8081) se define EXPO_PUBLIC_WEB_API_URL en .env.development.
    return process.env.EXPO_PUBLIC_WEB_API_URL || window.location.origin;
  }
  // Teléfono físico: IP LAN del PC (ej. http://192.168.1.20:8000). Emulador Android: 10.0.2.2.
  return process.env.EXPO_PUBLIC_API_URL || 'http://10.0.2.2:8000';
}

export const API_URL = resolveApiUrl().replace(/\/+$/, '');
export const OAUTH_CLIENT_ID = 'unisabana-mobile'; // cliente público: NO existe client_secret en la app
export const APP_SCHEME = 'unisabana-auth';
export const IS_WEB = Platform.OS === 'web';
/** Web: refresh_token en cookie HttpOnly. Nativo: en Keychain/Keystore vía expo-secure-store. */
export const TOKEN_DELIVERY: 'cookie' | 'body' = IS_WEB ? 'cookie' : 'body';
