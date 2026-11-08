import Constants from 'expo-constants';
import { Platform } from 'react-native';

const BACKEND_PORT = 8000;
const METRO_PORT = '8081';

function resolveApiUrl(): string {
  if (Platform.OS === 'web') {
    if (process.env.EXPO_PUBLIC_WEB_API_URL) return process.env.EXPO_PUBLIC_WEB_API_URL;
    const { protocol, hostname, port, origin } = window.location;
    // `npx expo start --web` (puerto 8081): el backend está en el mismo host, puerto 8000.
    // Si la app la sirve el propio backend (expo export), es el mismo origen.
    return port === METRO_PORT ? `${protocol}//${hostname}:${BACKEND_PORT}` : origin;
  }

  if (process.env.EXPO_PUBLIC_API_URL) return process.env.EXPO_PUBLIC_API_URL;
  // Expo Go / development build: hostUri = "<ip-del-pc>:8081" (el mismo PC que corre `expo start`),
  // así el celular encuentra el backend sin configurar nada.
  const devHost = Constants.expoConfig?.hostUri?.split(':')[0];
  if (devHost) return `http://${devHost}:${BACKEND_PORT}`;
  return `http://10.0.2.2:${BACKEND_PORT}`; // emulador Android sin servidor de Expo
}

export const API_URL = resolveApiUrl().replace(/\/+$/, '');
export const OAUTH_CLIENT_ID = 'unisabana-mobile'; // cliente público: NO existe client_secret en la app
export const APP_SCHEME = 'unisabana-auth';
export const IS_WEB = Platform.OS === 'web';
/** Web: refresh_token en cookie HttpOnly. Nativo: en Keychain/Keystore vía expo-secure-store. */
export const TOKEN_DELIVERY: 'cookie' | 'body' = IS_WEB ? 'cookie' : 'body';
