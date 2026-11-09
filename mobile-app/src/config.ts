import Constants from 'expo-constants';

const BACKEND_PORT = 8000;

function resolveApiUrl(): string {
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
