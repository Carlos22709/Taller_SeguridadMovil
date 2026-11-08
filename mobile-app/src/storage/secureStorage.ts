import * as SecureStore from 'expo-secure-store';

/**
 * Almacenamiento cifrado por hardware:
 *  - iOS: Keychain (kSecClassGenericPassword)
 *  - Android: Keystore (AES con llave no exportable)
 * Nunca AsyncStorage / SharedPreferences en texto plano.
 */
const OPTIONS: SecureStore.SecureStoreOptions = {
  // Solo legible con el dispositivo desbloqueado y no se migra a backups/otros dispositivos.
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export const secureStorage = {
  backend: 'Keychain / Keystore (expo-secure-store)',
  getItem: (key: string) => SecureStore.getItemAsync(key, OPTIONS),
  setItem: (key: string, value: string) => SecureStore.setItemAsync(key, value, OPTIONS),
  deleteItem: (key: string) => SecureStore.deleteItemAsync(key, OPTIONS),
};

export const STORAGE_KEYS = {
  refreshToken: 'unisabana.refresh_token',
  totpAccount: 'unisabana.totp_account',
} as const;
