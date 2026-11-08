/**
 * Versión web (Metro elige este archivo automáticamente en web).
 *
 * El navegador no tiene Keychain/Keystore. Para no caer en localStorage (legible por cualquier
 * script inyectado), en web:
 *  - el refresh_token NUNCA llega a JavaScript: el backend lo entrega como cookie HttpOnly + SameSite=Strict;
 *  - la semilla TOTP vive solo en memoria de la pestaña (se pierde al recargar, a propósito).
 */
const memory = new Map<string, string>();

export const secureStorage = {
  backend: 'Memoria de la pestaña + cookie HttpOnly (web)',
  getItem: async (key: string) => memory.get(key) ?? null,
  setItem: async (key: string, value: string) => {
    memory.set(key, value);
  },
  deleteItem: async (key: string) => {
    memory.delete(key);
  },
};

export const STORAGE_KEYS = {
  refreshToken: 'unisabana.refresh_token',
  totpAccount: 'unisabana.totp_account',
} as const;
