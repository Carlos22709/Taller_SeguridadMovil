import type { TotpAccount } from '../crypto/otpauth';
import { STORAGE_KEYS, secureStorage } from '../storage/secureStorage';

/** La semilla TOTP es un secreto: también va al almacenamiento seguro (Keychain/Keystore). */
export const totpAccountStore = {
  async load(): Promise<TotpAccount | null> {
    const raw = await secureStorage.getItem(STORAGE_KEYS.totpAccount);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as TotpAccount;
    } catch {
      return null;
    }
  },
  save: (account: TotpAccount) => secureStorage.setItem(STORAGE_KEYS.totpAccount, JSON.stringify(account)),
  clear: () => secureStorage.deleteItem(STORAGE_KEYS.totpAccount),
};
