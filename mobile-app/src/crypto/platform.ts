import * as ExpoCrypto from 'expo-crypto';

import type { CryptoPrimitives } from './primitives';

/** Implementación real: usa el hashing nativo del sistema (CommonCrypto / java.security / WebCrypto). */
export const platformCrypto: CryptoPrimitives = {
  randomBytes: (length) => ExpoCrypto.getRandomBytes(length),
  sha1: async (data) =>
    new Uint8Array(await ExpoCrypto.digest(ExpoCrypto.CryptoDigestAlgorithm.SHA1, data as BufferSource)),
  sha256: async (data) =>
    new Uint8Array(await ExpoCrypto.digest(ExpoCrypto.CryptoDigestAlgorithm.SHA256, data as BufferSource)),
};
