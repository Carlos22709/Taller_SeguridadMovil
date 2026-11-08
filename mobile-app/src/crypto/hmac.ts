import { concatBytes } from './encoding';

/**
 * HMAC (RFC 2104) construido a mano sobre una función hash:
 *
 *   HMAC(K, m) = H( (K' ⊕ opad) || H( (K' ⊕ ipad) || m ) )
 *
 * expo-crypto solo expone digest (SHA-1/SHA-256), no HMAC; por eso se arma aquí.
 */
const BLOCK_SIZE = 64; // bytes, para SHA-1 y SHA-256
const IPAD = 0x36;
const OPAD = 0x5c;

export type HashFn = (data: Uint8Array) => Promise<Uint8Array>;

export async function hmac(hash: HashFn, key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  // 1) Claves más largas que el bloque se reducen con el hash; las cortas se rellenan con ceros.
  const shortKey = key.length > BLOCK_SIZE ? await hash(key) : key;
  const paddedKey = new Uint8Array(BLOCK_SIZE);
  paddedKey.set(shortKey);

  const innerKey = new Uint8Array(BLOCK_SIZE);
  const outerKey = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    innerKey[i] = paddedKey[i] ^ IPAD;
    outerKey[i] = paddedKey[i] ^ OPAD;
  }

  // 2) Hash interno y externo
  const inner = await hash(concatBytes(innerKey, message));
  return hash(concatBytes(outerKey, inner));
}
