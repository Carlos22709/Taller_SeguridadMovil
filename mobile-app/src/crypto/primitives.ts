/**
 * Primitivas criptográficas de bajo nivel que los algoritmos necesitan.
 *
 * Los algoritmos (HMAC, TOTP, PKCE) reciben estas primitivas por parámetro: así el
 * mismo código corre en la app (expo-crypto, nativo) y en los tests (WebCrypto de Node).
 */
export interface CryptoPrimitives {
  randomBytes(length: number): Uint8Array;
  sha1(data: Uint8Array): Promise<Uint8Array>;
  sha256(data: Uint8Array): Promise<Uint8Array>;
}
