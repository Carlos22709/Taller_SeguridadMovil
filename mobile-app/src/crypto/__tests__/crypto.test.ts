/// <reference types="node" />
/**
 * Pruebas de la criptografía propia contra los vectores oficiales de los RFC.
 * Ejecutar: npm test   (usa node:test + WebCrypto de Node como primitivas)
 */
import assert from 'node:assert/strict';
import { createHmac, randomBytes, webcrypto } from 'node:crypto';
import { describe, it } from 'node:test';

import { base32Decode, validateBase32 } from '../base32';
import { asciiToBytes, base64UrlEncode, bytesToHex } from '../encoding';
import { hmac } from '../hmac';
import { parseTotpInput } from '../otpauth';
import { codeChallengeS256, createPkcePair, randomUnreserved, safeEqual } from '../pkce';
import type { CryptoPrimitives } from '../primitives';
import { counterToBytes, hotp, secondsRemaining, timeCounter, totp } from '../totp';

const nodeCrypto: CryptoPrimitives = {
  randomBytes: (n) => new Uint8Array(randomBytes(n)),
  sha1: async (d) => new Uint8Array(await webcrypto.subtle.digest('SHA-1', new Uint8Array(d))),
  sha256: async (d) => new Uint8Array(await webcrypto.subtle.digest('SHA-256', new Uint8Array(d))),
};

const RFC_KEY = asciiToBytes('12345678901234567890');

describe('HMAC-SHA1 hecho a mano', () => {
  it('coincide con RFC 2202 caso 1', async () => {
    const key = new Uint8Array(20).fill(0x0b);
    const mac = await hmac(nodeCrypto.sha1, key, asciiToBytes('Hi There'));
    assert.equal(bytesToHex(mac), 'b617318655057264e28bc0b6fb378c8ef146be00');
  });

  it('coincide con el HMAC nativo de Node para claves largas (> 64 bytes)', async () => {
    const key = new Uint8Array(randomBytes(100));
    const msg = new Uint8Array(randomBytes(37));
    const expected = createHmac('sha1', key).update(msg).digest('hex');
    assert.equal(bytesToHex(await hmac(nodeCrypto.sha1, key, msg)), expected);
  });
});

describe('TOTP RFC 6238 (Apéndice B, SHA-1)', () => {
  const vectors: [number, string][] = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  for (const [seconds, expected] of vectors) {
    it(`T=${seconds}s -> ${expected}`, async () => {
      assert.equal(await totp(nodeCrypto.sha1, RFC_KEY, seconds * 1000, 8), expected);
      assert.equal(await totp(nodeCrypto.sha1, RFC_KEY, seconds * 1000, 6), expected.slice(-6));
    });
  }
});

describe('Paridad con el backend Python', () => {
  const key = base32Decode('JBSWY3DPEHPK3PXP');
  const reference: [number, string][] = [
    [0, '282760'],
    [1, '996554'],
    [56666666, '324550'],
    [2 ** 32 + 5, '255408'], // usa la parte alta del contador de 64 bits
    [2 ** 40 + 123, '130900'],
  ];
  for (const [counter, expected] of reference) {
    it(`HOTP(counter=${counter}) = ${expected}`, async () => {
      assert.equal(await hotp(nodeCrypto.sha1, key, counter), expected);
    });
  }
});

describe('Contador y temporizador', () => {
  it('codifica 64 bits big-endian', () => {
    assert.equal(bytesToHex(counterToBytes(1)), '0000000000000001');
    assert.equal(bytesToHex(counterToBytes(2 ** 32 + 5)), '0000000100000005');
  });
  it('T = floor(unix/30) y segundos restantes', () => {
    assert.equal(timeCounter(59_000), 1);
    assert.equal(secondsRemaining(59_000), 1);
    assert.equal(secondsRemaining(60_000), 30);
  });
});

describe('Base32 y otpauth', () => {
  it('decodifica la semilla RFC', () => {
    assert.deepEqual(base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), RFC_KEY);
    assert.deepEqual(base32Decode('gezd gnbv-gy3t qojq gezd gnbv gy3t qojq'), RFC_KEY);
  });
  it('valida entradas', () => {
    assert.equal(validateBase32('JBSWY3DPEHPK3PXP'), null);
    assert.ok(validateBase32('JBSW1890'));
    assert.ok(validateBase32('ABC'));
  });
  it('interpreta la URI del QR de la guía', () => {
    const r = parseTotpInput(
      'otpauth://totp/UniSabana:estudiante@unisabana.edu.co?secret=JBSWY3DPEHPK3PXP&issuer=UniSabana',
    );
    assert.ok(r.ok);
    if (r.ok) {
      assert.equal(r.value.secret, 'JBSWY3DPEHPK3PXP');
      assert.equal(r.value.issuer, 'UniSabana');
      assert.equal(r.value.account, 'estudiante@unisabana.edu.co');
    }
  });
  it('rechaza HOTP y algoritmos no soportados', () => {
    assert.equal(parseTotpInput('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP').ok, false);
    assert.equal(parseTotpInput('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256').ok, false);
  });
});

describe('PKCE RFC 7636', () => {
  it('reproduce el ejemplo del Apéndice B', async () => {
    const challenge = await codeChallengeS256(nodeCrypto, 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
    assert.equal(challenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
  it('genera verifier válido y state único', async () => {
    const a = await createPkcePair(nodeCrypto);
    const b = await createPkcePair(nodeCrypto);
    assert.match(a.codeVerifier, /^[A-Za-z0-9\-._~]{43,128}$/);
    assert.match(a.codeChallenge, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(a.state, b.state);
    assert.equal(randomUnreserved(nodeCrypto, 128).length, 128);
  });
  it('base64url sin relleno', () => {
    assert.equal(base64UrlEncode(new Uint8Array([0xfb, 0xff])), '-_8');
  });
  it('safeEqual', () => {
    assert.ok(safeEqual('abc', 'abc'));
    assert.ok(!safeEqual('abc', 'abd'));
    assert.ok(!safeEqual('abc', 'ab'));
  });
});
