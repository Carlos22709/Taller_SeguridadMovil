/// <reference types="node" />
import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { ApiClient, type ClientEvent } from '../client';
import { SessionExpiredError } from '../errors';

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Servidor falso: acepta solo el token "nuevo". */
function mockServer(validToken: string) {
  const calls: string[] = [];
  globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    const auth = new Headers(init?.headers).get('Authorization');
    calls.push(auth ?? 'none');
    await new Promise((r) => setTimeout(r, 5));
    if (auth === `Bearer ${validToken}`) return new Response(JSON.stringify({ ok: true }), { status: 200 });
    return new Response(JSON.stringify({ error: 'token_expired', message: 'vencido' }), { status: 401 });
  }) as typeof fetch;
  return calls;
}

describe('Silent Refresh Queue', () => {
  it('3 peticiones concurrentes con 401 disparan UN solo refresh y todas se reintentan', async () => {
    let token = 'viejo';
    let refreshCalls = 0;
    mockServer('nuevo');
    const client = new ApiClient({
      baseUrl: 'http://api',
      getAccessToken: () => token,
      refreshAccessToken: async () => {
        refreshCalls++;
        await new Promise((r) => setTimeout(r, 20));
        token = 'nuevo';
        return token;
      },
      onSessionExpired: () => assert.fail('no debe cerrar sesión'),
    });
    const events: ClientEvent[] = [];
    client.onEvent((e) => events.push(e));

    const results = await Promise.all([client.get('/a'), client.get('/b'), client.get('/c')]);

    assert.equal(refreshCalls, 1);
    assert.deepEqual(results, [{ ok: true }, { ok: true }, { ok: true }]);
    assert.ok(events.some((e) => e.type === 'queued'));
  });

  it('las peticiones que llegan durante el refresh esperan y salen ya con el token nuevo', async () => {
    let token = 'viejo';
    const calls = mockServer('nuevo');
    const client = new ApiClient({
      baseUrl: 'http://api',
      getAccessToken: () => token,
      refreshAccessToken: async () => {
        await new Promise((r) => setTimeout(r, 30));
        token = 'nuevo';
        return token;
      },
      onSessionExpired: () => undefined,
    });
    const first = client.get('/a');
    await new Promise((r) => setTimeout(r, 10)); // ya está renovando
    const late = client.get('/late');
    await Promise.all([first, late]);
    // /a viejo, /a nuevo, /late nuevo (la tardía nunca salió con el token viejo)
    assert.deepEqual(calls, ['Bearer viejo', 'Bearer nuevo', 'Bearer nuevo']);
  });

  it('si el refresh falla, rechaza toda la cola y cierra sesión una vez', async () => {
    mockServer('nunca');
    let expired = 0;
    const client = new ApiClient({
      baseUrl: 'http://api',
      getAccessToken: () => 'viejo',
      refreshAccessToken: async () => {
        throw new Error('refresh revocado');
      },
      onSessionExpired: () => expired++,
    });
    const results = await Promise.allSettled([client.get('/a'), client.get('/b')]);
    assert.ok(results.every((r) => r.status === 'rejected' && r.reason instanceof SessionExpiredError));
    assert.equal(expired, 1);
  });

  it('un 401 con token explícito (elevated) no dispara refresh', async () => {
    mockServer('nunca');
    let refreshCalls = 0;
    const client = new ApiClient({
      baseUrl: 'http://api',
      getAccessToken: () => 'x',
      refreshAccessToken: async () => {
        refreshCalls++;
        return 'y';
      },
      onSessionExpired: () => undefined,
    });
    await assert.rejects(client.get('/boveda', { token: 'elevado-vencido' }));
    assert.equal(refreshCalls, 0);
  });
});
