import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createFastifyWafPreHandler } from '../fastify-waf';

describe('createFastifyWafPreHandler', () => {
  it('blocks SQLi in query and sends 403', async () => {
    const hook = createFastifyWafPreHandler({ sqlInjection: { enabled: true }, mode: 'block' });
    const sent: { code?: number; body?: unknown } = {};
    const req = {
      method: 'GET',
      url: '/api?q=' + encodeURIComponent('UNION SELECT 1'),
      query: { q: 'UNION SELECT 1' },
      headers: {},
    };
    const reply = {
      code(c: number) {
        sent.code = c;
        return this;
      },
      send(b?: unknown) {
        sent.body = b;
      },
    };
    await hook(req, reply);
    assert.strictEqual(sent.code, 403);
  });

  it('allows clean request (no reply body)', async () => {
    const hook = createFastifyWafPreHandler({ sqlInjection: { enabled: true } });
    let sent = false;
    const req = {
      method: 'GET',
      url: '/health',
      query: {},
      headers: {},
    };
    const reply = {
      code() {
        sent = true;
        return this;
      },
      send() {
        sent = true;
      },
    };
    await hook(req, reply);
    assert.strictEqual(sent, false);
  });

  it('strips query string from path for policy matching', async () => {
    const hook = createFastifyWafPreHandler({
      policies: [
        {
          match: { path: '/v1' },
          overrides: { mode: 'monitor', sqlInjection: { enabled: true } },
        },
      ],
    });
    const req = {
      method: 'GET',
      url: '/v1/items?q=' + encodeURIComponent('UNION SELECT 1'),
      query: { q: 'UNION SELECT 1' },
      headers: {},
    };
    let code: number | undefined;
    const reply = {
      code(c: number) {
        code = c;
        return this;
      },
      send() {
        /* monitor: no send */
      },
    };
    await hook(req, reply);
    assert.strictEqual(code, undefined);
  });
});
