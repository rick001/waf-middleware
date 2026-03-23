import { describe, it } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import express from 'express';
import { WafMiddleware } from '../waf.middleware';

function httpGet(url: string): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () =>
          resolve({ statusCode: res.statusCode ?? 0, body })
        );
      })
      .on('error', reject);
  });
}

describe('WafMiddleware (integration)', () => {
  it('blocks high-confidence SQLi in query (block mode)', async () => {
    const app = express();
    app.use(new WafMiddleware({ sqlInjection: { enabled: true } }).use);
    app.get('/x', (_req, res) => {
      res.send('ok');
    });

    const server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    try {
      const q = encodeURIComponent('UNION SELECT * FROM users');
      const r = await httpGet(`http://127.0.0.1:${port}/x?q=${q}`);
      assert.strictEqual(r.statusCode, 403);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('monitor mode allows request through', async () => {
    const app = express();
    app.use(new WafMiddleware({ mode: 'monitor', sqlInjection: { enabled: true } }).use);
    app.get('/x', (_req, res) => {
      res.send('ok');
    });

    const server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    try {
      const q = encodeURIComponent('UNION SELECT * FROM users');
      const r = await httpGet(`http://127.0.0.1:${port}/x?q=${q}`);
      assert.strictEqual(r.statusCode, 200);
      assert.strictEqual(r.body, 'ok');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
