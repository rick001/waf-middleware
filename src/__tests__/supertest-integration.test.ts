import { describe, it } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import { WafMiddleware } from '../waf.middleware';

describe('WafMiddleware (supertest)', () => {
  it('returns 403 for SQLi in query', async () => {
    const app = express();
    app.use(new WafMiddleware({ sqlInjection: { enabled: true } }).use);
    app.get('/api', (_req, res) => {
      res.json({ ok: true });
    });

    const res = await request(app).get('/api').query({ q: 'UNION SELECT * FROM t' });
    assert.strictEqual(res.status, 403);
  });

  it('returns 200 for clean query', async () => {
    const app = express();
    app.use(new WafMiddleware({ sqlInjection: { enabled: true } }).use);
    app.get('/api', (_req, res) => {
      res.json({ ok: true });
    });

    const res = await request(app).get('/api').query({ q: 'hello' });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.ok, true);
  });
});
