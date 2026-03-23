import { describe, it } from 'node:test';
import assert from 'node:assert';
import express from 'express';
import request from 'supertest';
import { WafMiddleware } from '../waf.middleware';
import type { WafAuditEvent } from '../config';
import { RULESET_VERSION } from '../ruleset-manifest';

describe('audit rulesetVersion', () => {
  it('includes rulesetVersion on block audit', async () => {
    const events: WafAuditEvent[] = [];
    const app = express();
    app.use(
      new WafMiddleware({
        mode: 'block',
        sqlInjection: { enabled: true },
        auditLogger: (e) => events.push(e),
      }).use
    );
    app.get('/x', (_req, res) => {
      res.send('ok');
    });

    await request(app).get('/x').query({ q: 'UNION SELECT 1' });

    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].rulesetVersion, RULESET_VERSION);
    assert.strictEqual(events[0].action, 'block');
  });

  it('respects custom rulesetVersion', async () => {
    const events: WafAuditEvent[] = [];
    const app = express();
    app.use(
      new WafMiddleware({
        mode: 'block',
        sqlInjection: { enabled: true },
        rulesetVersion: 'custom-9',
        auditLogger: (e) => events.push(e),
      }).use
    );
    app.get('/x', (_req, res) => {
      res.send('ok');
    });

    await request(app).get('/x').query({ q: 'UNION SELECT 1' });

    assert.strictEqual(events[0]?.rulesetVersion, 'custom-9');
  });
});
