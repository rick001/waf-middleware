import { describe, it } from 'node:test';
import assert from 'node:assert';
import { decodeHtmlEntitiesBounded, decodeQueryValues } from '../utils';
import { looksLikeSqlInjection } from '../rules/sql-injection';

describe('decodeHtmlEntitiesBounded', () => {
  it('decodes named entities', () => {
    assert.strictEqual(decodeHtmlEntitiesBounded('&lt;script&gt;', 2, 256), '<script>');
  });

  it('decodes numeric entities', () => {
    assert.strictEqual(decodeHtmlEntitiesBounded('&#39;OR&#39;1&#39;=&#39;1', 2, 256), "'OR'1'='1");
  });

  it('handles double-encoded amp entities', () => {
    assert.strictEqual(decodeHtmlEntitiesBounded('&amp;lt;', 3, 256), '<');
  });
});

describe('decodeQueryValues with htmlEntities', () => {
  it('allows SQLi heuristic to see decoded payload after URL + entity decode', () => {
    const q = { q: 'UNION%20SELECT' };
    const decoded = decodeQueryValues(q, { maxUrlRounds: 2, htmlEntities: true });
    assert.strictEqual(decoded.q, 'UNION SELECT');
    assert.strictEqual(looksLikeSqlInjection(decoded.q, 'balanced'), true);
  });

  it('decodes entity-heavy query value', () => {
    const q = { x: '&#85;&#78;&#73;&#79;&#78;' }; // UNION
    const out = decodeQueryValues(q, { maxUrlRounds: 2, htmlEntities: true });
    assert.strictEqual(out.x, 'UNION');
  });
});
