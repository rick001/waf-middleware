/**
 * Curated encoding / obfuscation cases (OWASP-style evasion patterns).
 * Documents current heuristic behavior; extend when rules improve.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { looksLikeSqlInjection } from '../rules/sql-injection';
import { looksLikeXss } from '../rules/xss';
import { looksLikePathTraversal } from '../rules/path-traversal';
import { decodeUrlBounded, decodeQueryValues, decodeHtmlEntitiesBounded } from '../utils';

describe('evasion corpus — SQLi (balanced)', () => {
  const shouldFlag: { label: string; value: string }[] = [
    { label: 'union select', value: 'UNION SELECT null FROM x' },
    { label: 'mixed case union', value: 'UnIoN SeLeCt password FROM users' },
    { label: 'comment between keywords (slash-star)', value: 'UN/**/ION SEL/**/ECT 1' },
    { label: 'semicolon drop', value: "; DROP TABLE users--" },
    { label: 'hex-like backslash pattern', value: String.raw`\x53\x45\x4C\x45\x43\x54` },
  ];

  for (const { label, value } of shouldFlag) {
    it(`flags: ${label}`, () => {
      assert.strictEqual(
        looksLikeSqlInjection(value, 'balanced'),
        true,
        `expected flag: ${value.slice(0, 80)}`
      );
    });
  }

  const shouldAllow: { label: string; value: string }[] = [
    { label: 'plain product search', value: 'blue running shoes size 10' },
    { label: 'single keyword select', value: 'select' },
    { label: 'and or in sentence', value: 'I want this and that or something else' },
    { label: 'sort asc', value: 'asc' },
    { label: 'email-like without injection', value: 'user.name+tag@example.com' },
  ];

  for (const { label, value } of shouldAllow) {
    it(`allows: ${label}`, () => {
      assert.strictEqual(looksLikeSqlInjection(value, 'balanced'), false, label);
    });
  }
});

describe('evasion corpus — decode pipeline + SQLi', () => {
  it('flags entity-wrapped union after query decode + htmlEntities', () => {
    const q = { s: '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;' };
    const decoded = decodeQueryValues(q, {
      maxUrlRounds: 2,
      htmlEntities: true,
      maxHtmlEntityRounds: 3,
      maxHtmlEntityExpansion: 512,
    });
    assert.strictEqual(decoded.s, 'UNION SELECT');
    assert.strictEqual(looksLikeSqlInjection(decoded.s, 'balanced'), true);
  });

  it('flags percent-encoded union after url decode', () => {
    const q = { q: 'uni%6Fn%20%53%45%4C%45%43%54%201' };
    const decoded = decodeQueryValues(q, { maxUrlRounds: 3, htmlEntities: false });
    assert.strictEqual(looksLikeSqlInjection(decoded.q, 'balanced'), true);
  });

  it('flags double-percent-encoded UNION SELECT after bounded decode', () => {
    const raw =
      '%2555%254E%2549%254F%254E%2520%2553%2545%254C%2545%2543%2554';
    const decoded = decodeUrlBounded(raw, 2);
    assert.strictEqual(decoded, 'UNION SELECT');
    assert.strictEqual(looksLikeSqlInjection(decoded, 'balanced'), true);
  });
});

describe('evasion corpus — XSS', () => {
  const flag: { label: string; v: string }[] = [
    { label: 'lower script', v: '<script>void(0)</script>' },
    { label: 'upper case script open', v: '<SCRIPT>alert(1)</SCRIPT>' },
    { label: 'javascript url', v: 'javascript:alert(1)' },
    { label: 'onerror attr', v: '"><img src=x onerror=alert(1)>' },
  ];
  for (const { label, v } of flag) {
    it(`flags: ${label}`, () => assert.strictEqual(looksLikeXss(v), true));
  }

  it('allows escaped-looking text without executable pattern', () => {
    assert.strictEqual(looksLikeXss('click here for &lt;help&gt;'), false);
  });
});

describe('evasion corpus — path traversal', () => {
  const bad = ['/../../etc/passwd', '/foo/../../../bar', '/static/%2e%2e%2fsecret'];
  for (const p of bad) {
    it(`flags ${p}`, () => assert.strictEqual(looksLikePathTraversal(p), true));
  }
  const ok = ['/api/v1/users', '/static/public/logo.png'];
  for (const p of ok) {
    it(`allows ${p}`, () => assert.strictEqual(looksLikePathTraversal(p), false));
  }

  it('flags literal .. segment (may FP on normalized relative paths)', () => {
    assert.strictEqual(looksLikePathTraversal('/static/../public/logo.png'), true);
  });
});

describe('evasion corpus — HTML entity decode safety', () => {
  it('does not expand unreasonably on repeated amp', () => {
    const huge = '&amp;'.repeat(200);
    const out = decodeHtmlEntitiesBounded(huge, 3, 64);
    assert.ok(out.length < huge.length + 128);
  });
});
