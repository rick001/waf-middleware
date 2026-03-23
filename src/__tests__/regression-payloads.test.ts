/**
 * Curated payloads for regression (not exhaustive fuzzing).
 * Extend as you harden rules; pair changes with CHANGELOG rule semantics.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { looksLikeSqlInjection } from '../rules/sql-injection';
import { looksLikeXss } from '../rules/xss';
import { ruleIdForRuleName, RULE_IDS } from '../rule-ids';

describe('regression payloads — SQLi', () => {
  const cases: { input: string; shouldFlag: boolean; note: string }[] = [
    { input: 'UNION SELECT password FROM users', shouldFlag: true, note: 'classic union' },
    { input: "admin'--", shouldFlag: true, note: 'quote comment' },
    { input: 'search only', shouldFlag: false, note: 'benign text' },
    { input: 'and or select', shouldFlag: false, note: 'keywords in prose (balanced)' },
  ];

  for (const { input, shouldFlag, note } of cases) {
    it(`${note}: ${shouldFlag ? 'flags' : 'allows'}`, () => {
      assert.strictEqual(looksLikeSqlInjection(input, 'balanced'), shouldFlag, input);
    });
  }
});

describe('regression payloads — XSS', () => {
  it('flags script block', () => {
    assert.strictEqual(looksLikeXss('<script>alert(1)</script>'), true);
  });
  it('allows plain text', () => {
    assert.strictEqual(looksLikeXss('Hello <b>world</b>'), false);
  });
});

describe('ruleIdForRuleName', () => {
  it('maps known rules', () => {
    assert.strictEqual(ruleIdForRuleName('sql_injection'), RULE_IDS.sql_injection);
    assert.strictEqual(ruleIdForRuleName('unknown_rule'), 'WAF-UNK-001');
  });
});
