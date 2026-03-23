import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mergeOptions, mergeResolvedWafOptions } from '../config';

describe('mergeResolvedWafOptions', () => {
  it('merges mode over base', () => {
    const base = mergeOptions({});
    const next = mergeResolvedWafOptions(base, { mode: 'monitor' });
    assert.strictEqual(next.mode, 'monitor');
    assert.strictEqual(base.mode, 'block');
  });

  it('strips policies and policyResolver from merge payload', () => {
    const base = mergeOptions({});
    const next = mergeResolvedWafOptions(base, {
      mode: 'monitor',
      policies: [],
      policyResolver: () => ({}),
    } as import('../config').WafOptions);
    assert.strictEqual(next.mode, 'monitor');
  });
});
