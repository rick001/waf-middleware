import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mergeOptions, resolvePolicyForRequest } from '../config';

describe('resolvePolicyForRequest', () => {
  const globalResolved = mergeOptions({});

  it('returns global options when no policies match', () => {
    const policies = [{ match: { path: '/webhooks' }, overrides: { pathAllowlist: ['/webhooks'] } }];
    const resolved = resolvePolicyForRequest(
      { method: 'GET', path: '/api/users' },
      globalResolved,
      policies
    );
    assert.strictEqual(resolved.pathAllowlist, globalResolved.pathAllowlist);
  });

  it('merges first matching policy over global (path prefix)', () => {
    const policies = [{ match: { path: '/webhooks' }, overrides: { pathAllowlist: ['/webhooks'] } }];
    const resolved = resolvePolicyForRequest(
      { method: 'POST', path: '/webhooks/stripe' },
      globalResolved,
      policies
    );
    assert.deepStrictEqual(resolved.pathAllowlist, ['/webhooks']);
  });

  it('matches by method when specified', () => {
    const policies = [
      { match: { path: '/api', method: 'POST' }, overrides: { blockMessage: 'Custom' } },
    ];
    const resolvedPost = resolvePolicyForRequest(
      { method: 'POST', path: '/api' },
      globalResolved,
      policies
    );
    const resolvedGet = resolvePolicyForRequest(
      { method: 'GET', path: '/api' },
      globalResolved,
      policies
    );
    assert.strictEqual(resolvedPost.blockMessage, 'Custom');
    assert.strictEqual(resolvedGet.blockMessage, globalResolved.blockMessage);
  });

  it('returns global when policies array is empty', () => {
    const resolved = resolvePolicyForRequest(
      { method: 'GET', path: '/any' },
      globalResolved,
      []
    );
    assert.strictEqual(resolved, globalResolved);
  });
});
