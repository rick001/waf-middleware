import { describe, it } from 'node:test';
import assert from 'node:assert';
import { looksLikePathTraversal } from '../path-traversal';
import { looksLikeCommandInjection, checkCommandInjectionQuery } from '../command-injection';

describe('looksLikePathTraversal', () => {
  it('flags obvious traversal segments', () => {
    assert.strictEqual(looksLikePathTraversal('/static/../../../etc/passwd'), true);
    assert.strictEqual(looksLikePathTraversal('/x%2e%2e%2f'), true);
  });

  it('allows normal paths', () => {
    assert.strictEqual(looksLikePathTraversal('/api/users/1'), false);
    assert.strictEqual(looksLikePathTraversal('/v1.0/health'), false);
  });
});

describe('command injection heuristics', () => {
  it('flags shell-like patterns', () => {
    assert.strictEqual(looksLikeCommandInjection('; rm -rf /', 500), true);
    assert.strictEqual(looksLikeCommandInjection('`id`', 500), true);
  });

  it('allows normal text', () => {
    assert.strictEqual(looksLikeCommandInjection('hello world', 500), false);
  });

  it('checkCommandInjectionQuery', () => {
    assert.strictEqual(checkCommandInjectionQuery({ q: 'search' }, 500), false);
    assert.strictEqual(checkCommandInjectionQuery({ x: '; curl evil' }, 500), true);
  });
});
