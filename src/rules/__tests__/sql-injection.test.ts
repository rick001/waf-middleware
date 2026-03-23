import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  looksLikeSqlInjection,
  hasEmailInjectionFragment,
  checkBody,
  checkQueryParams,
} from '../sql-injection';

describe('looksLikeSqlInjection', () => {
  it('allows normal words that are SQL keywords (no false positives)', () => {
    assert.strictEqual(looksLikeSqlInjection('and', 'balanced'), false);
    assert.strictEqual(looksLikeSqlInjection('or', 'balanced'), false);
    assert.strictEqual(looksLikeSqlInjection('select', 'balanced'), false);
    assert.strictEqual(looksLikeSqlInjection('order', 'balanced'), false);
    assert.strictEqual(looksLikeSqlInjection('My name is Andrew', 'balanced'), false);
  });

  it('blocks high-confidence SQL injection patterns', () => {
    assert.strictEqual(looksLikeSqlInjection("' OR 1=1 --", 'lenient'), true);
    assert.strictEqual(looksLikeSqlInjection('UNION SELECT * FROM users', 'lenient'), true);
    assert.strictEqual(looksLikeSqlInjection('; DROP TABLE users;', 'lenient'), true);
    assert.strictEqual(looksLikeSqlInjection("1' OR '1'='1", 'lenient'), true);
    assert.strictEqual(looksLikeSqlInjection('\\x53\\x45\\x4C\\x45\\x43\\x54', 'lenient'), true);
  });

  it('allows empty and very long input', () => {
    assert.strictEqual(looksLikeSqlInjection('', 'strict'), false);
    assert.strictEqual(looksLikeSqlInjection('x'.repeat(10001), 'strict'), false);
  });
});

describe('hasEmailInjectionFragment', () => {
  it('allows valid and invalid email formats (WAF does not validate email format)', () => {
    assert.strictEqual(hasEmailInjectionFragment('user@example.com'), false);
    assert.strictEqual(hasEmailInjectionFragment('invalid-email'), false);
    assert.strictEqual(hasEmailInjectionFragment('user+tag@domain.co.uk'), false);
  });

  it('blocks only obvious injection in email-like value', () => {
    assert.strictEqual(hasEmailInjectionFragment("user@example.com' OR '1'='1"), true);
    assert.strictEqual(hasEmailInjectionFragment("' OR 1=1 --"), true);
  });
});

describe('checkBody', () => {
  it('skips password-like keys (no blocking on SQL keywords in password)', () => {
    const result = checkBody(
      { password: "MyP@ssw0rd_SELECT_AND_OR", email: 'u@e.com' },
      { sensitivity: 'balanced', skipBodyKeys: ['password', 'email'] }
    );
    assert.strictEqual(result.block, false);
  });

  it('allows special characters in password when key is in skipBodyKeys', () => {
    const result = checkBody(
      { password: "P@$$w0rd!#';--" },
      { sensitivity: 'strict', skipBodyKeys: ['password'] }
    );
    assert.strictEqual(result.block, false);
  });

  it('blocks injection in non-password body fields', () => {
    const result = checkBody(
      { username: "' OR 1=1 --" },
      { sensitivity: 'balanced', skipBodyKeys: ['password'] }
    );
    assert.strictEqual(result.block, true);
  });
});

describe('checkQueryParams', () => {
  it('allows normal query values', () => {
    assert.strictEqual(checkQueryParams({ q: 'searchterm' }, 'balanced'), false);
    assert.strictEqual(checkQueryParams({ search: 'and or select' }, 'balanced'), false);
  });

  it('blocks injection in query', () => {
    assert.strictEqual(checkQueryParams({ id: "1; DROP TABLE x--" }, 'balanced'), true);
    assert.strictEqual(checkQueryParams({ order_field: "name'; DELETE FROM users--" }, 'balanced'), true);
  });
});
