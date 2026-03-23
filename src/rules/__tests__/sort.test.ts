import { describe, it } from 'node:test';
import assert from 'node:assert';
import { checkSortValidation } from '../sort';

const defaultOpts = {
  sortParamNames: ['sort', 'order', 'dir'],
  orderFieldParamNames: ['order_field', 'orderby', 'field'],
  fieldNamePattern: /^[a-zA-Z0-9_.-]+$/,
};

describe('checkSortValidation', () => {
  it('allows valid sort values (ASC, DESC)', () => {
    assert.strictEqual(checkSortValidation({ sort: 'ASC' }, defaultOpts).block, false);
    assert.strictEqual(checkSortValidation({ sort: 'desc' }, defaultOpts).block, false);
    assert.strictEqual(checkSortValidation({ order: 'ASC' }, defaultOpts).block, false);
  });

  it('blocks invalid sort value', () => {
    const r = checkSortValidation({ sort: "ASC; DROP TABLE x" }, defaultOpts);
    assert.strictEqual(r.block, true);
    assert.strictEqual((r as { reason: string }).reason, 'invalid_sort');
  });

  it('allows field names with dots and hyphens', () => {
    assert.strictEqual(checkSortValidation({ order_field: 'user.name' }, defaultOpts).block, false);
    assert.strictEqual(checkSortValidation({ orderby: 'created-at' }, defaultOpts).block, false);
  });

  it('only validates allowlisted param names (not substring match)', () => {
    assert.strictEqual(checkSortValidation({ disorder: 'yes' }, defaultOpts).block, false);
    assert.strictEqual(checkSortValidation({ reorder: 'ASC' }, defaultOpts).block, false);
  });

  it('blocks invalid characters in order field', () => {
    const r = checkSortValidation({ order_field: "name'; DELETE FROM users--" }, defaultOpts);
    assert.strictEqual(r.block, true);
    assert.strictEqual((r as { reason: string }).reason, 'invalid_order_field');
  });
});
