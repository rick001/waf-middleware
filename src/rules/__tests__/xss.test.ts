import { describe, it } from 'node:test';
import assert from 'node:assert';
import { looksLikeXss, checkQueryAndBody } from '../xss';

describe('looksLikeXss', () => {
  it('blocks script tags', () => {
    assert.strictEqual(looksLikeXss('<script>alert(1)</script>'), true);
    assert.strictEqual(looksLikeXss('<SCRIPT type="text/javascript">x</SCRIPT>'), true);
  });

  it('blocks javascript: protocol in executable context', () => {
    assert.strictEqual(looksLikeXss('javascript:alert(1)'), true);
  });

  it('does not block bare word "onclick" (no = sign)', () => {
    assert.strictEqual(looksLikeXss('onclick'), false);
  });

  it('allows empty or non-string', () => {
    assert.strictEqual(looksLikeXss(''), false);
  });
});

describe('checkQueryAndBody', () => {
  it('does not block on key names (only values)', () => {
    const query = { onclick: 'doSomething' };
    const body = { onload: 'handler' };
    const block = checkQueryAndBody(query, body, { allowlistedBodyKeys: [] });
    assert.strictEqual(block, false);
  });

  it('blocks when value contains script', () => {
    const body = { comment: '<script>alert(1)</script>' };
    assert.strictEqual(checkQueryAndBody({}, body, { allowlistedBodyKeys: [] }), true);
  });

  it('allows allowlisted body keys (e.g. rich text content)', () => {
    const body = { content: '<p>Hello <script>nope</script> world</p>' };
    const block = checkQueryAndBody({}, body, { allowlistedBodyKeys: ['content'] });
    assert.strictEqual(block, false);
  });
});
