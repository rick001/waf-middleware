"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const xss_1 = require("../xss");
(0, node_test_1.describe)('looksLikeXss', () => {
    (0, node_test_1.it)('blocks script tags', () => {
        node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)('<script>alert(1)</script>'), true);
        node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)('<SCRIPT type="text/javascript">x</SCRIPT>'), true);
    });
    (0, node_test_1.it)('blocks javascript: protocol in executable context', () => {
        node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)('javascript:alert(1)'), true);
    });
    (0, node_test_1.it)('does not block bare word "onclick" (no = sign)', () => {
        node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)('onclick'), false);
    });
    (0, node_test_1.it)('allows empty or non-string', () => {
        node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)(''), false);
    });
});
(0, node_test_1.describe)('checkQueryAndBody', () => {
    (0, node_test_1.it)('does not block on key names (only values)', () => {
        const query = { onclick: 'doSomething' };
        const body = { onload: 'handler' };
        const block = (0, xss_1.checkQueryAndBody)(query, body, { allowlistedBodyKeys: [] });
        node_assert_1.default.strictEqual(block, false);
    });
    (0, node_test_1.it)('blocks when value contains script', () => {
        const body = { comment: '<script>alert(1)</script>' };
        node_assert_1.default.strictEqual((0, xss_1.checkQueryAndBody)({}, body, { allowlistedBodyKeys: [] }), true);
    });
    (0, node_test_1.it)('allows allowlisted body keys (e.g. rich text content)', () => {
        const body = { content: '<p>Hello <script>nope</script> world</p>' };
        const block = (0, xss_1.checkQueryAndBody)({}, body, { allowlistedBodyKeys: ['content'] });
        node_assert_1.default.strictEqual(block, false);
    });
});
//# sourceMappingURL=xss.test.js.map