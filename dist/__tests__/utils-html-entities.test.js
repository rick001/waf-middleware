"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const utils_1 = require("../utils");
const sql_injection_1 = require("../rules/sql-injection");
(0, node_test_1.describe)('decodeHtmlEntitiesBounded', () => {
    (0, node_test_1.it)('decodes named entities', () => {
        node_assert_1.default.strictEqual((0, utils_1.decodeHtmlEntitiesBounded)('&lt;script&gt;', 2, 256), '<script>');
    });
    (0, node_test_1.it)('decodes numeric entities', () => {
        node_assert_1.default.strictEqual((0, utils_1.decodeHtmlEntitiesBounded)('&#39;OR&#39;1&#39;=&#39;1', 2, 256), "'OR'1'='1");
    });
    (0, node_test_1.it)('handles double-encoded amp entities', () => {
        node_assert_1.default.strictEqual((0, utils_1.decodeHtmlEntitiesBounded)('&amp;lt;', 3, 256), '<');
    });
});
(0, node_test_1.describe)('decodeQueryValues with htmlEntities', () => {
    (0, node_test_1.it)('allows SQLi heuristic to see decoded payload after URL + entity decode', () => {
        const q = { q: 'UNION%20SELECT' };
        const decoded = (0, utils_1.decodeQueryValues)(q, { maxUrlRounds: 2, htmlEntities: true });
        node_assert_1.default.strictEqual(decoded.q, 'UNION SELECT');
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)(decoded.q, 'balanced'), true);
    });
    (0, node_test_1.it)('decodes entity-heavy query value', () => {
        const q = { x: '&#85;&#78;&#73;&#79;&#78;' }; // UNION
        const out = (0, utils_1.decodeQueryValues)(q, { maxUrlRounds: 2, htmlEntities: true });
        node_assert_1.default.strictEqual(out.x, 'UNION');
    });
});
//# sourceMappingURL=utils-html-entities.test.js.map