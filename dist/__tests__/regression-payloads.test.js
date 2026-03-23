"use strict";
/**
 * Curated payloads for regression (not exhaustive fuzzing).
 * Extend as you harden rules; pair changes with CHANGELOG rule semantics.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const sql_injection_1 = require("../rules/sql-injection");
const xss_1 = require("../rules/xss");
const rule_ids_1 = require("../rule-ids");
(0, node_test_1.describe)('regression payloads — SQLi', () => {
    const cases = [
        { input: 'UNION SELECT password FROM users', shouldFlag: true, note: 'classic union' },
        { input: "admin'--", shouldFlag: true, note: 'quote comment' },
        { input: 'search only', shouldFlag: false, note: 'benign text' },
        { input: 'and or select', shouldFlag: false, note: 'keywords in prose (balanced)' },
    ];
    for (const { input, shouldFlag, note } of cases) {
        (0, node_test_1.it)(`${note}: ${shouldFlag ? 'flags' : 'allows'}`, () => {
            node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)(input, 'balanced'), shouldFlag, input);
        });
    }
});
(0, node_test_1.describe)('regression payloads — XSS', () => {
    (0, node_test_1.it)('flags script block', () => {
        node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)('<script>alert(1)</script>'), true);
    });
    (0, node_test_1.it)('allows plain text', () => {
        node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)('Hello <b>world</b>'), false);
    });
});
(0, node_test_1.describe)('ruleIdForRuleName', () => {
    (0, node_test_1.it)('maps known rules', () => {
        node_assert_1.default.strictEqual((0, rule_ids_1.ruleIdForRuleName)('sql_injection'), rule_ids_1.RULE_IDS.sql_injection);
        node_assert_1.default.strictEqual((0, rule_ids_1.ruleIdForRuleName)('unknown_rule'), 'WAF-UNK-001');
    });
});
//# sourceMappingURL=regression-payloads.test.js.map