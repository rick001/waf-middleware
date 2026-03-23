"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const sql_injection_1 = require("../sql-injection");
(0, node_test_1.describe)('looksLikeSqlInjection', () => {
    (0, node_test_1.it)('allows normal words that are SQL keywords (no false positives)', () => {
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('and', 'balanced'), false);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('or', 'balanced'), false);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('select', 'balanced'), false);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('order', 'balanced'), false);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('My name is Andrew', 'balanced'), false);
    });
    (0, node_test_1.it)('blocks high-confidence SQL injection patterns', () => {
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)("' OR 1=1 --", 'lenient'), true);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('UNION SELECT * FROM users', 'lenient'), true);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('; DROP TABLE users;', 'lenient'), true);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)("1' OR '1'='1", 'lenient'), true);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('\\x53\\x45\\x4C\\x45\\x43\\x54', 'lenient'), true);
    });
    (0, node_test_1.it)('allows empty and very long input', () => {
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('', 'strict'), false);
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)('x'.repeat(10001), 'strict'), false);
    });
});
(0, node_test_1.describe)('hasEmailInjectionFragment', () => {
    (0, node_test_1.it)('allows valid and invalid email formats (WAF does not validate email format)', () => {
        node_assert_1.default.strictEqual((0, sql_injection_1.hasEmailInjectionFragment)('user@example.com'), false);
        node_assert_1.default.strictEqual((0, sql_injection_1.hasEmailInjectionFragment)('invalid-email'), false);
        node_assert_1.default.strictEqual((0, sql_injection_1.hasEmailInjectionFragment)('user+tag@domain.co.uk'), false);
    });
    (0, node_test_1.it)('blocks only obvious injection in email-like value', () => {
        node_assert_1.default.strictEqual((0, sql_injection_1.hasEmailInjectionFragment)("user@example.com' OR '1'='1"), true);
        node_assert_1.default.strictEqual((0, sql_injection_1.hasEmailInjectionFragment)("' OR 1=1 --"), true);
    });
});
(0, node_test_1.describe)('checkBody', () => {
    (0, node_test_1.it)('skips password-like keys (no blocking on SQL keywords in password)', () => {
        const result = (0, sql_injection_1.checkBody)({ password: "MyP@ssw0rd_SELECT_AND_OR", email: 'u@e.com' }, { sensitivity: 'balanced', skipBodyKeys: ['password', 'email'] });
        node_assert_1.default.strictEqual(result.block, false);
    });
    (0, node_test_1.it)('allows special characters in password when key is in skipBodyKeys', () => {
        const result = (0, sql_injection_1.checkBody)({ password: "P@$$w0rd!#';--" }, { sensitivity: 'strict', skipBodyKeys: ['password'] });
        node_assert_1.default.strictEqual(result.block, false);
    });
    (0, node_test_1.it)('blocks injection in non-password body fields', () => {
        const result = (0, sql_injection_1.checkBody)({ username: "' OR 1=1 --" }, { sensitivity: 'balanced', skipBodyKeys: ['password'] });
        node_assert_1.default.strictEqual(result.block, true);
    });
});
(0, node_test_1.describe)('checkQueryParams', () => {
    (0, node_test_1.it)('allows normal query values', () => {
        node_assert_1.default.strictEqual((0, sql_injection_1.checkQueryParams)({ q: 'searchterm' }, 'balanced'), false);
        node_assert_1.default.strictEqual((0, sql_injection_1.checkQueryParams)({ search: 'and or select' }, 'balanced'), false);
    });
    (0, node_test_1.it)('blocks injection in query', () => {
        node_assert_1.default.strictEqual((0, sql_injection_1.checkQueryParams)({ id: "1; DROP TABLE x--" }, 'balanced'), true);
        node_assert_1.default.strictEqual((0, sql_injection_1.checkQueryParams)({ order_field: "name'; DELETE FROM users--" }, 'balanced'), true);
    });
});
//# sourceMappingURL=sql-injection.test.js.map