"use strict";
/**
 * Curated encoding / obfuscation cases (OWASP-style evasion patterns).
 * Documents current heuristic behavior; extend when rules improve.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const sql_injection_1 = require("../rules/sql-injection");
const xss_1 = require("../rules/xss");
const path_traversal_1 = require("../rules/path-traversal");
const utils_1 = require("../utils");
(0, node_test_1.describe)('evasion corpus — SQLi (balanced)', () => {
    const shouldFlag = [
        { label: 'union select', value: 'UNION SELECT null FROM x' },
        { label: 'mixed case union', value: 'UnIoN SeLeCt password FROM users' },
        { label: 'comment between keywords (slash-star)', value: 'UN/**/ION SEL/**/ECT 1' },
        { label: 'semicolon drop', value: "; DROP TABLE users--" },
        { label: 'hex-like backslash pattern', value: String.raw `\x53\x45\x4C\x45\x43\x54` },
    ];
    for (const { label, value } of shouldFlag) {
        (0, node_test_1.it)(`flags: ${label}`, () => {
            node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)(value, 'balanced'), true, `expected flag: ${value.slice(0, 80)}`);
        });
    }
    const shouldAllow = [
        { label: 'plain product search', value: 'blue running shoes size 10' },
        { label: 'single keyword select', value: 'select' },
        { label: 'and or in sentence', value: 'I want this and that or something else' },
        { label: 'sort asc', value: 'asc' },
        { label: 'email-like without injection', value: 'user.name+tag@example.com' },
    ];
    for (const { label, value } of shouldAllow) {
        (0, node_test_1.it)(`allows: ${label}`, () => {
            node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)(value, 'balanced'), false, label);
        });
    }
});
(0, node_test_1.describe)('evasion corpus — decode pipeline + SQLi', () => {
    (0, node_test_1.it)('flags entity-wrapped union after query decode + htmlEntities', () => {
        const q = { s: '&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;' };
        const decoded = (0, utils_1.decodeQueryValues)(q, {
            maxUrlRounds: 2,
            htmlEntities: true,
            maxHtmlEntityRounds: 3,
            maxHtmlEntityExpansion: 512,
        });
        node_assert_1.default.strictEqual(decoded.s, 'UNION SELECT');
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)(decoded.s, 'balanced'), true);
    });
    (0, node_test_1.it)('flags percent-encoded union after url decode', () => {
        const q = { q: 'uni%6Fn%20%53%45%4C%45%43%54%201' };
        const decoded = (0, utils_1.decodeQueryValues)(q, { maxUrlRounds: 3, htmlEntities: false });
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)(decoded.q, 'balanced'), true);
    });
    (0, node_test_1.it)('flags double-percent-encoded UNION SELECT after bounded decode', () => {
        const raw = '%2555%254E%2549%254F%254E%2520%2553%2545%254C%2545%2543%2554';
        const decoded = (0, utils_1.decodeUrlBounded)(raw, 2);
        node_assert_1.default.strictEqual(decoded, 'UNION SELECT');
        node_assert_1.default.strictEqual((0, sql_injection_1.looksLikeSqlInjection)(decoded, 'balanced'), true);
    });
});
(0, node_test_1.describe)('evasion corpus — XSS', () => {
    const flag = [
        { label: 'lower script', v: '<script>void(0)</script>' },
        { label: 'upper case script open', v: '<SCRIPT>alert(1)</SCRIPT>' },
        { label: 'javascript url', v: 'javascript:alert(1)' },
        { label: 'onerror attr', v: '"><img src=x onerror=alert(1)>' },
    ];
    for (const { label, v } of flag) {
        (0, node_test_1.it)(`flags: ${label}`, () => node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)(v), true));
    }
    (0, node_test_1.it)('allows escaped-looking text without executable pattern', () => {
        node_assert_1.default.strictEqual((0, xss_1.looksLikeXss)('click here for &lt;help&gt;'), false);
    });
});
(0, node_test_1.describe)('evasion corpus — path traversal', () => {
    const bad = ['/../../etc/passwd', '/foo/../../../bar', '/static/%2e%2e%2fsecret'];
    for (const p of bad) {
        (0, node_test_1.it)(`flags ${p}`, () => node_assert_1.default.strictEqual((0, path_traversal_1.looksLikePathTraversal)(p), true));
    }
    const ok = ['/api/v1/users', '/static/public/logo.png'];
    for (const p of ok) {
        (0, node_test_1.it)(`allows ${p}`, () => node_assert_1.default.strictEqual((0, path_traversal_1.looksLikePathTraversal)(p), false));
    }
    (0, node_test_1.it)('flags literal .. segment (may FP on normalized relative paths)', () => {
        node_assert_1.default.strictEqual((0, path_traversal_1.looksLikePathTraversal)('/static/../public/logo.png'), true);
    });
});
(0, node_test_1.describe)('evasion corpus — HTML entity decode safety', () => {
    (0, node_test_1.it)('does not expand unreasonably on repeated amp', () => {
        const huge = '&amp;'.repeat(200);
        const out = (0, utils_1.decodeHtmlEntitiesBounded)(huge, 3, 64);
        node_assert_1.default.ok(out.length < huge.length + 128);
    });
});
//# sourceMappingURL=evasion-corpus.test.js.map