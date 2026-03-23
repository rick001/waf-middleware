"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const path_traversal_1 = require("../path-traversal");
const command_injection_1 = require("../command-injection");
(0, node_test_1.describe)('looksLikePathTraversal', () => {
    (0, node_test_1.it)('flags obvious traversal segments', () => {
        node_assert_1.default.strictEqual((0, path_traversal_1.looksLikePathTraversal)('/static/../../../etc/passwd'), true);
        node_assert_1.default.strictEqual((0, path_traversal_1.looksLikePathTraversal)('/x%2e%2e%2f'), true);
    });
    (0, node_test_1.it)('allows normal paths', () => {
        node_assert_1.default.strictEqual((0, path_traversal_1.looksLikePathTraversal)('/api/users/1'), false);
        node_assert_1.default.strictEqual((0, path_traversal_1.looksLikePathTraversal)('/v1.0/health'), false);
    });
});
(0, node_test_1.describe)('command injection heuristics', () => {
    (0, node_test_1.it)('flags shell-like patterns', () => {
        node_assert_1.default.strictEqual((0, command_injection_1.looksLikeCommandInjection)('; rm -rf /', 500), true);
        node_assert_1.default.strictEqual((0, command_injection_1.looksLikeCommandInjection)('`id`', 500), true);
    });
    (0, node_test_1.it)('allows normal text', () => {
        node_assert_1.default.strictEqual((0, command_injection_1.looksLikeCommandInjection)('hello world', 500), false);
    });
    (0, node_test_1.it)('checkCommandInjectionQuery', () => {
        node_assert_1.default.strictEqual((0, command_injection_1.checkCommandInjectionQuery)({ q: 'search' }, 500), false);
        node_assert_1.default.strictEqual((0, command_injection_1.checkCommandInjectionQuery)({ x: '; curl evil' }, 500), true);
    });
});
//# sourceMappingURL=path-command.test.js.map