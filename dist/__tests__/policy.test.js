"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const config_1 = require("../config");
(0, node_test_1.describe)('resolvePolicyForRequest', () => {
    const globalResolved = (0, config_1.mergeOptions)({});
    (0, node_test_1.it)('returns global options when no policies match', () => {
        const policies = [{ match: { path: '/webhooks' }, overrides: { pathAllowlist: ['/webhooks'] } }];
        const resolved = (0, config_1.resolvePolicyForRequest)({ method: 'GET', path: '/api/users' }, globalResolved, policies);
        node_assert_1.default.strictEqual(resolved.pathAllowlist, globalResolved.pathAllowlist);
    });
    (0, node_test_1.it)('merges first matching policy over global (path prefix)', () => {
        const policies = [{ match: { path: '/webhooks' }, overrides: { pathAllowlist: ['/webhooks'] } }];
        const resolved = (0, config_1.resolvePolicyForRequest)({ method: 'POST', path: '/webhooks/stripe' }, globalResolved, policies);
        node_assert_1.default.deepStrictEqual(resolved.pathAllowlist, ['/webhooks']);
    });
    (0, node_test_1.it)('matches by method when specified', () => {
        const policies = [
            { match: { path: '/api', method: 'POST' }, overrides: { blockMessage: 'Custom' } },
        ];
        const resolvedPost = (0, config_1.resolvePolicyForRequest)({ method: 'POST', path: '/api' }, globalResolved, policies);
        const resolvedGet = (0, config_1.resolvePolicyForRequest)({ method: 'GET', path: '/api' }, globalResolved, policies);
        node_assert_1.default.strictEqual(resolvedPost.blockMessage, 'Custom');
        node_assert_1.default.strictEqual(resolvedGet.blockMessage, globalResolved.blockMessage);
    });
    (0, node_test_1.it)('returns global when policies array is empty', () => {
        const resolved = (0, config_1.resolvePolicyForRequest)({ method: 'GET', path: '/any' }, globalResolved, []);
        node_assert_1.default.strictEqual(resolved, globalResolved);
    });
});
//# sourceMappingURL=policy.test.js.map