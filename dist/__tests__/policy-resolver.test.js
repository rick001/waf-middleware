"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const config_1 = require("../config");
(0, node_test_1.describe)('mergeResolvedWafOptions', () => {
    (0, node_test_1.it)('merges mode over base', () => {
        const base = (0, config_1.mergeOptions)({});
        const next = (0, config_1.mergeResolvedWafOptions)(base, { mode: 'monitor' });
        node_assert_1.default.strictEqual(next.mode, 'monitor');
        node_assert_1.default.strictEqual(base.mode, 'block');
    });
    (0, node_test_1.it)('strips policies and policyResolver from merge payload', () => {
        const base = (0, config_1.mergeOptions)({});
        const next = (0, config_1.mergeResolvedWafOptions)(base, {
            mode: 'monitor',
            policies: [],
            policyResolver: () => ({}),
        });
        node_assert_1.default.strictEqual(next.mode, 'monitor');
    });
});
//# sourceMappingURL=policy-resolver.test.js.map