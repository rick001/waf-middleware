"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const sort_1 = require("../sort");
const defaultOpts = {
    sortParamNames: ['sort', 'order', 'dir'],
    orderFieldParamNames: ['order_field', 'orderby', 'field'],
    fieldNamePattern: /^[a-zA-Z0-9_.-]+$/,
};
(0, node_test_1.describe)('checkSortValidation', () => {
    (0, node_test_1.it)('allows valid sort values (ASC, DESC)', () => {
        node_assert_1.default.strictEqual((0, sort_1.checkSortValidation)({ sort: 'ASC' }, defaultOpts).block, false);
        node_assert_1.default.strictEqual((0, sort_1.checkSortValidation)({ sort: 'desc' }, defaultOpts).block, false);
        node_assert_1.default.strictEqual((0, sort_1.checkSortValidation)({ order: 'ASC' }, defaultOpts).block, false);
    });
    (0, node_test_1.it)('blocks invalid sort value', () => {
        const r = (0, sort_1.checkSortValidation)({ sort: "ASC; DROP TABLE x" }, defaultOpts);
        node_assert_1.default.strictEqual(r.block, true);
        node_assert_1.default.strictEqual(r.reason, 'invalid_sort');
    });
    (0, node_test_1.it)('allows field names with dots and hyphens', () => {
        node_assert_1.default.strictEqual((0, sort_1.checkSortValidation)({ order_field: 'user.name' }, defaultOpts).block, false);
        node_assert_1.default.strictEqual((0, sort_1.checkSortValidation)({ orderby: 'created-at' }, defaultOpts).block, false);
    });
    (0, node_test_1.it)('only validates allowlisted param names (not substring match)', () => {
        node_assert_1.default.strictEqual((0, sort_1.checkSortValidation)({ disorder: 'yes' }, defaultOpts).block, false);
        node_assert_1.default.strictEqual((0, sort_1.checkSortValidation)({ reorder: 'ASC' }, defaultOpts).block, false);
    });
    (0, node_test_1.it)('blocks invalid characters in order field', () => {
        const r = (0, sort_1.checkSortValidation)({ order_field: "name'; DELETE FROM users--" }, defaultOpts);
        node_assert_1.default.strictEqual(r.block, true);
        node_assert_1.default.strictEqual(r.reason, 'invalid_order_field');
    });
});
//# sourceMappingURL=sort.test.js.map