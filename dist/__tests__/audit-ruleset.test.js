"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const node_assert_1 = __importDefault(require("node:assert"));
const express_1 = __importDefault(require("express"));
const supertest_1 = __importDefault(require("supertest"));
const waf_middleware_1 = require("../waf.middleware");
const ruleset_manifest_1 = require("../ruleset-manifest");
(0, node_test_1.describe)('audit rulesetVersion', () => {
    (0, node_test_1.it)('includes rulesetVersion on block audit', () => __awaiter(void 0, void 0, void 0, function* () {
        const events = [];
        const app = (0, express_1.default)();
        app.use(new waf_middleware_1.WafMiddleware({
            mode: 'block',
            sqlInjection: { enabled: true },
            auditLogger: (e) => events.push(e),
        }).use);
        app.get('/x', (_req, res) => {
            res.send('ok');
        });
        yield (0, supertest_1.default)(app).get('/x').query({ q: 'UNION SELECT 1' });
        node_assert_1.default.strictEqual(events.length, 1);
        node_assert_1.default.strictEqual(events[0].rulesetVersion, ruleset_manifest_1.RULESET_VERSION);
        node_assert_1.default.strictEqual(events[0].action, 'block');
    }));
    (0, node_test_1.it)('respects custom rulesetVersion', () => __awaiter(void 0, void 0, void 0, function* () {
        var _a;
        const events = [];
        const app = (0, express_1.default)();
        app.use(new waf_middleware_1.WafMiddleware({
            mode: 'block',
            sqlInjection: { enabled: true },
            rulesetVersion: 'custom-9',
            auditLogger: (e) => events.push(e),
        }).use);
        app.get('/x', (_req, res) => {
            res.send('ok');
        });
        yield (0, supertest_1.default)(app).get('/x').query({ q: 'UNION SELECT 1' });
        node_assert_1.default.strictEqual((_a = events[0]) === null || _a === void 0 ? void 0 : _a.rulesetVersion, 'custom-9');
    }));
});
//# sourceMappingURL=audit-ruleset.test.js.map