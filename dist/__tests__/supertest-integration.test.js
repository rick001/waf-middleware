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
(0, node_test_1.describe)('WafMiddleware (supertest)', () => {
    (0, node_test_1.it)('returns 403 for SQLi in query', () => __awaiter(void 0, void 0, void 0, function* () {
        const app = (0, express_1.default)();
        app.use(new waf_middleware_1.WafMiddleware({ sqlInjection: { enabled: true } }).use);
        app.get('/api', (_req, res) => {
            res.json({ ok: true });
        });
        const res = yield (0, supertest_1.default)(app).get('/api').query({ q: 'UNION SELECT * FROM t' });
        node_assert_1.default.strictEqual(res.status, 403);
    }));
    (0, node_test_1.it)('returns 200 for clean query', () => __awaiter(void 0, void 0, void 0, function* () {
        const app = (0, express_1.default)();
        app.use(new waf_middleware_1.WafMiddleware({ sqlInjection: { enabled: true } }).use);
        app.get('/api', (_req, res) => {
            res.json({ ok: true });
        });
        const res = yield (0, supertest_1.default)(app).get('/api').query({ q: 'hello' });
        node_assert_1.default.strictEqual(res.status, 200);
        node_assert_1.default.strictEqual(res.body.ok, true);
    }));
});
//# sourceMappingURL=supertest-integration.test.js.map