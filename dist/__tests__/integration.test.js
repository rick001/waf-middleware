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
const node_http_1 = __importDefault(require("node:http"));
const express_1 = __importDefault(require("express"));
const waf_middleware_1 = require("../waf.middleware");
function httpGet(url) {
    return new Promise((resolve, reject) => {
        node_http_1.default
            .get(url, (res) => {
            let body = '';
            res.on('data', (c) => (body += c));
            res.on('end', () => { var _a; return resolve({ statusCode: (_a = res.statusCode) !== null && _a !== void 0 ? _a : 0, body }); });
        })
            .on('error', reject);
    });
}
(0, node_test_1.describe)('WafMiddleware (integration)', () => {
    (0, node_test_1.it)('blocks high-confidence SQLi in query (block mode)', () => __awaiter(void 0, void 0, void 0, function* () {
        const app = (0, express_1.default)();
        app.use(new waf_middleware_1.WafMiddleware({ sqlInjection: { enabled: true } }).use);
        app.get('/x', (_req, res) => {
            res.send('ok');
        });
        const server = yield new Promise((resolve) => {
            const s = app.listen(0, () => resolve(s));
        });
        const addr = server.address();
        const port = typeof addr === 'object' && addr ? addr.port : 0;
        try {
            const q = encodeURIComponent('UNION SELECT * FROM users');
            const r = yield httpGet(`http://127.0.0.1:${port}/x?q=${q}`);
            node_assert_1.default.strictEqual(r.statusCode, 403);
        }
        finally {
            yield new Promise((resolve) => server.close(() => resolve()));
        }
    }));
    (0, node_test_1.it)('monitor mode allows request through', () => __awaiter(void 0, void 0, void 0, function* () {
        const app = (0, express_1.default)();
        app.use(new waf_middleware_1.WafMiddleware({ mode: 'monitor', sqlInjection: { enabled: true } }).use);
        app.get('/x', (_req, res) => {
            res.send('ok');
        });
        const server = yield new Promise((resolve) => {
            const s = app.listen(0, () => resolve(s));
        });
        const addr = server.address();
        const port = typeof addr === 'object' && addr ? addr.port : 0;
        try {
            const q = encodeURIComponent('UNION SELECT * FROM users');
            const r = yield httpGet(`http://127.0.0.1:${port}/x?q=${q}`);
            node_assert_1.default.strictEqual(r.statusCode, 200);
            node_assert_1.default.strictEqual(r.body, 'ok');
        }
        finally {
            yield new Promise((resolve) => server.close(() => resolve()));
        }
    }));
});
//# sourceMappingURL=integration.test.js.map