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
const fastify_waf_1 = require("../fastify-waf");
(0, node_test_1.describe)('createFastifyWafPreHandler', () => {
    (0, node_test_1.it)('blocks SQLi in query and sends 403', () => __awaiter(void 0, void 0, void 0, function* () {
        const hook = (0, fastify_waf_1.createFastifyWafPreHandler)({ sqlInjection: { enabled: true }, mode: 'block' });
        const sent = {};
        const req = {
            method: 'GET',
            url: '/api?q=' + encodeURIComponent('UNION SELECT 1'),
            query: { q: 'UNION SELECT 1' },
            headers: {},
        };
        const reply = {
            code(c) {
                sent.code = c;
                return this;
            },
            send(b) {
                sent.body = b;
            },
        };
        yield hook(req, reply);
        node_assert_1.default.strictEqual(sent.code, 403);
    }));
    (0, node_test_1.it)('allows clean request (no reply body)', () => __awaiter(void 0, void 0, void 0, function* () {
        const hook = (0, fastify_waf_1.createFastifyWafPreHandler)({ sqlInjection: { enabled: true } });
        let sent = false;
        const req = {
            method: 'GET',
            url: '/health',
            query: {},
            headers: {},
        };
        const reply = {
            code() {
                sent = true;
                return this;
            },
            send() {
                sent = true;
            },
        };
        yield hook(req, reply);
        node_assert_1.default.strictEqual(sent, false);
    }));
    (0, node_test_1.it)('strips query string from path for policy matching', () => __awaiter(void 0, void 0, void 0, function* () {
        const hook = (0, fastify_waf_1.createFastifyWafPreHandler)({
            policies: [
                {
                    match: { path: '/v1' },
                    overrides: { mode: 'monitor', sqlInjection: { enabled: true } },
                },
            ],
        });
        const req = {
            method: 'GET',
            url: '/v1/items?q=' + encodeURIComponent('UNION SELECT 1'),
            query: { q: 'UNION SELECT 1' },
            headers: {},
        };
        let code;
        const reply = {
            code(c) {
                code = c;
                return this;
            },
            send() {
                /* monitor: no send */
            },
        };
        yield hook(req, reply);
        node_assert_1.default.strictEqual(code, undefined);
    }));
});
//# sourceMappingURL=fastify-waf.test.js.map