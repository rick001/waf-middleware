"use strict";
/**
 * Fastify `preHandler` hook factory — same pipeline as `WafMiddleware`.
 * Install **after** body parsers so `req.body` is populated when applicable.
 *
 * Peer dependency: `fastify` (^4 || ^5). Types here are structural; any compatible server works.
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createFastifyWafPreHandler = createFastifyWafPreHandler;
exports.createFastifyWafPreHandlerWithMerge = createFastifyWafPreHandlerWithMerge;
const config_1 = require("./config");
const resolve_effective_options_1 = require("./resolve-effective-options");
const waf_engine_1 = require("./waf-engine");
function pathFromUrl(url) {
    const q = url.indexOf('?');
    return q >= 0 ? url.slice(0, q) : url || '/';
}
function getHeader(headers, name) {
    const key = name.toLowerCase();
    const v = headers[key];
    if (typeof v === 'string')
        return v;
    if (Array.isArray(v) && typeof v[0] === 'string')
        return v[0];
    return undefined;
}
function toExpressLikeRequest(req, path) {
    var _a;
    return {
        method: req.method,
        path,
        query: req.query,
        body: req.body,
        get: (n) => getHeader(req.headers, n),
        socket: (_a = req.socket) !== null && _a !== void 0 ? _a : { remoteAddress: req.ip },
        id: req.id,
    };
}
function toExpressLikeReply(reply) {
    let code = 200;
    const res = {
        status(c) {
            code = c;
            return res;
        },
        json(payload) {
            reply.code(code).send(payload);
        },
    };
    return res;
}
/**
 * Returns an async `preHandler` compatible with Fastify 4/5.
 * On block, the reply is sent and the hook returns without calling `done` (async style).
 */
function createFastifyWafPreHandler(userOptions) {
    const globalOptions = (0, config_1.mergeOptions)(userOptions);
    const policies = userOptions === null || userOptions === void 0 ? void 0 : userOptions.policies;
    const policyResolver = userOptions === null || userOptions === void 0 ? void 0 : userOptions.policyResolver;
    return function wafPreHandler(req, reply) {
        return __awaiter(this, void 0, void 0, function* () {
            const path = pathFromUrl(req.url || '/');
            const opts = (0, resolve_effective_options_1.resolveEffectiveWafOptions)(globalOptions, policies, policyResolver, {
                method: req.method,
                path,
                getHeader: (n) => getHeader(req.headers, n),
            });
            const fauxReq = toExpressLikeRequest(req, path);
            const fauxRes = toExpressLikeReply(reply);
            if ((0, waf_engine_1.runWafOnRequest)(fauxReq, fauxRes, opts)) {
                return;
            }
            /* Blocked: response already sent */
        });
    };
}
/**
 * Merge extra `Partial<WafOptions>` (e.g. per-plugin overrides) then build a preHandler.
 * Rare; prefer global `WafOptions` + `policies` / `policyResolver`.
 */
function createFastifyWafPreHandlerWithMerge(base, mergeBeforeRequest) {
    const globalOptions = (0, config_1.mergeOptions)(base);
    const policies = base === null || base === void 0 ? void 0 : base.policies;
    const policyResolver = base === null || base === void 0 ? void 0 : base.policyResolver;
    return function wafPreHandler(req, reply) {
        return __awaiter(this, void 0, void 0, function* () {
            const path = pathFromUrl(req.url || '/');
            let opts = (0, resolve_effective_options_1.resolveEffectiveWafOptions)(globalOptions, policies, policyResolver, {
                method: req.method,
                path,
                getHeader: (n) => getHeader(req.headers, n),
            });
            const extra = mergeBeforeRequest(req);
            if (extra && Object.keys(extra).length > 0) {
                opts = (0, config_1.mergeResolvedWafOptions)(opts, extra);
            }
            const fauxReq = toExpressLikeRequest(req, path);
            const fauxRes = toExpressLikeReply(reply);
            if ((0, waf_engine_1.runWafOnRequest)(fauxReq, fauxRes, opts)) {
                return;
            }
        });
    };
}
