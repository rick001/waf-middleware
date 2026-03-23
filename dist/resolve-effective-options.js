"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveEffectiveWafOptions = resolveEffectiveWafOptions;
const config_1 = require("./config");
/**
 * Apply `policies[]` (first match) then `policyResolver` for this request.
 * Nest `@WafPolicy()` / other merges should be layered with `mergeResolvedWafOptions` after this.
 */
function resolveEffectiveWafOptions(globalResolved, policies, policyResolver, ctx) {
    let opts = policies && policies.length > 0
        ? (0, config_1.resolvePolicyForRequest)({ method: ctx.method, path: ctx.path }, globalResolved, policies)
        : globalResolved;
    if (policyResolver) {
        const partial = policyResolver({
            method: ctx.method,
            path: ctx.path,
            get: ctx.getHeader,
        });
        if (partial && Object.keys(partial).length > 0) {
            opts = (0, config_1.mergeResolvedWafOptions)(opts, partial);
        }
    }
    return opts;
}
