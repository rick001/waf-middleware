import { type WafOptions, type ResolvedWafOptions } from './config';
/** Minimal HTTP context for policy resolution (Express, Fastify, etc.). */
export interface WafHttpContext {
    method: string;
    path: string;
    getHeader(name: string): string | undefined;
}
/**
 * Apply `policies[]` (first match) then `policyResolver` for this request.
 * Nest `@WafPolicy()` / other merges should be layered with `mergeResolvedWafOptions` after this.
 */
export declare function resolveEffectiveWafOptions(globalResolved: ResolvedWafOptions, policies: WafOptions['policies'], policyResolver: WafOptions['policyResolver'], ctx: WafHttpContext): ResolvedWafOptions;
