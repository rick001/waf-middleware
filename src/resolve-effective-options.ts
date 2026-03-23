import {
  mergeResolvedWafOptions,
  resolvePolicyForRequest,
  type WafOptions,
  type ResolvedWafOptions,
} from './config';

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
export function resolveEffectiveWafOptions(
  globalResolved: ResolvedWafOptions,
  policies: WafOptions['policies'],
  policyResolver: WafOptions['policyResolver'],
  ctx: WafHttpContext
): ResolvedWafOptions {
  let opts =
    policies && policies.length > 0
      ? resolvePolicyForRequest({ method: ctx.method, path: ctx.path }, globalResolved, policies)
      : globalResolved;

  if (policyResolver) {
    const partial = policyResolver({
      method: ctx.method,
      path: ctx.path,
      get: ctx.getHeader,
    });
    if (partial && Object.keys(partial).length > 0) {
      opts = mergeResolvedWafOptions(opts, partial);
    }
  }
  return opts;
}
