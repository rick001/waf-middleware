import type { WafOptions } from '../config';
/** Metadata key for per-controller WAF overrides (use with `WafPolicyGuard`). */
export declare const WAF_POLICY_KEY = "wafPolicy";
/**
 * Per-route WAF overrides when using `WafPolicyGuard` (class metadata merged first, then method).
 * For path-only apps, `WafOptions.policies` with `WafMiddleware` is usually simpler.
 */
export declare const WafPolicy: (overrides: Partial<WafOptions>) => import("@nestjs/common").CustomDecorator<string>;
