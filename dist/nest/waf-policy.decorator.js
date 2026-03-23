"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WafPolicy = exports.WAF_POLICY_KEY = void 0;
const common_1 = require("@nestjs/common");
/** Metadata key for per-controller WAF overrides (use with `WafPolicyGuard`). */
exports.WAF_POLICY_KEY = 'wafPolicy';
/**
 * Per-route WAF overrides when using `WafPolicyGuard` (class metadata merged first, then method).
 * For path-only apps, `WafOptions.policies` with `WafMiddleware` is usually simpler.
 */
const WafPolicy = (overrides) => (0, common_1.SetMetadata)(exports.WAF_POLICY_KEY, overrides);
exports.WafPolicy = WafPolicy;
//# sourceMappingURL=waf-policy.decorator.js.map