"use strict";
/**
 * Schema-first request hardening stack.
 * Run your schema validator (ValidationPipe, Zod, etc.) first; this middleware runs as a secondary layer.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.createRequestHardeningStack = createRequestHardeningStack;
const waf_middleware_1 = require("./waf.middleware");
/**
 * Returns a single middleware that runs schemaValidator (if provided) then WAF.
 * Use this to enforce "schema first, WAF second" and avoid competing with framework validation.
 *
 * @example
 * // Express + Zod: validate body first, then harden
 * const schemaValidator = (req, res, next) => {
 *   const result = myZodSchema.safeParse(req.body);
 *   if (!result.success) return res.status(400).json({ errors: result.error.flatten() });
 *   next();
 * };
 * app.use(createRequestHardeningStack({ wafOptions: { ... }, schemaValidator }));
 *
 * @example
 * // Nest: use ValidationPipe globally; then use WafMiddleware (no schemaValidator here)
 * app.use(new WafMiddleware(options).use);
 */
function createRequestHardeningStack(options = {}) {
    const { wafOptions, schemaValidator } = options;
    const waf = new waf_middleware_1.WafMiddleware(wafOptions);
    if (!schemaValidator) {
        return (req, res, next) => waf.use(req, res, next);
    }
    return (req, res, next) => {
        schemaValidator(req, res, (err) => {
            if (err != null) {
                return next(err);
            }
            waf.use(req, res, next);
        });
    };
}
