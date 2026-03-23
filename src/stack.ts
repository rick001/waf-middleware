/**
 * Schema-first request hardening stack.
 * Run your schema validator (ValidationPipe, Zod, etc.) first; this middleware runs as a secondary layer.
 */

import { Request, Response, NextFunction } from 'express';
import { WafMiddleware } from './waf.middleware';
import type { WafOptions } from './config';

/** Optional schema validator middleware. Run before WAF; must call next() or send a response. */
export type SchemaValidatorMiddleware = (req: Request, res: Response, next: NextFunction) => void;

export interface RequestHardeningStackOptions {
  /** WAF options (route policies, rules, logger, etc.). */
  wafOptions?: WafOptions;
  /**
   * Optional schema validator middleware. If provided, it runs first; on success, WAF runs next.
   * Use with Zod, Yup, Joi, or Express validators so that schema validation is the primary enforcement.
   */
  schemaValidator?: SchemaValidatorMiddleware;
}

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
export function createRequestHardeningStack(options: RequestHardeningStackOptions = {}): (req: Request, res: Response, next: NextFunction) => void {
  const { wafOptions, schemaValidator } = options;
  const waf = new WafMiddleware(wafOptions);

  if (!schemaValidator) {
    return (req: Request, res: Response, next: NextFunction) => waf.use(req, res, next);
  }

  return (req: Request, res: Response, next: NextFunction) => {
    schemaValidator(req, res, (err?: unknown) => {
      if (err != null) {
        return next(err);
      }
      waf.use(req, res, next);
    });
  };
}
