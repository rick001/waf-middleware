import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { mergeOptions, type WafOptions, type ResolvedWafOptions } from './config';
import { resolveEffectiveWafOptions } from './resolve-effective-options';
import { runWafOnRequest } from './waf-engine';

@Injectable()
export class WafMiddleware implements NestMiddleware {
  private readonly globalOptions: ResolvedWafOptions;
  private readonly policies: WafOptions['policies'];
  private readonly policyResolver: WafOptions['policyResolver'];

  constructor(options?: WafOptions) {
    this.globalOptions = mergeOptions(options);
    this.policies = options?.policies;
    this.policyResolver = options?.policyResolver;
  }

  use = (req: Request, res: Response, next: NextFunction): void => {
    const opts = resolveEffectiveWafOptions(this.globalOptions, this.policies, this.policyResolver, {
      method: req.method,
      path: req.path,
      getHeader: (name: string) => req.get(name) ?? undefined,
    });

    if (runWafOnRequest(req, res, opts)) {
      next();
    }
  };
}
