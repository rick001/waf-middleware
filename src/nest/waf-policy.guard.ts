import { CanActivate, ExecutionContext, Injectable, Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request, Response } from 'express';
import { mergeOptions, mergeResolvedWafOptions, type WafOptions } from '../config';
import { resolveEffectiveWafOptions } from '../resolve-effective-options';
import { runWafOnRequest } from '../waf-engine';
import { WAF_POLICY_KEY } from './waf-policy.decorator';
import { WAF_MODULE_OPTIONS } from './waf.module';

/**
 * Runs the same inspection pipeline as `WafMiddleware` after merging `@WafPolicy()` metadata
 * (class, then handler) over resolved global + route `policies` + `policyResolver`.
 *
 * **Do not** apply both this guard and `WafMiddleware` on the same traffic — you would double-scan.
 * Use this guard (e.g. `APP_GUARD`) when you need decorator-based overrides; otherwise use middleware + `policies[]`.
 */
@Injectable()
export class WafPolicyGuard implements CanActivate {
  constructor(
    @Inject(WAF_MODULE_OPTIONS) private readonly moduleOptions: WafOptions,
    private readonly reflector: Reflector
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();

    const global = mergeOptions(this.moduleOptions);
    let opts = resolveEffectiveWafOptions(
      global,
      this.moduleOptions.policies,
      this.moduleOptions.policyResolver,
      {
        method: req.method,
        path: req.path,
        getHeader: (name: string) => req.get(name) ?? undefined,
      }
    );

    const classMeta = this.reflector.get<Partial<WafOptions> | undefined>(WAF_POLICY_KEY, context.getClass());
    const handlerMeta = this.reflector.get<Partial<WafOptions> | undefined>(
      WAF_POLICY_KEY,
      context.getHandler()
    );
    if (classMeta && Object.keys(classMeta).length > 0) {
      opts = mergeResolvedWafOptions(opts, classMeta);
    }
    if (handlerMeta && Object.keys(handlerMeta).length > 0) {
      opts = mergeResolvedWafOptions(opts, handlerMeta);
    }

    return runWafOnRequest(req, res, opts);
  }
}
