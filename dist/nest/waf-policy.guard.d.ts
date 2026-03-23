import { CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { type WafOptions } from '../config';
/**
 * Runs the same inspection pipeline as `WafMiddleware` after merging `@WafPolicy()` metadata
 * (class, then handler) over resolved global + route `policies` + `policyResolver`.
 *
 * **Do not** apply both this guard and `WafMiddleware` on the same traffic — you would double-scan.
 * Use this guard (e.g. `APP_GUARD`) when you need decorator-based overrides; otherwise use middleware + `policies[]`.
 */
export declare class WafPolicyGuard implements CanActivate {
    private readonly moduleOptions;
    private readonly reflector;
    constructor(moduleOptions: WafOptions, reflector: Reflector);
    canActivate(context: ExecutionContext): boolean;
}
