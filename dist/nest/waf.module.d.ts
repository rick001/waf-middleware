import { DynamicModule } from '@nestjs/common';
import type { WafOptions } from '../config';
/** Injection token for raw `WafOptions` when using `WafModule.forRoot`. */
export declare const WAF_MODULE_OPTIONS = "WAF_MODULE_OPTIONS";
/**
 * NestJS global module that provides `WafMiddleware` with options from `forRoot`.
 * Apply the middleware in your root module:
 *
 * ```ts
 * export class AppModule implements NestModule {
 *   configure(consumer: MiddlewareConsumer) {
 *     consumer.apply(WafMiddleware).forRoutes('*');
 *   }
 * }
 * ```
 *
 * For `@WafPolicy()` on controllers, register `WafPolicyGuard` (e.g. `APP_GUARD`) and **omit** the global
 * WAF middleware to avoid scanning twice — see `examples/nest-basic`.
 */
export declare class WafModule {
    static forRoot(options?: WafOptions): DynamicModule;
}
