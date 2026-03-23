import { DynamicModule, Global, Module } from '@nestjs/common';
import { WafMiddleware } from '../waf.middleware';
import type { WafOptions } from '../config';
import { WafPolicyGuard } from './waf-policy.guard';

/** Injection token for raw `WafOptions` when using `WafModule.forRoot`. */
export const WAF_MODULE_OPTIONS = 'WAF_MODULE_OPTIONS';

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
@Global()
@Module({})
export class WafModule {
  static forRoot(options: WafOptions = {}): DynamicModule {
    return {
      module: WafModule,
      providers: [
        { provide: WAF_MODULE_OPTIONS, useValue: options },
        {
          provide: WafMiddleware,
          useFactory: (opts: WafOptions) => new WafMiddleware(opts),
          inject: [WAF_MODULE_OPTIONS],
        },
        WafPolicyGuard,
      ],
      exports: [WafMiddleware, WafPolicyGuard],
    };
  }
}
