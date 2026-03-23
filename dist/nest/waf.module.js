"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var WafModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.WafModule = exports.WAF_MODULE_OPTIONS = void 0;
const common_1 = require("@nestjs/common");
const waf_middleware_1 = require("../waf.middleware");
const waf_policy_guard_1 = require("./waf-policy.guard");
/** Injection token for raw `WafOptions` when using `WafModule.forRoot`. */
exports.WAF_MODULE_OPTIONS = 'WAF_MODULE_OPTIONS';
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
let WafModule = WafModule_1 = class WafModule {
    static forRoot(options = {}) {
        return {
            module: WafModule_1,
            providers: [
                { provide: exports.WAF_MODULE_OPTIONS, useValue: options },
                {
                    provide: waf_middleware_1.WafMiddleware,
                    useFactory: (opts) => new waf_middleware_1.WafMiddleware(opts),
                    inject: [exports.WAF_MODULE_OPTIONS],
                },
                waf_policy_guard_1.WafPolicyGuard,
            ],
            exports: [waf_middleware_1.WafMiddleware, waf_policy_guard_1.WafPolicyGuard],
        };
    }
};
exports.WafModule = WafModule;
exports.WafModule = WafModule = WafModule_1 = __decorate([
    (0, common_1.Global)(),
    (0, common_1.Module)({})
], WafModule);
