"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WafPolicyGuard = void 0;
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const config_1 = require("../config");
const resolve_effective_options_1 = require("../resolve-effective-options");
const waf_engine_1 = require("../waf-engine");
const waf_policy_decorator_1 = require("./waf-policy.decorator");
const waf_module_1 = require("./waf.module");
/**
 * Runs the same inspection pipeline as `WafMiddleware` after merging `@WafPolicy()` metadata
 * (class, then handler) over resolved global + route `policies` + `policyResolver`.
 *
 * **Do not** apply both this guard and `WafMiddleware` on the same traffic — you would double-scan.
 * Use this guard (e.g. `APP_GUARD`) when you need decorator-based overrides; otherwise use middleware + `policies[]`.
 */
let WafPolicyGuard = class WafPolicyGuard {
    constructor(moduleOptions, reflector) {
        this.moduleOptions = moduleOptions;
        this.reflector = reflector;
    }
    canActivate(context) {
        const http = context.switchToHttp();
        const req = http.getRequest();
        const res = http.getResponse();
        const global = (0, config_1.mergeOptions)(this.moduleOptions);
        let opts = (0, resolve_effective_options_1.resolveEffectiveWafOptions)(global, this.moduleOptions.policies, this.moduleOptions.policyResolver, {
            method: req.method,
            path: req.path,
            getHeader: (name) => { var _a; return (_a = req.get(name)) !== null && _a !== void 0 ? _a : undefined; },
        });
        const classMeta = this.reflector.get(waf_policy_decorator_1.WAF_POLICY_KEY, context.getClass());
        const handlerMeta = this.reflector.get(waf_policy_decorator_1.WAF_POLICY_KEY, context.getHandler());
        if (classMeta && Object.keys(classMeta).length > 0) {
            opts = (0, config_1.mergeResolvedWafOptions)(opts, classMeta);
        }
        if (handlerMeta && Object.keys(handlerMeta).length > 0) {
            opts = (0, config_1.mergeResolvedWafOptions)(opts, handlerMeta);
        }
        return (0, waf_engine_1.runWafOnRequest)(req, res, opts);
    }
};
exports.WafPolicyGuard = WafPolicyGuard;
exports.WafPolicyGuard = WafPolicyGuard = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(waf_module_1.WAF_MODULE_OPTIONS)),
    __metadata("design:paramtypes", [Object, core_1.Reflector])
], WafPolicyGuard);
//# sourceMappingURL=waf-policy.guard.js.map