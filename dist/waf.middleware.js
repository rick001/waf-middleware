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
Object.defineProperty(exports, "__esModule", { value: true });
exports.WafMiddleware = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("./config");
const resolve_effective_options_1 = require("./resolve-effective-options");
const waf_engine_1 = require("./waf-engine");
let WafMiddleware = class WafMiddleware {
    constructor(options) {
        this.use = (req, res, next) => {
            const opts = (0, resolve_effective_options_1.resolveEffectiveWafOptions)(this.globalOptions, this.policies, this.policyResolver, {
                method: req.method,
                path: req.path,
                getHeader: (name) => { var _a; return (_a = req.get(name)) !== null && _a !== void 0 ? _a : undefined; },
            });
            if ((0, waf_engine_1.runWafOnRequest)(req, res, opts)) {
                next();
            }
        };
        this.globalOptions = (0, config_1.mergeOptions)(options);
        this.policies = options === null || options === void 0 ? void 0 : options.policies;
        this.policyResolver = options === null || options === void 0 ? void 0 : options.policyResolver;
    }
};
exports.WafMiddleware = WafMiddleware;
exports.WafMiddleware = WafMiddleware = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [Object])
], WafMiddleware);
