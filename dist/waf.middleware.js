"use strict";
var __esDecorate = (this && this.__esDecorate) || function (ctor, descriptorIn, decorators, contextIn, initializers, extraInitializers) {
    function accept(f) { if (f !== void 0 && typeof f !== "function") throw new TypeError("Function expected"); return f; }
    var kind = contextIn.kind, key = kind === "getter" ? "get" : kind === "setter" ? "set" : "value";
    var target = !descriptorIn && ctor ? contextIn["static"] ? ctor : ctor.prototype : null;
    var descriptor = descriptorIn || (target ? Object.getOwnPropertyDescriptor(target, contextIn.name) : {});
    var _, done = false;
    for (var i = decorators.length - 1; i >= 0; i--) {
        var context = {};
        for (var p in contextIn) context[p] = p === "access" ? {} : contextIn[p];
        for (var p in contextIn.access) context.access[p] = contextIn.access[p];
        context.addInitializer = function (f) { if (done) throw new TypeError("Cannot add initializers after decoration has completed"); extraInitializers.push(accept(f || null)); };
        var result = (0, decorators[i])(kind === "accessor" ? { get: descriptor.get, set: descriptor.set } : descriptor[key], context);
        if (kind === "accessor") {
            if (result === void 0) continue;
            if (result === null || typeof result !== "object") throw new TypeError("Object expected");
            if (_ = accept(result.get)) descriptor.get = _;
            if (_ = accept(result.set)) descriptor.set = _;
            if (_ = accept(result.init)) initializers.unshift(_);
        }
        else if (_ = accept(result)) {
            if (kind === "field") initializers.unshift(_);
            else descriptor[key] = _;
        }
    }
    if (target) Object.defineProperty(target, contextIn.name, descriptor);
    done = true;
};
var __runInitializers = (this && this.__runInitializers) || function (thisArg, initializers, value) {
    var useValue = arguments.length > 2;
    for (var i = 0; i < initializers.length; i++) {
        value = useValue ? initializers[i].call(thisArg, value) : initializers[i].call(thisArg);
    }
    return useValue ? value : void 0;
};
var __setFunctionName = (this && this.__setFunctionName) || function (f, name, prefix) {
    if (typeof name === "symbol") name = name.description ? "[".concat(name.description, "]") : "";
    return Object.defineProperty(f, "name", { configurable: true, value: prefix ? "".concat(prefix, " ", name) : name });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WafMiddleware = void 0;
const common_1 = require("@nestjs/common");
let WafMiddleware = (() => {
    let _classDecorators = [(0, common_1.Injectable)()];
    let _classDescriptor;
    let _classExtraInitializers = [];
    let _classThis;
    var WafMiddleware = _classThis = class {
        use(req, res, next) {
            const { query, body } = req;
            const validSortValues = ['ASC', 'DESC'];
            // Normalize query parameter keys to lowercase for consistent validation
            const standardizedQuery = Object.keys(query).reduce((acc, key) => {
                acc[key.toLowerCase()] = query[key];
                return acc;
            }, {});
            // Remove empty query parameters
            Object.keys(standardizedQuery).forEach(key => {
                if (standardizedQuery[key] === '') {
                    delete standardizedQuery[key];
                }
            });
            // Validate sorting-related parameters and sanitize field names
            for (const key of Object.keys(standardizedQuery)) {
                const value = standardizedQuery[key];
                if (key.includes('sort')) {
                    const valueStr = Array.isArray(value) ? value[0] : value;
                    if (typeof valueStr === 'string' && !validSortValues.includes(valueStr.toUpperCase())) {
                        return res.status(403).json({ message: 'Invalid input detected. Request blocked.' });
                    }
                }
                if (key.includes('order') || key.includes('field')) {
                    if (!/^[a-zA-Z0-9_]+$/.test(value)) {
                        return res.status(400).json({ message: 'Invalid input detected. Request blocked.' });
                    }
                }
            }
            const isSqlInjected = (input, isFreeText = false, isPassword = false, isEmail = false) => {
                if (!input)
                    return false;
                const inputStr = typeof input === 'object' ? JSON.stringify(input) : String(input).trim();
                if (isPassword) {
                    return /(\bSELECT\b|\bDROP\b|\bTABLE\b|\bUNION\b|\bWHERE\b|\bOR\b|\bAND\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)/gi.test(inputStr);
                }
                if (isEmail) {
                    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                    return !emailRegex.test(inputStr);
                }
                const sqlPatterns = [
                    /\b(OR|AND)\b\s*\d*\s*=\s*\d*/gi,
                    /\b(UNION\s+SELECT|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|UPDATE\s+SET)\b/gi,
                    /(--|#|\/\*)/g,
                    /\b(EXEC|EXECUTE|SLEEP|WAITFOR|DELAY|HAVING|CAST|CONVERT)\b\s*\(/gi,
                    /['"][\s]*OR[\s]+['"]?[\d]+=[\d]+/gi,
                    /['"][\s]*AND[\s]+['"]?[\d]+=[\d]+/gi,
                    /(\x53\x45\x4C\x45\x43\x54|\x44\x52\x4F\x50|\x54\x41\x42\x4C\x45)/gi,
                ];
                if (!isFreeText) {
                    return sqlPatterns.some(pattern => pattern.test(inputStr));
                }
                return sqlPatterns.some(pattern => pattern.test(inputStr)) &&
                    /(\bTABLE\b|\bFROM\b|\bWHERE\b|\bINTO\b|\bVALUES\b|\bSET\b)/gi.test(inputStr);
            };
            // Validate query parameters
            for (const key of Object.keys(standardizedQuery)) {
                if (isSqlInjected(standardizedQuery[key])) {
                    return res.status(400).json({ message: 'Invalid input detected. Request blocked.' });
                }
            }
            // Validate body parameters
            if (body && typeof body === 'object') {
                for (const key of Object.keys(body)) {
                    const value = body[key];
                    const isEmailField = key.toLowerCase().includes('email');
                    const isPasswordField = key.toLowerCase().includes('password');
                    if ((isEmailField && isSqlInjected(value, false, false, true)) ||
                        (isPasswordField && isSqlInjected(value, false, true)) ||
                        (typeof value === 'number' || typeof value === 'boolean') && isSqlInjected(value) ||
                        (typeof value === 'string' && !/\s/.test(value) && isSqlInjected(value)) ||
                        (typeof value === 'string' && /\s/.test(value) && isSqlInjected(value, true))) {
                        return res.status(403).json({ message: 'Invalid input detected. Request blocked.' });
                    }
                }
            }
            // XSS Protection
            const xssPattern = /(<script.*?>.*?<\/script>|javascript:|on\w+\s*=)/gi;
            if (xssPattern.test(JSON.stringify(standardizedQuery)) || xssPattern.test(JSON.stringify(body))) {
                return res.status(403).json({ message: 'Potential XSS attack detected' });
            }
            next();
        }
    };
    __setFunctionName(_classThis, "WafMiddleware");
    (() => {
        const _metadata = typeof Symbol === "function" && Symbol.metadata ? Object.create(null) : void 0;
        __esDecorate(null, _classDescriptor = { value: _classThis }, _classDecorators, { kind: "class", name: _classThis.name, metadata: _metadata }, null, _classExtraInitializers);
        WafMiddleware = _classThis = _classDescriptor.value;
        if (_metadata) Object.defineProperty(_classThis, Symbol.metadata, { enumerable: true, configurable: true, writable: true, value: _metadata });
        __runInitializers(_classThis, _classExtraInitializers);
    })();
    return WafMiddleware = _classThis;
})();
exports.WafMiddleware = WafMiddleware;
//# sourceMappingURL=waf.middleware.js.map