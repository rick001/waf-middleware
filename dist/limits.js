"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_INSPECTION_LIMITS = void 0;
exports.resolveInspectionLimits = resolveInspectionLimits;
/** Defaults for bounded inspection (DoS / latency protection). */
exports.DEFAULT_INSPECTION_LIMITS = {
    maxStringLength: 10000,
    maxObjectDepth: 20,
    maxObjectKeys: 500,
};
function resolveInspectionLimits(partial) {
    var _a, _b, _c;
    return {
        maxStringLength: (_a = partial === null || partial === void 0 ? void 0 : partial.maxStringLength) !== null && _a !== void 0 ? _a : exports.DEFAULT_INSPECTION_LIMITS.maxStringLength,
        maxObjectDepth: (_b = partial === null || partial === void 0 ? void 0 : partial.maxObjectDepth) !== null && _b !== void 0 ? _b : exports.DEFAULT_INSPECTION_LIMITS.maxObjectDepth,
        maxObjectKeys: (_c = partial === null || partial === void 0 ? void 0 : partial.maxObjectKeys) !== null && _c !== void 0 ? _c : exports.DEFAULT_INSPECTION_LIMITS.maxObjectKeys,
    };
}
//# sourceMappingURL=limits.js.map