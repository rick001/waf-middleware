"use strict";
/**
 * Configuration types and defaults for production-grade WAF middleware.
 */
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultWafOptions = void 0;
exports.mergeOptions = mergeOptions;
exports.mergeResolvedWafOptions = mergeResolvedWafOptions;
exports.resolvePolicyForRequest = resolvePolicyForRequest;
const limits_1 = require("./limits");
const ruleset_manifest_1 = require("./ruleset-manifest");
const DEFAULT_SORT_PARAM_NAMES = ['sort', 'order', 'sortorder', 'sort_order', 'dir', 'direction'];
const DEFAULT_ORDER_FIELD_PARAM_NAMES = ['order_field', 'orderby', 'order_by', 'field', 'sort_by', 'sortby'];
exports.defaultWafOptions = {
    sqlInjection: {
        enabled: true,
        sensitivity: 'balanced',
        skipBodyKeys: ['password', 'passwordConfirm', 'currentPassword', 'newPassword', 'token', 'secret'],
    },
    xss: {
        enabled: true,
        allowlistedBodyKeys: [],
        richHtmlBodyKeys: [],
    },
    sortValidation: {
        enabled: true,
        sortParamNames: DEFAULT_SORT_PARAM_NAMES,
        orderFieldParamNames: DEFAULT_ORDER_FIELD_PARAM_NAMES,
        fieldNamePattern: /^[a-zA-Z0-9_.-]+$/,
    },
    pathAllowlist: [],
    contentTypeSkipList: ['multipart/form-data'],
    blockStatus: 403,
    blockMessage: 'Request blocked by security policy.',
    logger: undefined,
    mode: 'block',
    queryDecode: {
        enabled: false,
        maxRounds: 2,
        htmlEntities: false,
        maxHtmlEntityRounds: 2,
        maxHtmlEntityExpansion: 256,
    },
    pathTraversal: { enabled: false },
    commandInjection: { enabled: false },
};
function mergeOptions(user) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y, _z;
    const pathAllowlist = (_a = user === null || user === void 0 ? void 0 : user.pathAllowlist) !== null && _a !== void 0 ? _a : exports.defaultWafOptions.pathAllowlist;
    const contentTypeSkipList = (_b = user === null || user === void 0 ? void 0 : user.contentTypeSkipList) !== null && _b !== void 0 ? _b : exports.defaultWafOptions.contentTypeSkipList;
    const sqlInjection = Object.assign(Object.assign({}, exports.defaultWafOptions.sqlInjection), user === null || user === void 0 ? void 0 : user.sqlInjection);
    const xss = Object.assign(Object.assign({}, exports.defaultWafOptions.xss), user === null || user === void 0 ? void 0 : user.xss);
    const sortValidation = Object.assign(Object.assign({}, exports.defaultWafOptions.sortValidation), user === null || user === void 0 ? void 0 : user.sortValidation);
    const queryDecode = Object.assign(Object.assign({}, exports.defaultWafOptions.queryDecode), user === null || user === void 0 ? void 0 : user.queryDecode);
    const pathTraversal = Object.assign(Object.assign({}, exports.defaultWafOptions.pathTraversal), user === null || user === void 0 ? void 0 : user.pathTraversal);
    const commandInjection = Object.assign(Object.assign({}, exports.defaultWafOptions.commandInjection), user === null || user === void 0 ? void 0 : user.commandInjection);
    return {
        sqlInjection: {
            enabled: (_c = sqlInjection.enabled) !== null && _c !== void 0 ? _c : true,
            sensitivity: (_d = sqlInjection.sensitivity) !== null && _d !== void 0 ? _d : 'balanced',
            skipBodyKeys: ((_e = sqlInjection.skipBodyKeys) !== null && _e !== void 0 ? _e : exports.defaultWafOptions.sqlInjection.skipBodyKeys),
        },
        xss: {
            enabled: (_f = xss.enabled) !== null && _f !== void 0 ? _f : true,
            allowlistedBodyKeys: ((_g = xss.allowlistedBodyKeys) !== null && _g !== void 0 ? _g : []),
            richHtmlBodyKeys: ((_h = xss.richHtmlBodyKeys) !== null && _h !== void 0 ? _h : []),
            sanitizeHtml: xss.sanitizeHtml,
        },
        sortValidation: {
            enabled: (_j = sortValidation.enabled) !== null && _j !== void 0 ? _j : true,
            sortParamNames: ((_k = sortValidation.sortParamNames) !== null && _k !== void 0 ? _k : exports.defaultWafOptions.sortValidation.sortParamNames),
            orderFieldParamNames: ((_l = sortValidation.orderFieldParamNames) !== null && _l !== void 0 ? _l : exports.defaultWafOptions.sortValidation.orderFieldParamNames),
            fieldNamePattern: ((_m = sortValidation.fieldNamePattern) !== null && _m !== void 0 ? _m : exports.defaultWafOptions.sortValidation.fieldNamePattern),
        },
        pathAllowlist: (Array.isArray(pathAllowlist) ? pathAllowlist : []),
        contentTypeSkipList: (Array.isArray(contentTypeSkipList) ? contentTypeSkipList : exports.defaultWafOptions.contentTypeSkipList),
        blockStatus: (_o = user === null || user === void 0 ? void 0 : user.blockStatus) !== null && _o !== void 0 ? _o : exports.defaultWafOptions.blockStatus,
        blockMessage: (_p = user === null || user === void 0 ? void 0 : user.blockMessage) !== null && _p !== void 0 ? _p : exports.defaultWafOptions.blockMessage,
        logger: (_q = user === null || user === void 0 ? void 0 : user.logger) !== null && _q !== void 0 ? _q : exports.defaultWafOptions.logger,
        mode: (_r = user === null || user === void 0 ? void 0 : user.mode) !== null && _r !== void 0 ? _r : exports.defaultWafOptions.mode,
        policyVersion: user === null || user === void 0 ? void 0 : user.policyVersion,
        rulesetVersion: (_s = user === null || user === void 0 ? void 0 : user.rulesetVersion) !== null && _s !== void 0 ? _s : ruleset_manifest_1.RULESET_VERSION,
        auditLogger: user === null || user === void 0 ? void 0 : user.auditLogger,
        metrics: user === null || user === void 0 ? void 0 : user.metrics,
        inspectionLimits: (0, limits_1.resolveInspectionLimits)(user === null || user === void 0 ? void 0 : user.inspectionLimits),
        queryDecode: {
            enabled: (_t = queryDecode.enabled) !== null && _t !== void 0 ? _t : false,
            maxRounds: (_u = queryDecode.maxRounds) !== null && _u !== void 0 ? _u : 2,
            htmlEntities: (_v = queryDecode.htmlEntities) !== null && _v !== void 0 ? _v : false,
            maxHtmlEntityRounds: (_w = queryDecode.maxHtmlEntityRounds) !== null && _w !== void 0 ? _w : 2,
            maxHtmlEntityExpansion: (_x = queryDecode.maxHtmlEntityExpansion) !== null && _x !== void 0 ? _x : 256,
        },
        pathTraversal: {
            enabled: (_y = pathTraversal.enabled) !== null && _y !== void 0 ? _y : false,
        },
        commandInjection: {
            enabled: (_z = commandInjection.enabled) !== null && _z !== void 0 ? _z : false,
        },
    };
}
function matchRoutePolicy(req, policy) {
    const { path, method } = req;
    const { match } = policy;
    const pathMatch = typeof match.path === 'string'
        ? path === match.path || path.startsWith(match.path + '/') || path.startsWith(match.path + '?')
        : match.path.test(path);
    if (!pathMatch)
        return false;
    if (match.method != null && match.method.toUpperCase() !== method.toUpperCase())
        return false;
    return true;
}
/**
 * Merge partial `WafOptions` onto an already-resolved config (route policies, `policyResolver`, etc.).
 * Nested options (sqlInjection, xss, sortValidation) are merged; primitives and arrays replaced.
 * Ignores `policies` and `policyResolver` keys if present on `overrides`.
 */
function mergeResolvedWafOptions(base, overrides) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s;
    if (!overrides || Object.keys(overrides).length === 0)
        return base;
    const { policies: _policies, policyResolver: _policyResolver } = overrides, o = __rest(overrides, ["policies", "policyResolver"]);
    if (Object.keys(o).length === 0)
        return base;
    const mergedXss = o.xss ? Object.assign(Object.assign({}, base.xss), o.xss) : base.xss;
    const mergedQueryDecode = o.queryDecode ? Object.assign(Object.assign({}, base.queryDecode), o.queryDecode) : base.queryDecode;
    const mergedPathTrav = o.pathTraversal ? Object.assign(Object.assign({}, base.pathTraversal), o.pathTraversal) : base.pathTraversal;
    const mergedCmd = o.commandInjection ? Object.assign(Object.assign({}, base.commandInjection), o.commandInjection) : base.commandInjection;
    return {
        sqlInjection: o.sqlInjection ? Object.assign(Object.assign({}, base.sqlInjection), o.sqlInjection) : base.sqlInjection,
        xss: mergedXss,
        sortValidation: o.sortValidation ? Object.assign(Object.assign({}, base.sortValidation), o.sortValidation) : base.sortValidation,
        pathAllowlist: (_a = o.pathAllowlist) !== null && _a !== void 0 ? _a : base.pathAllowlist,
        contentTypeSkipList: (_b = o.contentTypeSkipList) !== null && _b !== void 0 ? _b : base.contentTypeSkipList,
        blockStatus: (_c = o.blockStatus) !== null && _c !== void 0 ? _c : base.blockStatus,
        blockMessage: (_d = o.blockMessage) !== null && _d !== void 0 ? _d : base.blockMessage,
        logger: (_e = o.logger) !== null && _e !== void 0 ? _e : base.logger,
        mode: (_f = o.mode) !== null && _f !== void 0 ? _f : base.mode,
        policyVersion: (_g = o.policyVersion) !== null && _g !== void 0 ? _g : base.policyVersion,
        rulesetVersion: (_h = o.rulesetVersion) !== null && _h !== void 0 ? _h : base.rulesetVersion,
        auditLogger: (_j = o.auditLogger) !== null && _j !== void 0 ? _j : base.auditLogger,
        metrics: (_k = o.metrics) !== null && _k !== void 0 ? _k : base.metrics,
        inspectionLimits: o.inspectionLimits
            ? (0, limits_1.resolveInspectionLimits)(Object.assign(Object.assign({}, base.inspectionLimits), o.inspectionLimits))
            : base.inspectionLimits,
        queryDecode: {
            enabled: (_l = mergedQueryDecode.enabled) !== null && _l !== void 0 ? _l : false,
            maxRounds: (_m = mergedQueryDecode.maxRounds) !== null && _m !== void 0 ? _m : 2,
            htmlEntities: (_o = mergedQueryDecode.htmlEntities) !== null && _o !== void 0 ? _o : false,
            maxHtmlEntityRounds: (_p = mergedQueryDecode.maxHtmlEntityRounds) !== null && _p !== void 0 ? _p : 2,
            maxHtmlEntityExpansion: (_q = mergedQueryDecode.maxHtmlEntityExpansion) !== null && _q !== void 0 ? _q : 256,
        },
        pathTraversal: {
            enabled: (_r = mergedPathTrav.enabled) !== null && _r !== void 0 ? _r : false,
        },
        commandInjection: {
            enabled: (_s = mergedCmd.enabled) !== null && _s !== void 0 ? _s : false,
        },
    };
}
/**
 * Resolve effective options for a request by merging the first matching route policy over global options.
 * Use this when options.policies is set; otherwise use the single merged global options.
 */
function resolvePolicyForRequest(req, globalResolved, policies) {
    if (!(policies === null || policies === void 0 ? void 0 : policies.length))
        return globalResolved;
    const policy = policies.find((p) => matchRoutePolicy(req, p));
    if (!(policy === null || policy === void 0 ? void 0 : policy.overrides))
        return globalResolved;
    return mergeResolvedWafOptions(globalResolved, policy.overrides);
}
//# sourceMappingURL=config.js.map