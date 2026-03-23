"use strict";
/**
 * Shared WAF inspection pipeline for Express middleware and Nest guards.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.runWafOnRequest = runWafOnRequest;
const rule_ids_1 = require("./rule-ids");
const utils_1 = require("./utils");
const sql_injection_1 = require("./rules/sql-injection");
const xss_1 = require("./rules/xss");
const sort_1 = require("./rules/sort");
const path_traversal_1 = require("./rules/path-traversal");
const command_injection_1 = require("./rules/command-injection");
/**
 * Run all enabled checks. Returns `true` if the request may proceed (`next()`), `false` if the response was ended (blocked).
 */
function runWafOnRequest(req, res, opts) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m;
    const pathAllowlist = (_a = opts.pathAllowlist) !== null && _a !== void 0 ? _a : [];
    if (pathAllowlist.length > 0 && (0, utils_1.isPathAllowlisted)(req.path, pathAllowlist)) {
        return true;
    }
    const limits = opts.inspectionLimits;
    let standardizedQuery = (0, utils_1.normalizeQuery)(req.query || {});
    if (opts.queryDecode.enabled) {
        const qd = opts.queryDecode;
        standardizedQuery = (0, utils_1.decodeQueryValues)(standardizedQuery, {
            maxUrlRounds: (_b = qd.maxRounds) !== null && _b !== void 0 ? _b : 2,
            htmlEntities: (_c = qd.htmlEntities) !== null && _c !== void 0 ? _c : false,
            maxHtmlEntityRounds: (_d = qd.maxHtmlEntityRounds) !== null && _d !== void 0 ? _d : 2,
            maxHtmlEntityExpansion: (_e = qd.maxHtmlEntityExpansion) !== null && _e !== void 0 ? _e : 256,
        });
    }
    if (opts.pathTraversal.enabled && (0, path_traversal_1.looksLikePathTraversal)(req.path)) {
        if (onViolation(req, res, opts, 'path_traversal', 'suspicious_path_segment'))
            return false;
    }
    if (opts.sortValidation.enabled) {
        const sortResult = (0, sort_1.checkSortValidation)(standardizedQuery, {
            sortParamNames: opts.sortValidation.sortParamNames,
            orderFieldParamNames: opts.sortValidation.orderFieldParamNames,
            fieldNamePattern: opts.sortValidation.fieldNamePattern,
        });
        if (sortResult.block) {
            if (onViolation(req, res, opts, sortResult.reason, 'invalid_sort_or_order_field'))
                return false;
        }
    }
    if (opts.sqlInjection.enabled) {
        const sensitivity = (_f = opts.sqlInjection.sensitivity) !== null && _f !== void 0 ? _f : 'balanced';
        if ((0, sql_injection_1.checkQueryParams)(standardizedQuery, sensitivity, limits.maxStringLength)) {
            if (onViolation(req, res, opts, 'sql_injection', 'query_signal'))
                return false;
        }
        const body = req.body;
        if (body && typeof body === 'object' && !(0, utils_1.shouldSkipBodyScan)((0, utils_1.getContentType)(req), opts.contentTypeSkipList)) {
            const bodyResult = (0, sql_injection_1.checkBody)(body, {
                sensitivity: (_g = opts.sqlInjection.sensitivity) !== null && _g !== void 0 ? _g : 'balanced',
                skipBodyKeys: (_h = opts.sqlInjection.skipBodyKeys) !== null && _h !== void 0 ? _h : [],
                limits,
            });
            if (bodyResult.block) {
                if (onViolation(req, res, opts, 'sql_injection', 'body_signal'))
                    return false;
            }
        }
    }
    if (opts.commandInjection.enabled) {
        if ((0, command_injection_1.checkCommandInjectionQuery)(standardizedQuery, limits.maxStringLength)) {
            if (onViolation(req, res, opts, 'command_injection', 'query_signal'))
                return false;
        }
        const body = req.body;
        if (body && typeof body === 'object' && !(0, utils_1.shouldSkipBodyScan)((0, utils_1.getContentType)(req), opts.contentTypeSkipList)) {
            if ((0, command_injection_1.checkCommandInjectionBody)(body, (_j = opts.sqlInjection.skipBodyKeys) !== null && _j !== void 0 ? _j : [], limits)) {
                if (onViolation(req, res, opts, 'command_injection', 'body_signal'))
                    return false;
            }
        }
    }
    if (opts.xss.enabled) {
        const body = req.body;
        const skipBody = (0, utils_1.shouldSkipBodyScan)((0, utils_1.getContentType)(req), opts.contentTypeSkipList);
        const xssHit = (0, xss_1.checkQueryAndBody)(standardizedQuery, skipBody ? undefined : body, {
            allowlistedBodyKeys: (_k = opts.xss.allowlistedBodyKeys) !== null && _k !== void 0 ? _k : [],
            limits,
        });
        if (xssHit) {
            if (opts.mode === 'sanitize' &&
                !skipBody &&
                body &&
                typeof body === 'object' &&
                !Array.isArray(body) &&
                opts.xss.richHtmlBodyKeys.length > 0 &&
                typeof opts.xss.sanitizeHtml === 'function') {
                const changed = (0, xss_1.sanitizeRichHtmlFieldsInBody)(body, opts.xss.richHtmlBodyKeys, opts.xss.sanitizeHtml, limits);
                const stillBad = (0, xss_1.checkQueryAndBody)(standardizedQuery, body, {
                    allowlistedBodyKeys: (_l = opts.xss.allowlistedBodyKeys) !== null && _l !== void 0 ? _l : [],
                    limits,
                });
                if (changed) {
                    audit(opts, req, {
                        action: 'sanitize',
                        rule: 'xss',
                        reason: 'rich_html_sanitized',
                    });
                    (_m = opts.metrics) === null || _m === void 0 ? void 0 : _m.increment('waf_sanitize_total', { rule: 'xss' });
                }
                if (!stillBad) {
                    return true;
                }
            }
            if (onViolation(req, res, opts, 'xss', 'xss_signal'))
                return false;
        }
    }
    return true;
}
/** @returns true if request should be stopped (blocked); false if only monitored (still allow). */
function onViolation(req, res, opts, rule, reason) {
    var _a;
    (_a = opts.metrics) === null || _a === void 0 ? void 0 : _a.increment('waf_signal_total', { rule, mode: opts.mode });
    if (opts.mode === 'monitor') {
        audit(opts, req, { action: 'monitor', rule, reason });
        return false;
    }
    block(req, res, rule, opts);
    return true;
}
function audit(opts, req, partial) {
    if (!opts.auditLogger)
        return;
    const event = Object.assign(Object.assign({}, partial), { ruleId: (0, rule_ids_1.ruleIdForRuleName)(partial.rule), mode: opts.mode, method: req.method, path: req.path, policyVersion: opts.policyVersion, rulesetVersion: opts.rulesetVersion, requestId: (0, utils_1.getRequestId)(req), clientIp: (0, utils_1.getClientIp)(req) });
    opts.auditLogger(event);
}
function block(req, res, rule, opts) {
    var _a;
    (_a = opts.metrics) === null || _a === void 0 ? void 0 : _a.increment('waf_block_total', { rule });
    if (opts.logger) {
        opts.logger(rule, { method: req.method, path: req.path });
    }
    audit(opts, req, { action: 'block', rule, reason: 'request_rejected' });
    res.status(opts.blockStatus).json({ message: opts.blockMessage });
}
