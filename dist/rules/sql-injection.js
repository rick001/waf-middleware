"use strict";
/**
 * Heuristic SQL injection detection.
 * - Skips password-like fields (no SQL keyword blocking; allow special chars).
 * - For email-like fields: only blocks obvious injection fragments, not "invalid email".
 * - For other values: multi-signal heuristics to avoid blocking "and", "or", "select" in normal text.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.hasEmailInjectionFragment = hasEmailInjectionFragment;
exports.looksLikeSqlInjection = looksLikeSqlInjection;
exports.checkQueryParams = checkQueryParams;
exports.checkBody = checkBody;
const limits_1 = require("../limits");
/** High-confidence patterns: clear injection (quote + OR/AND + equality, comment, etc.). */
const HIGH_CONFIDENCE_PATTERNS = [
    /\bUNION\s+SELECT\b/gi,
    /\bINSERT\s+INTO\b/gi,
    /\bDELETE\s+FROM\b/gi,
    /\bDROP\s+TABLE\b/gi,
    /\bALTER\s+TABLE\b/gi,
    /\bUPDATE\s+SET\b/gi,
    /\bEXEC\s*\(|\bEXECUTE\s*\(/gi,
    /\bSLEEP\s*\(|\bWAITFOR\s+DELAY\b/gi,
    /'\s*OR\s*'?\d*'\s*=\s*'?\d*|"\s*OR\s*"?\d*"\s*=\s*"?\d*/gi,
    /'\s*AND\s*'?\d*'\s*=\s*'?\d*|"\s*AND\s*"?\d*"\s*=\s*"?\d*/gi,
    /\b(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/gi,
    /--\s*$|#\s*$|\/\*[\s\S]*\*\//g,
    /;\s*(DROP|DELETE|INSERT|UPDATE|ALTER)\b/gi,
    /* Backslash-hex obfuscation (e.g. \x53\x45\x4C in payload) – not literal word "select" */
    /\\x[0-9a-fA-F]{2}\s*\\x[0-9a-fA-F]{2}/g,
];
/** Fragment that indicates injection in email-like field (quote then OR/AND equality). */
const EMAIL_INJECTION_FRAGMENT = /['"]\s*(OR|AND)\s+['"]?\d*['"]?\s*=\s*['"]?\d*|--\s*$|;\s*(DROP|DELETE|INSERT)/gi;
function toStr(input) {
    if (input == null)
        return '';
    if (typeof input === 'object')
        return JSON.stringify(input);
    return String(input).trim();
}
/**
 * Check only for obvious injection fragment in a value (e.g. email field).
 * Does NOT block on "invalid email" format.
 */
function hasEmailInjectionFragment(value, maxStringLength = limits_1.DEFAULT_INSPECTION_LIMITS.maxStringLength) {
    const raw = toStr(value);
    if (!raw)
        return false;
    const s = raw.length > maxStringLength ? raw.slice(0, maxStringLength) : raw;
    EMAIL_INJECTION_FRAGMENT.lastIndex = 0;
    return EMAIL_INJECTION_FRAGMENT.test(s);
}
/**
 * Heuristic: does the input look like SQL injection?
 * - strict: any high-confidence pattern, or (keyword + structure).
 * - balanced: high-confidence only, or two signals (e.g. keyword + comment/quote).
 * - lenient: only high-confidence patterns.
 */
function looksLikeSqlInjection(input, sensitivity, maxStringLength = limits_1.DEFAULT_INSPECTION_LIMITS.maxStringLength) {
    var _a;
    const raw = toStr(input);
    if (!raw)
        return false;
    const s = raw.length > maxStringLength ? raw.slice(0, maxStringLength) : raw;
    // Single alphanumeric token (e.g. "and", "or", "select") or common sort values – allow to avoid false positives
    if (/^[a-zA-Z0-9_]+$/.test(s) && s.length < 20)
        return false;
    if (/^(asc|desc)$/i.test(s))
        return false;
    for (const p of HIGH_CONFIDENCE_PATTERNS) {
        if (new RegExp(p.source, p.flags).test(s))
            return true;
    }
    if (sensitivity === 'lenient')
        return false;
    const hasCommentOrQuote = /--|#|\/\*|'|"/.test(s);
    const keywordMatches = s.match(/\b(SELECT|FROM|WHERE|UNION|INSERT|DROP|TABLE|OR|AND)\b/gi);
    const hasMultipleKeywords = ((_a = keywordMatches === null || keywordMatches === void 0 ? void 0 : keywordMatches.length) !== null && _a !== void 0 ? _a : 0) >= 2;
    const orAndEquality = /\b(OR|AND)\b\s*\d*\s*=\s*\d+/i.test(s);
    if (sensitivity === 'strict') {
        return (hasMultipleKeywords && hasCommentOrQuote) || orAndEquality;
    }
    // balanced
    return orAndEquality || (hasMultipleKeywords && hasCommentOrQuote);
}
function checkQueryParams(query, sensitivity, maxStringLength = limits_1.DEFAULT_INSPECTION_LIMITS.maxStringLength) {
    for (const value of Object.values(query)) {
        if (value == null)
            continue;
        const str = Array.isArray(value) ? String(value[0]) : value;
        if (looksLikeSqlInjection(str, sensitivity, maxStringLength))
            return true;
    }
    return false;
}
function checkBody(body, opts) {
    var _a;
    const limits = (_a = opts.limits) !== null && _a !== void 0 ? _a : limits_1.DEFAULT_INSPECTION_LIMITS;
    const counters = { depth: 0, keys: 0 };
    return scanBodySql(body, opts, limits, counters);
}
function scanBodySql(body, opts, limits, counters) {
    if (counters.depth > limits.maxObjectDepth)
        return { block: false };
    for (const [key, value] of Object.entries(body)) {
        if (counters.keys >= limits.maxObjectKeys)
            return { block: false };
        counters.keys++;
        if (value == null)
            continue;
        if (shouldSkipBodyKey(key, opts.skipBodyKeys))
            continue;
        const isEmailLike = /email|e-mail|mail/.test(key.toLowerCase());
        if (isEmailLike) {
            if (hasEmailInjectionFragment(value, limits.maxStringLength))
                return { block: true };
            continue;
        }
        if (typeof value === 'number' || typeof value === 'boolean') {
            if (looksLikeSqlInjection(value, opts.sensitivity, limits.maxStringLength))
                return { block: true };
            continue;
        }
        if (typeof value === 'string') {
            if (looksLikeSqlInjection(value, opts.sensitivity, limits.maxStringLength))
                return { block: true };
            continue;
        }
        if (Array.isArray(value)) {
            for (const item of value) {
                if (looksLikeSqlInjection(item, opts.sensitivity, limits.maxStringLength))
                    return { block: true };
            }
            continue;
        }
        if (typeof value === 'object') {
            counters.depth++;
            const nested = scanBodySql(value, opts, limits, counters);
            counters.depth--;
            if (nested.block)
                return { block: true };
        }
    }
    return { block: false };
}
function shouldSkipBodyKey(key, skipKeys) {
    const lower = key.toLowerCase();
    return skipKeys.some(s => lower.includes(s.toLowerCase()));
}
