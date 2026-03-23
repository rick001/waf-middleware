"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeQuery = normalizeQuery;
exports.isPathAllowlisted = isPathAllowlisted;
exports.getContentType = getContentType;
exports.shouldSkipBodyScan = shouldSkipBodyScan;
exports.shouldSkipBodyKey = shouldSkipBodyKey;
exports.collectStringValues = collectStringValues;
exports.decodeUrlBounded = decodeUrlBounded;
exports.decodeHtmlEntitiesBounded = decodeHtmlEntitiesBounded;
exports.decodeQueryValues = decodeQueryValues;
exports.getClientIp = getClientIp;
exports.getRequestId = getRequestId;
/**
 * Normalize query: lowercase keys, remove empty string values.
 */
function normalizeQuery(query) {
    const out = {};
    for (const key of Object.keys(query)) {
        const v = query[key];
        if (v === '' || v === undefined)
            continue;
        out[key.toLowerCase()] = v;
    }
    return out;
}
/**
 * Check if request path is allowlisted (skip WAF).
 */
function isPathAllowlisted(path, allowlist) {
    if (!allowlist.length)
        return false;
    for (const entry of allowlist) {
        if (typeof entry === 'string') {
            if (path === entry || path.startsWith(entry + '/') || path.startsWith(entry + '?'))
                return true;
        }
        else {
            if (entry.test(path))
                return true;
        }
    }
    return false;
}
/**
 * Get request content-type (without charset etc).
 */
function getContentType(req) {
    const raw = req.get('content-type') || '';
    return raw.split(';')[0].trim().toLowerCase();
}
/**
 * Check if we should skip body scanning (e.g. multipart).
 */
function shouldSkipBodyScan(contentType, skipList) {
    return skipList.some(s => contentType.includes(s));
}
/**
 * Check if a body key should be skipped for a rule (e.g. password for SQLi).
 */
function shouldSkipBodyKey(key, skipKeys) {
    const lower = key.toLowerCase();
    return skipKeys.some(skip => lower.includes(skip.toLowerCase()));
}
/**
 * Recursively collect all string values from an object (for XSS scan).
 */
function collectStringValues(obj) {
    const out = [];
    if (obj === null || obj === undefined)
        return out;
    if (typeof obj === 'string') {
        out.push(obj);
        return out;
    }
    if (typeof obj === 'number' || typeof obj === 'boolean')
        return out;
    if (Array.isArray(obj)) {
        for (const item of obj)
            out.push(...collectStringValues(item));
        return out;
    }
    if (typeof obj === 'object') {
        for (const v of Object.values(obj))
            out.push(...collectStringValues(v));
    }
    return out;
}
/**
 * URL-decode a string up to maxRounds times (evasion hardening). Bounded work per value.
 */
function decodeUrlBounded(value, maxRounds) {
    let current = value;
    let prev = '';
    let rounds = 0;
    while (rounds < maxRounds && current !== prev) {
        prev = current;
        try {
            current = decodeURIComponent(current.replace(/\+/g, ' '));
        }
        catch (_a) {
            break;
        }
        rounds++;
    }
    return current;
}
/**
 * Decode common HTML/XML numeric and named entities (bounded). Used after URL decode for query evasion hardening.
 * Not a full HTML parser — only a small allowlist safe for injection heuristics.
 */
function decodeHtmlEntitiesBounded(value, maxRounds, maxExpansion) {
    let current = value;
    let rounds = 0;
    while (rounds < maxRounds) {
        const startLen = current.length;
        let next = decodeHtmlEntitiesOnce(current);
        if (next === current)
            break;
        if (next.length > startLen + maxExpansion)
            break;
        current = next;
        rounds++;
    }
    return current;
}
function decodeHtmlEntitiesOnce(input) {
    let s = input;
    // Numeric decimal &#39; &#00039;
    s = s.replace(/&#(\d{1,7});/g, (full, num) => {
        const code = parseInt(num, 10);
        if (code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff))
            return full;
        return String.fromCodePoint(code);
    });
    // Numeric hex &#x27; &#X0027;
    s = s.replace(/&#x([0-9a-f]{1,6});/gi, (full, hex) => {
        const code = parseInt(hex, 16);
        if (code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff))
            return full;
        return String.fromCodePoint(code);
    });
    // Named (decode &amp; last among these to handle &amp;lt;)
    const named = [
        [/&lt;/gi, '<'],
        [/&gt;/gi, '>'],
        [/&quot;/gi, '"'],
        [/&apos;/gi, "'"],
        [/&nbsp;/gi, ' '],
        [/&amp;/gi, '&'],
    ];
    for (const [re, ch] of named) {
        s = s.replace(re, ch);
    }
    return s;
}
/**
 * Apply bounded URL decode (and optional HTML entity decode) to string / string[] query values.
 */
function decodeQueryValues(query, opts) {
    const out = Object.assign({}, query);
    const { maxUrlRounds, htmlEntities, maxHtmlEntityRounds = 2, maxHtmlEntityExpansion = 256 } = opts;
    for (const key of Object.keys(out)) {
        const v = out[key];
        if (typeof v === 'string') {
            let decoded = decodeUrlBounded(v, maxUrlRounds);
            if (htmlEntities) {
                decoded = decodeHtmlEntitiesBounded(decoded, maxHtmlEntityRounds, maxHtmlEntityExpansion);
            }
            out[key] = decoded;
        }
        else if (Array.isArray(v) && typeof v[0] === 'string') {
            let decoded0 = decodeUrlBounded(v[0], maxUrlRounds);
            if (htmlEntities) {
                decoded0 = decodeHtmlEntitiesBounded(decoded0, maxHtmlEntityRounds, maxHtmlEntityExpansion);
            }
            out[key] = [decoded0, ...v.slice(1)];
        }
    }
    return out;
}
/** Client IP with common proxy headers (configure Express trust proxy when using X-Forwarded-For). */
function getClientIp(req) {
    var _a, _b, _c;
    const xff = req.get('x-forwarded-for');
    if (xff) {
        const first = (_a = xff.split(',')[0]) === null || _a === void 0 ? void 0 : _a.trim();
        if (first)
            return first;
    }
    return (_c = (_b = req.socket) === null || _b === void 0 ? void 0 : _b.remoteAddress) !== null && _c !== void 0 ? _c : undefined;
}
function getRequestId(req) {
    return (req.get('x-request-id') ||
        req.get('x-correlation-id') ||
        req.id);
}
//# sourceMappingURL=utils.js.map