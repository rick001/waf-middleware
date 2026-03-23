import { Request } from 'express';
/**
 * Normalize query: lowercase keys, remove empty string values.
 */
export declare function normalizeQuery(query: Record<string, unknown>): Record<string, unknown>;
/**
 * Check if request path is allowlisted (skip WAF).
 */
export declare function isPathAllowlisted(path: string, allowlist: (string | RegExp)[]): boolean;
/**
 * Get request content-type (without charset etc).
 */
export declare function getContentType(req: Request): string;
/**
 * Check if we should skip body scanning (e.g. multipart).
 */
export declare function shouldSkipBodyScan(contentType: string, skipList: string[]): boolean;
/**
 * Check if a body key should be skipped for a rule (e.g. password for SQLi).
 */
export declare function shouldSkipBodyKey(key: string, skipKeys: string[]): boolean;
/**
 * Recursively collect all string values from an object (for XSS scan).
 */
export declare function collectStringValues(obj: unknown): string[];
/**
 * URL-decode a string up to maxRounds times (evasion hardening). Bounded work per value.
 */
export declare function decodeUrlBounded(value: string, maxRounds: number): string;
export interface DecodeQueryOptions {
    maxUrlRounds: number;
    htmlEntities?: boolean;
    maxHtmlEntityRounds?: number;
    maxHtmlEntityExpansion?: number;
}
/**
 * Decode common HTML/XML numeric and named entities (bounded). Used after URL decode for query evasion hardening.
 * Not a full HTML parser — only a small allowlist safe for injection heuristics.
 */
export declare function decodeHtmlEntitiesBounded(value: string, maxRounds: number, maxExpansion: number): string;
/**
 * Apply bounded URL decode (and optional HTML entity decode) to string / string[] query values.
 */
export declare function decodeQueryValues(query: Record<string, unknown>, opts: DecodeQueryOptions): Record<string, unknown>;
/** Client IP with common proxy headers (configure Express trust proxy when using X-Forwarded-For). */
export declare function getClientIp(req: Request): string | undefined;
export declare function getRequestId(req: Request): string | undefined;
