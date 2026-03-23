/**
 * XSS heuristic: block values that look like script injection or event handlers.
 * - Scans only string values (not keys) to avoid blocking JSON keys like "onclick".
 * - Bounded traversal via InspectionLimits.
 */
import type { InspectionLimits } from '../limits';
export declare function looksLikeXss(value: string): boolean;
export interface XssRuleOptions {
    allowlistedBodyKeys: string[];
    limits?: InspectionLimits;
}
/**
 * Check all string values in query and body for XSS patterns.
 * Keys are not scanned (so "onclick" as a key does not trigger).
 */
export declare function checkQueryAndBody(query: Record<string, unknown>, body: unknown, opts: XssRuleOptions): boolean;
/**
 * In-place: for keys matching richHtmlBodyKeys, replace string values with sanitizeHtml output.
 * Returns true if any field was modified.
 */
export declare function sanitizeRichHtmlFieldsInBody(body: Record<string, unknown>, richHtmlBodyKeys: string[], sanitizeHtml: (value: string, fieldPath: string) => string, limits: InspectionLimits): boolean;
