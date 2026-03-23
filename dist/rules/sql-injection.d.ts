/**
 * Heuristic SQL injection detection.
 * - Skips password-like fields (no SQL keyword blocking; allow special chars).
 * - For email-like fields: only blocks obvious injection fragments, not "invalid email".
 * - For other values: multi-signal heuristics to avoid blocking "and", "or", "select" in normal text.
 */
import type { Sensitivity } from '../config';
import { type InspectionLimits } from '../limits';
/**
 * Check only for obvious injection fragment in a value (e.g. email field).
 * Does NOT block on "invalid email" format.
 */
export declare function hasEmailInjectionFragment(value: unknown, maxStringLength?: number): boolean;
/**
 * Heuristic: does the input look like SQL injection?
 * - strict: any high-confidence pattern, or (keyword + structure).
 * - balanced: high-confidence only, or two signals (e.g. keyword + comment/quote).
 * - lenient: only high-confidence patterns.
 */
export declare function looksLikeSqlInjection(input: unknown, sensitivity: Sensitivity, maxStringLength?: number): boolean;
export interface SqlInjectionRuleOptions {
    sensitivity: Sensitivity;
    skipBodyKeys: string[];
    /** Inspection bounds; defaults from DEFAULT_INSPECTION_LIMITS if omitted. */
    limits?: InspectionLimits;
}
export declare function checkQueryParams(query: Record<string, unknown>, sensitivity: Sensitivity, maxStringLength?: number): boolean;
export declare function checkBody(body: Record<string, unknown>, opts: SqlInjectionRuleOptions): {
    block: true;
} | {
    block: false;
};
