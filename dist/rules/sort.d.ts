/**
 * Sort and order-field validation.
 * - Only applies to explicitly allowlisted param names (no substring match).
 * - Field names can contain letters, numbers, _, ., - by default.
 */
export interface SortValidationRuleOptions {
    sortParamNames: string[];
    orderFieldParamNames: string[];
    fieldNamePattern: RegExp;
}
export declare function checkSortValidation(query: Record<string, unknown>, opts: SortValidationRuleOptions): {
    block: true;
    reason: string;
} | {
    block: false;
};
