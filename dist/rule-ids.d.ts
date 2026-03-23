/**
 * Stable rule identifiers for audit / SIEM (pair with policyVersion in config).
 */
export declare const RULE_IDS: {
    readonly path_traversal: "WAF-PATH-001";
    readonly invalid_sort: "WAF-SORT-001";
    readonly invalid_order_field: "WAF-SORT-002";
    readonly sql_injection: "WAF-SQL-001";
    readonly command_injection: "WAF-CMD-001";
    readonly xss: "WAF-XSS-001";
};
export type WafRuleName = keyof typeof RULE_IDS;
export declare function ruleIdForRuleName(rule: string): string;
