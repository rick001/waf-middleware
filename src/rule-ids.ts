/**
 * Stable rule identifiers for audit / SIEM (pair with policyVersion in config).
 */

export const RULE_IDS = {
  path_traversal: 'WAF-PATH-001',
  invalid_sort: 'WAF-SORT-001',
  invalid_order_field: 'WAF-SORT-002',
  sql_injection: 'WAF-SQL-001',
  command_injection: 'WAF-CMD-001',
  xss: 'WAF-XSS-001',
} as const;

export type WafRuleName = keyof typeof RULE_IDS;

export function ruleIdForRuleName(rule: string): string {
  if (rule in RULE_IDS) {
    return RULE_IDS[rule as WafRuleName];
  }
  return 'WAF-UNK-001';
}
