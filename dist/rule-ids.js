"use strict";
/**
 * Stable rule identifiers for audit / SIEM (pair with policyVersion in config).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RULE_IDS = void 0;
exports.ruleIdForRuleName = ruleIdForRuleName;
exports.RULE_IDS = {
    path_traversal: 'WAF-PATH-001',
    invalid_sort: 'WAF-SORT-001',
    invalid_order_field: 'WAF-SORT-002',
    sql_injection: 'WAF-SQL-001',
    command_injection: 'WAF-CMD-001',
    xss: 'WAF-XSS-001',
};
function ruleIdForRuleName(rule) {
    if (rule in exports.RULE_IDS) {
        return exports.RULE_IDS[rule];
    }
    return 'WAF-UNK-001';
}
//# sourceMappingURL=rule-ids.js.map