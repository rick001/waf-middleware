/**
 * Sort and order-field validation.
 * - Only applies to explicitly allowlisted param names (no substring match).
 * - Field names can contain letters, numbers, _, ., - by default.
 */

const VALID_SORT_VALUES = ['ASC', 'DESC'];

export interface SortValidationRuleOptions {
  sortParamNames: string[];
  orderFieldParamNames: string[];
  fieldNamePattern: RegExp;
}

export function checkSortValidation(
  query: Record<string, unknown>,
  opts: SortValidationRuleOptions
): { block: true; reason: string } | { block: false } {
  const q = query as Record<string, unknown>;
  const sortNames = new Set(opts.sortParamNames.map(s => s.toLowerCase()));
  const fieldNames = new Set(opts.orderFieldParamNames.map(s => s.toLowerCase()));

  for (const [key, value] of Object.entries(q)) {
    const keyLower = key.toLowerCase();

    if (sortNames.has(keyLower)) {
      const v = Array.isArray(value) ? value[0] : value;
      const str = v != null ? String(v).trim().toUpperCase() : '';
      if (str && !VALID_SORT_VALUES.includes(str)) {
        return { block: true, reason: 'invalid_sort' };
      }
    }

    if (fieldNames.has(keyLower)) {
      const v = Array.isArray(value) ? value[0] : value;
      const str = v != null ? String(v).trim() : '';
      if (str && !opts.fieldNamePattern.test(str)) {
        return { block: true, reason: 'invalid_order_field' };
      }
    }
  }

  return { block: false };
}
