/**
 * Heuristic SQL injection detection.
 * - Skips password-like fields (no SQL keyword blocking; allow special chars).
 * - For email-like fields: only blocks obvious injection fragments, not "invalid email".
 * - For other values: multi-signal heuristics to avoid blocking "and", "or", "select" in normal text.
 */

import type { Sensitivity } from '../config';
import { DEFAULT_INSPECTION_LIMITS, type InspectionLimits } from '../limits';

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

function toStr(input: unknown): string {
  if (input == null) return '';
  if (typeof input === 'object') return JSON.stringify(input);
  return String(input).trim();
}

/**
 * Check only for obvious injection fragment in a value (e.g. email field).
 * Does NOT block on "invalid email" format.
 */
export function hasEmailInjectionFragment(value: unknown, maxStringLength = DEFAULT_INSPECTION_LIMITS.maxStringLength): boolean {
  const raw = toStr(value);
  if (!raw) return false;
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
export function looksLikeSqlInjection(
  input: unknown,
  sensitivity: Sensitivity,
  maxStringLength: number = DEFAULT_INSPECTION_LIMITS.maxStringLength
): boolean {
  const raw = toStr(input);
  if (!raw) return false;
  const s = raw.length > maxStringLength ? raw.slice(0, maxStringLength) : raw;

  // Single alphanumeric token (e.g. "and", "or", "select") or common sort values – allow to avoid false positives
  if (/^[a-zA-Z0-9_]+$/.test(s) && s.length < 20) return false;
  if (/^(asc|desc)$/i.test(s)) return false;

  for (const p of HIGH_CONFIDENCE_PATTERNS) {
    if (new RegExp(p.source, p.flags).test(s)) return true;
  }

  if (sensitivity === 'lenient') return false;

  const hasCommentOrQuote = /--|#|\/\*|'|"/.test(s);
  const keywordMatches = s.match(/\b(SELECT|FROM|WHERE|UNION|INSERT|DROP|TABLE|OR|AND)\b/gi);
  const hasMultipleKeywords = (keywordMatches?.length ?? 0) >= 2;
  const orAndEquality = /\b(OR|AND)\b\s*\d*\s*=\s*\d+/i.test(s);

  if (sensitivity === 'strict') {
    return (hasMultipleKeywords && hasCommentOrQuote) || orAndEquality;
  }
  // balanced
  return orAndEquality || (hasMultipleKeywords && hasCommentOrQuote);
}

export interface SqlInjectionRuleOptions {
  sensitivity: Sensitivity;
  skipBodyKeys: string[];
  /** Inspection bounds; defaults from DEFAULT_INSPECTION_LIMITS if omitted. */
  limits?: InspectionLimits;
}

export function checkQueryParams(
  query: Record<string, unknown>,
  sensitivity: Sensitivity,
  maxStringLength: number = DEFAULT_INSPECTION_LIMITS.maxStringLength
): boolean {
  for (const value of Object.values(query)) {
    if (value == null) continue;
    const str = Array.isArray(value) ? String(value[0]) : value;
    if (looksLikeSqlInjection(str, sensitivity, maxStringLength)) return true;
  }
  return false;
}

export function checkBody(
  body: Record<string, unknown>,
  opts: SqlInjectionRuleOptions
): { block: true } | { block: false } {
  const limits = opts.limits ?? DEFAULT_INSPECTION_LIMITS;
  const counters = { depth: 0, keys: 0 };
  return scanBodySql(body, opts, limits, counters);
}

function scanBodySql(
  body: Record<string, unknown>,
  opts: SqlInjectionRuleOptions,
  limits: InspectionLimits,
  counters: { depth: number; keys: number }
): { block: true } | { block: false } {
  if (counters.depth > limits.maxObjectDepth) return { block: false };

  for (const [key, value] of Object.entries(body)) {
    if (counters.keys >= limits.maxObjectKeys) return { block: false };
    counters.keys++;

    if (value == null) continue;
    if (shouldSkipBodyKey(key, opts.skipBodyKeys)) continue;

    const isEmailLike = /email|e-mail|mail/.test(key.toLowerCase());

    if (isEmailLike) {
      if (hasEmailInjectionFragment(value, limits.maxStringLength)) return { block: true };
      continue;
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
      if (looksLikeSqlInjection(value, opts.sensitivity, limits.maxStringLength)) return { block: true };
      continue;
    }

    if (typeof value === 'string') {
      if (looksLikeSqlInjection(value, opts.sensitivity, limits.maxStringLength)) return { block: true };
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        if (looksLikeSqlInjection(item, opts.sensitivity, limits.maxStringLength)) return { block: true };
      }
      continue;
    }

    if (typeof value === 'object') {
      counters.depth++;
      const nested = scanBodySql(value as Record<string, unknown>, opts, limits, counters);
      counters.depth--;
      if (nested.block) return { block: true };
    }
  }
  return { block: false };
}

function shouldSkipBodyKey(key: string, skipKeys: string[]): boolean {
  const lower = key.toLowerCase();
  return skipKeys.some(s => lower.includes(s.toLowerCase()));
}
