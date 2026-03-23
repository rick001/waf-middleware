/**
 * XSS heuristic: block values that look like script injection or event handlers.
 * - Scans only string values (not keys) to avoid blocking JSON keys like "onclick".
 * - Bounded traversal via InspectionLimits.
 */

import type { InspectionLimits } from '../limits';
import { DEFAULT_INSPECTION_LIMITS } from '../limits';

/** Script tag (any attributes). Lazy so .*? is non-greedy; use string search for reliability. */
const SCRIPT_OPEN = /<script[\s>]/i;
const SCRIPT_CLOSE = /<\/script\s*>/i;
/** javascript: protocol at start of string or after space/quote (executable context). */
const JAVASCRIPT_PROTOCOL = /(^|[\s'"=])javascript\s*:/gi;
/** Event handler attribute pattern: on\w+ = followed by quote or code. */
const EVENT_HANDLER = /on\w+\s*=\s*["']?\s*[a-zA-Z]/gi;

export function looksLikeXss(value: string): boolean {
  if (!value || typeof value !== 'string') return false;
  if (SCRIPT_OPEN.test(value) && SCRIPT_CLOSE.test(value)) return true;
  JAVASCRIPT_PROTOCOL.lastIndex = 0;
  if (JAVASCRIPT_PROTOCOL.test(value)) return true;
  EVENT_HANDLER.lastIndex = 0;
  if (EVENT_HANDLER.test(value)) return true;
  return false;
}

export interface XssRuleOptions {
  allowlistedBodyKeys: string[];
  limits?: InspectionLimits;
}

/**
 * Check all string values in query and body for XSS patterns.
 * Keys are not scanned (so "onclick" as a key does not trigger).
 */
export function checkQueryAndBody(
  query: Record<string, unknown>,
  body: unknown,
  opts: XssRuleOptions
): boolean {
  const limits = opts.limits ?? DEFAULT_INSPECTION_LIMITS;
  const stringsToCheck: string[] = [];
  const counters = { depth: 0, keys: 0 };

  for (const v of Object.values(query)) {
    if (stringsToCheck.length >= limits.maxObjectKeys) break;
    if (typeof v === 'string') {
      stringsToCheck.push(v.length > limits.maxStringLength ? v.slice(0, limits.maxStringLength) : v);
    } else if (Array.isArray(v) && typeof v[0] === 'string') {
      const s = v[0];
      stringsToCheck.push(s.length > limits.maxStringLength ? s.slice(0, limits.maxStringLength) : s);
    }
  }

  if (body && typeof body === 'object' && !Array.isArray(body)) {
    collectStringsFromBody(body as Record<string, unknown>, opts.allowlistedBodyKeys, limits, counters, stringsToCheck);
  }

  return stringsToCheck.some((s) => looksLikeXss(s));
}

function collectStringsFromBody(
  obj: Record<string, unknown>,
  allowlistedKeys: string[],
  limits: InspectionLimits,
  counters: { depth: number; keys: number },
  out: string[]
): void {
  if (counters.depth > limits.maxObjectDepth) return;
  if (out.length >= limits.maxObjectKeys) return;

  for (const [key, value] of Object.entries(obj)) {
    if (out.length >= limits.maxObjectKeys) return;
    if (counters.keys >= limits.maxObjectKeys) return;
    counters.keys++;

    const keyLower = key.toLowerCase();
    if (allowlistedKeys.some((a) => keyLower.includes(a.toLowerCase()))) continue;

    if (typeof value === 'string') {
      out.push(value.length > limits.maxStringLength ? value.slice(0, limits.maxStringLength) : value);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (out.length >= limits.maxObjectKeys) return;
        if (typeof item === 'string') {
          out.push(item.length > limits.maxStringLength ? item.slice(0, limits.maxStringLength) : item);
        } else if (item && typeof item === 'object') {
          counters.depth++;
          collectStringsFromBody(item as Record<string, unknown>, allowlistedKeys, limits, counters, out);
          counters.depth--;
        }
      }
    } else if (value && typeof value === 'object' && !(value instanceof Date)) {
      counters.depth++;
      collectStringsFromBody(value as Record<string, unknown>, allowlistedKeys, limits, counters, out);
      counters.depth--;
    }
  }
}

function keyMatchesRichHtml(key: string, richHtmlBodyKeys: string[]): boolean {
  const lower = key.toLowerCase();
  return richHtmlBodyKeys.some((p) => lower.includes(p.toLowerCase()));
}

/**
 * In-place: for keys matching richHtmlBodyKeys, replace string values with sanitizeHtml output.
 * Returns true if any field was modified.
 */
export function sanitizeRichHtmlFieldsInBody(
  body: Record<string, unknown>,
  richHtmlBodyKeys: string[],
  sanitizeHtml: (value: string, fieldPath: string) => string,
  limits: InspectionLimits
): boolean {
  if (!richHtmlBodyKeys.length) return false;
  const counters = { depth: 0, keys: 0 };
  return walkSanitize(body, '', richHtmlBodyKeys, sanitizeHtml, limits, counters);
}

function walkSanitize(
  obj: Record<string, unknown>,
  pathPrefix: string,
  richHtmlBodyKeys: string[],
  sanitizeHtml: (value: string, fieldPath: string) => string,
  limits: InspectionLimits,
  counters: { depth: number; keys: number }
): boolean {
  if (counters.depth > limits.maxObjectDepth) return false;
  let changed = false;

  for (const [key, value] of Object.entries(obj)) {
    if (counters.keys >= limits.maxObjectKeys) break;
    counters.keys++;

    const fieldPath = pathPrefix ? `${pathPrefix}.${key}` : key;

    if (typeof value === 'string' && keyMatchesRichHtml(key, richHtmlBodyKeys)) {
      if (looksLikeXss(value)) {
        const next = sanitizeHtml(value, fieldPath);
        if (next !== value) {
          obj[key] = next;
          changed = true;
        }
      }
      continue;
    }

    if (value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof Date)) {
      counters.depth++;
      if (walkSanitize(value as Record<string, unknown>, fieldPath, richHtmlBodyKeys, sanitizeHtml, limits, counters)) {
        changed = true;
      }
      counters.depth--;
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const item = value[i];
        if (typeof item === 'string' && keyMatchesRichHtml(key, richHtmlBodyKeys)) {
          if (looksLikeXss(item)) {
            const next = sanitizeHtml(item, `${fieldPath}[${i}]`);
            if (next !== item) {
              (value as unknown[])[i] = next;
              changed = true;
            }
          }
        } else if (item && typeof item === 'object' && !(item instanceof Date)) {
          counters.depth++;
          if (
            walkSanitize(item as Record<string, unknown>, `${fieldPath}[${i}]`, richHtmlBodyKeys, sanitizeHtml, limits, counters)
          ) {
            changed = true;
          }
          counters.depth--;
        }
      }
    }
  }
  return changed;
}
