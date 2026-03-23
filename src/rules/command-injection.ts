/**
 * Heuristic command-injection signals in string input (secondary control).
 */

import type { InspectionLimits } from '../limits';

const COMMAND_INJECTION_PATTERNS = [
  /;\s*(rm|wget|curl|bash|sh|nc|python|perl|ruby)\b/i,
  /\|\s*(rm|wget|curl|bash|sh|nc)\b/i,
  /`[^`]{0,200}`/,
  /\$\([^)]{0,200}\)/,
  /\b&&\s*(rm|curl|wget)\b/i,
];

export function looksLikeCommandInjection(input: unknown, maxLen: number): boolean {
  if (input == null) return false;
  const s = typeof input === 'string' ? input : typeof input === 'object' ? JSON.stringify(input) : String(input);
  if (!s) return false;
  const slice = s.length > maxLen ? s.slice(0, maxLen) : s;
  return COMMAND_INJECTION_PATTERNS.some((p) => p.test(slice));
}

function shouldSkipBodyKey(key: string, skipKeys: string[]): boolean {
  const lower = key.toLowerCase();
  return skipKeys.some((s) => lower.includes(s.toLowerCase()));
}

export function checkCommandInjectionQuery(
  query: Record<string, unknown>,
  maxStringLength: number
): boolean {
  for (const value of Object.values(query)) {
    if (value == null) continue;
    const str = Array.isArray(value) ? String(value[0]) : value;
    if (looksLikeCommandInjection(str, maxStringLength)) return true;
  }
  return false;
}

export function checkCommandInjectionBody(
  body: Record<string, unknown>,
  skipKeys: string[],
  limits: InspectionLimits
): boolean {
  const counters = { depth: 0, keys: 0 };
  return scanBody(body, skipKeys, limits, counters);
}

function scanBody(
  body: Record<string, unknown>,
  skipKeys: string[],
  limits: InspectionLimits,
  counters: { depth: number; keys: number }
): boolean {
  if (counters.depth > limits.maxObjectDepth) return false;
  for (const [key, value] of Object.entries(body)) {
    if (counters.keys >= limits.maxObjectKeys) return false;
    counters.keys++;
    if (value == null) continue;
    if (shouldSkipBodyKey(key, skipKeys)) continue;

    if (typeof value === 'string') {
      if (looksLikeCommandInjection(value, limits.maxStringLength)) return true;
      continue;
    }
    if (typeof value === 'number' || typeof value === 'boolean') {
      if (looksLikeCommandInjection(value, limits.maxStringLength)) return true;
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        if (looksLikeCommandInjection(item, limits.maxStringLength)) return true;
      }
      continue;
    }
    if (typeof value === 'object') {
      counters.depth++;
      const hit = scanBody(value as Record<string, unknown>, skipKeys, limits, counters);
      counters.depth--;
      if (hit) return true;
    }
  }
  return false;
}
