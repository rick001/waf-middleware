/**
 * Lightweight path traversal / suspicious path segments (defense in depth).
 * Does not replace proper path canonicalization in static file handlers.
 */

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/,
  /%2e%2e(\/|%2f|%5c)/i,
  /\.\.%2f/i,
  /%2f\.\./i,
  /\\x2e\\x2e/i,
];

export function looksLikePathTraversal(path: string): boolean {
  if (!path || path.length > 8192) return false;
  return PATH_TRAVERSAL_PATTERNS.some((p) => p.test(path));
}
