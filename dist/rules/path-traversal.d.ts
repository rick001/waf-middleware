/**
 * Lightweight path traversal / suspicious path segments (defense in depth).
 * Does not replace proper path canonicalization in static file handlers.
 */
export declare function looksLikePathTraversal(path: string): boolean;
