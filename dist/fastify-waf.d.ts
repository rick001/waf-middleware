/**
 * Fastify `preHandler` hook factory — same pipeline as `WafMiddleware`.
 * Install **after** body parsers so `req.body` is populated when applicable.
 *
 * Peer dependency: `fastify` (^4 || ^5). Types here are structural; any compatible server works.
 */
import { type WafOptions } from './config';
/** Subset of Fastify request used by the WAF (avoids hard dependency on `fastify` types). */
export interface WafFastifyRequest {
    method: string;
    /** Full URL path including query string prefix (e.g. `/items?page=1`). */
    url: string;
    query: Record<string, unknown>;
    body?: unknown;
    headers: Record<string, unknown>;
    /** Optional Fastify request id for audit correlation. */
    id?: string;
    ip?: string;
    socket?: {
        remoteAddress?: string | undefined;
    };
}
export interface WafFastifyReply {
    code(statusCode: number): WafFastifyReply;
    send(payload?: unknown): unknown;
}
/**
 * Returns an async `preHandler` compatible with Fastify 4/5.
 * On block, the reply is sent and the hook returns without calling `done` (async style).
 */
export declare function createFastifyWafPreHandler(userOptions?: WafOptions): (req: WafFastifyRequest, reply: WafFastifyReply) => Promise<void>;
/**
 * Merge extra `Partial<WafOptions>` (e.g. per-plugin overrides) then build a preHandler.
 * Rare; prefer global `WafOptions` + `policies` / `policyResolver`.
 */
export declare function createFastifyWafPreHandlerWithMerge(base: WafOptions | undefined, mergeBeforeRequest: (req: WafFastifyRequest) => Partial<WafOptions> | undefined): (req: WafFastifyRequest, reply: WafFastifyReply) => Promise<void>;
