/**
 * Fastify `preHandler` hook factory — same pipeline as `WafMiddleware`.
 * Install **after** body parsers so `req.body` is populated when applicable.
 *
 * Peer dependency: `fastify` (^4 || ^5). Types here are structural; any compatible server works.
 */

import type { Request, Response } from 'express';
import { mergeOptions, mergeResolvedWafOptions, type WafOptions } from './config';
import { resolveEffectiveWafOptions } from './resolve-effective-options';
import { runWafOnRequest } from './waf-engine';

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
  socket?: { remoteAddress?: string | undefined };
}

export interface WafFastifyReply {
  code(statusCode: number): WafFastifyReply;
  send(payload?: unknown): unknown;
}

function pathFromUrl(url: string): string {
  const q = url.indexOf('?');
  return q >= 0 ? url.slice(0, q) : url || '/';
}

function getHeader(headers: Record<string, unknown>, name: string): string | undefined {
  const key = name.toLowerCase();
  const v = headers[key];
  if (typeof v === 'string') return v;
  if (Array.isArray(v) && typeof v[0] === 'string') return v[0];
  return undefined;
}

function toExpressLikeRequest(req: WafFastifyRequest, path: string): Request {
  return {
    method: req.method,
    path,
    query: req.query as Request['query'],
    body: req.body,
    get: (n: string) => getHeader(req.headers, n),
    socket: req.socket ?? { remoteAddress: req.ip },
    id: req.id,
  } as unknown as Request;
}

function toExpressLikeReply(reply: WafFastifyReply): Response {
  let code = 200;
  const res = {
    status(c: number) {
      code = c;
      return res;
    },
    json(payload: unknown) {
      reply.code(code).send(payload);
    },
  };
  return res as unknown as Response;
}

/**
 * Returns an async `preHandler` compatible with Fastify 4/5.
 * On block, the reply is sent and the hook returns without calling `done` (async style).
 */
export function createFastifyWafPreHandler(userOptions?: WafOptions): (req: WafFastifyRequest, reply: WafFastifyReply) => Promise<void> {
  const globalOptions = mergeOptions(userOptions);
  const policies = userOptions?.policies;
  const policyResolver = userOptions?.policyResolver;

  return async function wafPreHandler(req: WafFastifyRequest, reply: WafFastifyReply): Promise<void> {
    const path = pathFromUrl(req.url || '/');
    const opts = resolveEffectiveWafOptions(globalOptions, policies, policyResolver, {
      method: req.method,
      path,
      getHeader: (n) => getHeader(req.headers, n),
    });

    const fauxReq = toExpressLikeRequest(req, path);
    const fauxRes = toExpressLikeReply(reply);

    if (runWafOnRequest(fauxReq, fauxRes, opts)) {
      return;
    }
    /* Blocked: response already sent */
  };
}

/**
 * Merge extra `Partial<WafOptions>` (e.g. per-plugin overrides) then build a preHandler.
 * Rare; prefer global `WafOptions` + `policies` / `policyResolver`.
 */
export function createFastifyWafPreHandlerWithMerge(
  base: WafOptions | undefined,
  mergeBeforeRequest: (req: WafFastifyRequest) => Partial<WafOptions> | undefined
): (req: WafFastifyRequest, reply: WafFastifyReply) => Promise<void> {
  const globalOptions = mergeOptions(base);
  const policies = base?.policies;
  const policyResolver = base?.policyResolver;

  return async function wafPreHandler(req: WafFastifyRequest, reply: WafFastifyReply): Promise<void> {
    const path = pathFromUrl(req.url || '/');
    let opts = resolveEffectiveWafOptions(globalOptions, policies, policyResolver, {
      method: req.method,
      path,
      getHeader: (n) => getHeader(req.headers, n),
    });
    const extra = mergeBeforeRequest(req);
    if (extra && Object.keys(extra).length > 0) {
      opts = mergeResolvedWafOptions(opts, extra);
    }

    const fauxReq = toExpressLikeRequest(req, path);
    const fauxRes = toExpressLikeReply(reply);

    if (runWafOnRequest(fauxReq, fauxRes, opts)) {
      return;
    }
  };
}
