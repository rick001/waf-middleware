# Fastify

The package exposes **`createFastifyWafPreHandler(options?)`**, an async `preHandler` hook with the same behavior as `WafMiddleware` (policies, `policyResolver`, `queryDecode`, etc.).

## Install

```bash
npm install node-waf-middleware fastify
```

`fastify` is an **optional peer** — only needed if you use this hook.

## Usage

Register **after** parsers (`@fastify/formbody`, `@fastify/multipart` as needed) so `request.body` is available.

```typescript
import Fastify from 'fastify';
import { createFastifyWafPreHandler } from 'node-waf-middleware';

const app = Fastify();
app.addHook('preHandler', createFastifyWafPreHandler({
  sqlInjection: { enabled: true },
  queryDecode: { enabled: true, htmlEntities: true },
}));

app.get('/health', async () => ({ ok: true }));
```

## Request shape

The hook accepts any object compatible with **`WafFastifyRequest`**: `method`, `url` (path + optional `?query`), `query`, `headers`, optional `body`, `id`, `ip`, `socket`.

Path inspection uses the pathname portion of `url` (before `?`), matching Express `req.path`.

## Per-request merge

Use **`createFastifyWafPreHandlerWithMerge(base, (req) => partial)`** when you must merge dynamic options from the Fastify request before checks (similar to `policyResolver`, but synchronous from the request object).

## Do not double-scan

If you attach this hook globally, avoid also running the Express `WafMiddleware` on the same server.
