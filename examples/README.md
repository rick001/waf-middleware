# Examples

Runnable samples that depend on the parent package (`file:../..`). Build the library first:

```bash
cd /path/to/waf-middleware
npm run build
```

## Express (`express-basic`)

```bash
cd examples/express-basic
npm install
node server.cjs
# curl http://localhost:3000/health
```

## Nest (`nest-basic`)

Uses **`WafPolicyGuard`** as `APP_GUARD` (no global `WafMiddleware`) so `@WafPolicy()` on handlers is honored.

```bash
cd examples/nest-basic
npm install
npm run build
npm start
# curl http://localhost:3001/health
```

## Fastify (`fastify-basic`)

```bash
cd examples/fastify-basic
npm install
node server.mjs
# curl http://localhost:3002/health
```

See [docs/FASTIFY.md](../docs/FASTIFY.md).

## Express + Mongo logger (`express-waf-mongo-logger`)

Integrates `http-waf-middleware` with [`api-logger-mongodb`](https://www.npmjs.com/package/api-logger-mongodb), including log enrichment via `getUserInfo` and `transformLog`.

```bash
cd examples/express-waf-mongo-logger
npm install
MONGO_URI="mongodb://127.0.0.1:27017" node server.mjs
# curl http://localhost:3003/health
```

## Nest + Mongo logger (`nest-waf-mongo-logger`)

Integrates `WafPolicyGuard` (`http-waf-middleware`) with [`api-logger-mongodb`](https://www.npmjs.com/package/api-logger-mongodb) using `createApiLoggerMiddleware`, `getUserInfo`, and `transformLog`.

```bash
cd examples/nest-waf-mongo-logger
npm install
npm run build
MONGO_URI="mongodb://127.0.0.1:27017" npm start
# curl http://localhost:3004/health
```
