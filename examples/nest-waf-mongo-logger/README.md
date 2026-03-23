# Nest + WAF + Mongo Logger

This example combines:

- `http-waf-middleware` via `WafModule` + `WafPolicyGuard`
- `api-logger-mongodb` via `createApiLoggerMiddleware`

It enriches Mongo rows using:

- `getUserInfo(req)` for user/tenant fields
- `transformLog(entry)` for trace and security metadata

## Run

```bash
cd examples/nest-waf-mongo-logger
npm install
npm run build
MONGO_URI="mongodb://127.0.0.1:27017" npm start
```

## Try requests

```bash
# normal
curl -i http://127.0.0.1:3004/health

# enriched user context
curl -i -X POST http://127.0.0.1:3004/search \
  -H "content-type: application/json" \
  -H "x-user-id: u_456" \
  -H "x-user-email: nest@example.com" \
  -H "x-user-role: admin" \
  -H "x-tenant-id: t_nest_01" \
  -H "x-request-id: req-nest-abc" \
  -d '{"query":"ultrabook"}'

# suspicious (blocked by WAF guard)
curl -i "http://127.0.0.1:3004/search?q=UNION%20SELECT%201"
```

## Notes

- This example uses `WafPolicyGuard` (not `WafMiddleware`) to support `@WafPolicy()` metadata.
- Logger middleware records request/response and custom enrichment fields to MongoDB.
