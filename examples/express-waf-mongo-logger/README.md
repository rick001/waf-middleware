# Express + WAF + Mongo Logger

This example integrates:

- `node-waf-middleware` for input hardening/blocking
- `api-logger-mongodb` for request/response logging to MongoDB

It demonstrates enriching Mongo rows via:

- `getUserInfo(req)` (user/tenant context)
- `transformLog(entry)` (trace/security metadata)

## Run

```bash
cd examples/express-waf-mongo-logger
npm install
MONGO_URI="mongodb://127.0.0.1:27017" node server.mjs
```

## Try requests

```bash
# normal request
curl -i http://127.0.0.1:3003/health

# request with enrichment headers
curl -i -X POST http://127.0.0.1:3003/search \
  -H "content-type: application/json" \
  -H "x-user-id: u_123" \
  -H "x-user-email: demo@example.com" \
  -H "x-user-role: admin" \
  -H "x-tenant-id: t_01" \
  -H "x-request-id: req-abc-123" \
  -d '{"query":"laptop"}'

# suspicious query (should be blocked by WAF)
curl -i "http://127.0.0.1:3003/search?q=UNION%20SELECT%201"
```

## Expected Mongo fields

Rows in `waf_examples.api_audit` include logger fields plus enrichment:

- `user.id`, `user.email`, `user.role`, `user.tenant` (from `getUserInfo`)
- `traceId` (from `transformLog`)
- `security.waf.policyVersion`, `security.waf.rulesetVersion`
- `security.logger.collection`
