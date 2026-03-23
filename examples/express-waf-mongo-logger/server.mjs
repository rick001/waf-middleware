import express from 'express';
import { apiLoggerExpress } from 'api-logger-mongodb';
import { WafMiddleware } from '@rick001/http-waf-middleware';

const app = express();
app.use(express.json({ limit: '1mb' }));

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017';
const PORT = Number(process.env.PORT || 3003);

// Demo auth context so getUserInfo can enrich logs.
app.use((req, _res, next) => {
  req.user = {
    id: req.get('x-user-id') || 'anonymous',
    email: req.get('x-user-email') || undefined,
    role: req.get('x-user-role') || 'guest',
    tenant: req.get('x-tenant-id') || 'public',
  };
  next();
});

// WAF first: block/monitor before request/response logging to MongoDB.
app.use(
  new WafMiddleware({
    mode: 'block',
    policyVersion: 'example-1.0.0',
    rulesetVersion: '2026.03-example',
    queryDecode: { enabled: true, htmlEntities: true },
    sqlInjection: { enabled: true },
    xss: { enabled: true, allowlistedBodyKeys: ['content'] },
  }).use
);

// API logger second: store request/response with custom enrichment.
app.use(
  apiLoggerExpress({
    mongoUri: MONGO_URI,
    databaseName: 'waf_examples',
    collectionName: 'api_audit',
    logRequestBody: true,
    logResponseBody: true,
    maskFields: ['password', 'token', 'authorization'],
    getUserInfo: (req) => {
      const user = req.user || {};
      return {
        id: user.id,
        email: user.email,
        role: user.role,
        tenant: user.tenant,
      };
    },
    transformLog: (entry) => {
      const traceId = entry?.request?.headers?.['x-request-id'] || `trace-${Date.now()}`;
      return {
        ...entry,
        traceId,
        security: {
          waf: {
            package: '@rick001/http-waf-middleware',
            policyVersion: 'example-1.0.0',
            rulesetVersion: '2026.03-example',
          },
          logger: {
            package: 'api-logger-mongodb',
            collection: 'api_audit',
          },
        },
      };
    },
  })
);

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/search', (req, res) => {
  res.json({
    ok: true,
    query: req.body?.query || null,
  });
});

app.listen(PORT, () => {
  console.log(`Express + WAF + Mongo logger running on http://127.0.0.1:${PORT}`);
  console.log(`Mongo URI: ${MONGO_URI}`);
});
