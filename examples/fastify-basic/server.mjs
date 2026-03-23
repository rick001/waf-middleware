import Fastify from 'fastify';
import { createFastifyWafPreHandler } from '@rick001/http-waf-middleware';

const app = Fastify({ logger: true });

app.addHook(
  'preHandler',
  createFastifyWafPreHandler({
    sqlInjection: { enabled: true },
    queryDecode: { enabled: true, htmlEntities: true },
  })
);

app.get('/health', async () => ({ ok: true }));

const port = Number(process.env.PORT || 3002);
await app.listen({ port, host: '127.0.0.1' });
console.log(`Fastify + WAF on http://127.0.0.1:${port}`);
