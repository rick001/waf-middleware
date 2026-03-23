# Node WAF middleware

[![npm version](https://badge.fury.io/js/node-waf-middleware.svg)](https://www.npmjs.com/package/node-waf-middleware)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A **request hardening and input validation middleware** for **NestJS/Express.js**, with schema-friendly validation hooks, sanitization, suspicious-input detection, and security integrations. It helps detect and harden against malicious input patterns (including SQLi/XSS-like payloads), but it is **not** a complete defense on its own.

---

## Scope & Guarantees

- **What this middleware does**
  - **Validates and normalizes input** within configured policies.
  - **Rejects malformed or clearly malicious payloads** according to its heuristic and policy rules.
  - **Enforces size / type / pattern limits** where configured.
  - **Emits structured logs/metrics** for suspicious or blocked requests (when logging/metrics are wired in).

- **What this middleware does *not* replace**
  - **Parameterized queries / prepared statements** for SQL injection prevention. See the [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
  - **Context-aware output encoding and HTML sanitization** for XSS prevention. See the [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) and the [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
  - **Authentication, authorization, CSRF protection, rate limiting, security headers (e.g. CSP, HSTS), or TLS**.

Use this middleware as **one layer** in a broader defense-in-depth strategy, not as a standalone WAF.

---

## When To Use

- You run **public APIs** and want to reject obvious malicious payloads before controller/DB logic.
- You need a **safe rollout** path (`monitor` first, then `block`).
- You want **structured audit signals** (`rule`, `ruleId`, `mode`, versions) for incident triage.
- You need **per-route/per-request policy control** (`policies`, `policyResolver`) in multi-tenant apps.

## When Not To Use (alone)

- You need a **full edge WAF** (managed bot mitigation, DDoS scrubbing, geo/rate controls).
- You need guaranteed prevention without proper **parameterized queries** and output encoding.
- You expect this package to replace authN/authZ, CSP, CSRF, or rate limiting.

---

## Features

- **SQLi signal detection** – Heuristic patterns for obvious injection; does **not** replace parameterized queries. See [docs/ORM_EXAMPLES.md](docs/ORM_EXAMPLES.md).
- **XSS-like payload detection** – Flags `<script>`, `javascript:`, event-handler-like strings in values; optional sanitize path for rich HTML fields. Not a substitute for output encoding or CSP.
- **Sort & Field Validation** – Validates only allowlisted param names (e.g. `sort`, `order`, `order_field`); allows field names with dots and hyphens (e.g. `user.name`, `created-at`).
- **Configurable** – Enable/disable checks, path allowlist, sensitivity, custom block response, and optional logging.
- **No false positives on** – Passwords (any characters), emails (format not enforced; only obvious SQL fragments blocked), normal search/free text.

---

## Installation

```bash
npm install node-waf-middleware
# or
yarn add node-waf-middleware
```

---

## Usage

### Basic (NestJS)

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { WafMiddleware } from 'node-waf-middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(new WafMiddleware().use);
  await app.listen(3000);
}
bootstrap();
```

### Basic (Express)

```typescript
import express from 'express';
import { WafMiddleware } from 'node-waf-middleware';

const app = express();
const waf = new WafMiddleware();
app.use((req, res, next) => waf.use(req, res, next));
app.listen(3000);
```

### With options (production)

```typescript
import { WafMiddleware, WafOptions } from 'node-waf-middleware';

const options: WafOptions = {
  sqlInjection: {
    enabled: true,
    sensitivity: 'balanced', // 'strict' | 'balanced' | 'lenient'
    skipBodyKeys: ['password', 'passwordConfirm', 'token'],
  },
  xss: {
    enabled: true,
    allowlistedBodyKeys: ['content', 'bio'], // rich text fields
  },
  sortValidation: {
    enabled: true,
    sortParamNames: ['sort', 'order', 'dir'],
    orderFieldParamNames: ['order_field', 'orderBy', 'field'],
    fieldNamePattern: /^[a-zA-Z0-9_.-]+$/,
  },
  pathAllowlist: ['/health', '/webhooks'],
  contentTypeSkipList: ['multipart/form-data'],
  blockStatus: 403,
  blockMessage: 'Request blocked by security policy.',
  logger: (reason, meta) => console.warn(`WAF blocked [${reason}] ${meta.method} ${meta.path}`),
};

const waf = new WafMiddleware(options);
app.use((req, res, next) => waf.use(req, res, next));
```

### Production controls

| Option | Purpose |
|--------|---------|
| `mode` | `'block'` (default) — reject matches; `'monitor'` — log/metrics only; `'sanitize'` — run `sanitizeHtml` on `xss.richHtmlBodyKeys` when XSS-like, then re-check. |
| `policyVersion` | String included in `auditLogger` events (e.g. semver of your policy bundle). |
| `rulesetVersion` | Built-in ruleset revision for SIEM (defaults to `RULESET_VERSION` from the package; override for forked builds). |
| `auditLogger` | Structured `WafAuditEvent` (`action`, `rule`, `ruleId`, `reason`, `mode`, `method`, `path`, `policyVersion`, `rulesetVersion`, `requestId`, `clientIp`). |
| `metrics` | `{ increment(name, labels?) }` — e.g. map to Prometheus/Datadog in your app. |
| `inspectionLimits` | `maxStringLength`, `maxObjectDepth`, `maxObjectKeys` — caps traversal cost. |
| `queryDecode` | `{ enabled, maxRounds, htmlEntities?, maxHtmlEntityRounds?, maxHtmlEntityExpansion? }` — bounded URL decode; optional HTML entity decode after URL decode for encoded injection fragments. |
| `pathTraversal` | `{ enabled: true }` — reject suspicious `req.path` segments (`../`, encoded variants). |
| `commandInjection` | `{ enabled: true }` — heuristic shell/command patterns in query/body. |
| `xss.richHtmlBodyKeys` + `xss.sanitizeHtml` | For `mode: 'sanitize'`, sanitize rich HTML fields instead of only blocking. |

**Rollout:** start with `mode: 'monitor'`, wire `auditLogger` and `metrics`, then switch to `block` or `sanitize` when false positives are acceptable.

### Production rollout checklist

1. Start with `mode: 'monitor'` in production-like traffic.
2. Wire `auditLogger` and inspect top triggered rules/routes.
3. Add route overrides with `policies` / `policyResolver` where needed.
4. Tighten to `mode: 'block'` (or `sanitize` for rich HTML routes).
5. Re-check after each ruleset/policy update (`rulesetVersion`, `policyVersion`).

### False positive tuning checklist

- Lower impact on known-safe routes with `pathAllowlist` or route `policies`.
- Use `xss.allowlistedBodyKeys` / `xss.richHtmlBodyKeys` for rich text fields.
- Keep `sqlInjection.sensitivity` at `balanced` initially; tighten only if needed.
- Tune `inspectionLimits` to your payload profile (avoid excessive scan cost).
- Use schema validation first (DTO/Zod) to reduce noisy inputs before WAF checks.

### NestJS `WafModule`

```typescript
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { WafModule, WafMiddleware } from 'node-waf-middleware';

@Module({
  imports: [WafModule.forRoot({ mode: 'monitor', policyVersion: '1.0.0' /* ... */ })],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(WafMiddleware).forRoutes('*');
  }
}
```

### NestJS `@WafPolicy()` + `WafPolicyGuard`

`WafMiddleware` runs **before** the route is known, so it cannot read handler metadata. To merge `@WafPolicy()` overrides, register **`WafPolicyGuard`** (e.g. as `APP_GUARD`) and **do not** also apply `WafMiddleware` on the same traffic (you would double-scan).

```typescript
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { WafModule, WafPolicyGuard, WafPolicy } from 'node-waf-middleware';

@Module({
  imports: [WafModule.forRoot({ sqlInjection: { enabled: true } })],
  providers: [{ provide: APP_GUARD, useClass: WafPolicyGuard }],
})
export class AppModule {}

// controller
@Get('import')
@WafPolicy({ mode: 'monitor' })
importRows() { /* ... */ }
```

Path-only overrides without a guard: keep using `WafMiddleware` + `WafOptions.policies`.

### Fastify

```typescript
import Fastify from 'fastify';
import { createFastifyWafPreHandler } from 'node-waf-middleware';

const app = Fastify();
app.addHook('preHandler', createFastifyWafPreHandler({ sqlInjection: { enabled: true } }));
```

Details: [docs/FASTIFY.md](docs/FASTIFY.md). Optional peer: `fastify` (^4 || ^5).

### Examples

See [examples/README.md](examples/README.md) for minimal **Express**, **Nest**, and **Fastify** apps (`examples/express-basic`, `examples/nest-basic`, `examples/fastify-basic`).

### WAF + MongoDB API logging

Use this middleware **before** request/response logging so bad traffic is blocked (or monitored) first. Pair with **[`api-logger-mongodb`](https://www.npmjs.com/package/api-logger-mongodb)** and enrich Mongo documents via `getUserInfo` and `transformLog`:

| Stack | Example |
|-------|---------|
| Express | [examples/express-waf-mongo-logger](examples/express-waf-mongo-logger/README.md) |
| NestJS | [examples/nest-waf-mongo-logger](examples/nest-waf-mongo-logger/README.md) |

### Advanced

- **`runWafOnRequest(req, res, opts)`** — same pipeline as the middleware (for custom stacks).
- **`RULESET_VERSION`** — exported built-in ruleset id (also sent as `rulesetVersion` in audits unless overridden).

### Layered security stack (recommended)

1. **TLS**, secure cookies, **Helmet** (CSP, HSTS, etc.).
2. **DTO / schema validation** (`ValidationPipe`, Zod, …).
3. **Parameterized DB access** — see [docs/ORM_EXAMPLES.md](docs/ORM_EXAMPLES.md).
4. **Output encoding** / **HTML sanitization** when rendering user content.
5. **This middleware** — hardening, signals, optional blocks.
6. **Rate limiting** (`@nestjs/throttler`, `express-rate-limit`).

More detail: [docs/BENCHMARKS.md](docs/BENCHMARKS.md), [docs/FASTIFY.md](docs/FASTIFY.md).

### Schema validation first (recommended)

This middleware is intended to run **after** or **alongside** schema/DTO validation, not instead of it. Use your framework’s validator for required/optional fields, types, min/max length, enums, and nested shapes; use this layer for hardening and suspicious-input detection.

**NestJS:** Use `ValidationPipe` (e.g. globally) for DTO validation, then apply WAF so it sees already-validated payloads:

```typescript
// main.ts
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
app.use(new WafMiddleware(wafOptions).use);
```

**Express:** Run your schema validator first, then WAF. Use `createRequestHardeningStack` to combine them:

```typescript
import { createRequestHardeningStack } from 'node-waf-middleware';
import { z } from 'zod'; // or Yup, Joi, etc.

const bodySchema = z.object({ name: z.string().max(100), email: z.string().email() });
const schemaValidator = (req, res, next) => {
  const result = bodySchema.safeParse(req.body);
  if (!result.success) return res.status(400).json({ errors: result.error.flatten() });
  next();
};

app.use(createRequestHardeningStack({ wafOptions: { ... }, schemaValidator }));
```

### Per-request `policyResolver` (multi-tenant)

Runs **after** static `policies[]`. Return a partial `WafOptions` to merge for this request only (e.g. disable SQLi for a tenant, or force `monitor` on canary hosts).

```typescript
new WafMiddleware({
  policyResolver: (req) => {
    const tenant = req.get('x-tenant-id');
    if (tenant === 'legacy-import') {
      return { mode: 'monitor', sqlInjection: { enabled: false } };
    }
    return undefined;
  },
});
```

Use `mergeResolvedWafOptions` in tests or custom stacks if you build policy chains yourself.

### Route-level policies

You can override options per route (path and optional method). First matching policy is merged over global options. Use this to relax or skip checks for webhooks, uploads, or rich-text editors.

```typescript
const options: WafOptions = {
  pathAllowlist: ['/health'],
  policies: [
    { match: { path: '/webhooks/stripe', method: 'POST' }, overrides: { pathAllowlist: ['/webhooks/stripe'] } },
    { match: { path: '/admin/editor' }, overrides: { xss: { enabled: false, allowlistedBodyKeys: ['html'] } } },
    { match: { path: /^\/api\/v2\// }, overrides: { sqlInjection: { sensitivity: 'lenient' } } },
  ],
};
const waf = new WafMiddleware(options);
app.use((req, res, next) => waf.use(req, res, next));
```

---

## Security behavior

- **Passwords** – Body keys containing "password" (or names in `skipBodyKeys`) skip SQL injection checks so users can use any characters.
- **Emails** – WAF does not validate email format; it only blocks values that contain obvious SQL fragments (e.g. `' OR 1=1`).
- **Query/body** – Single alphanumeric tokens and common sort values (`asc`, `desc`) are allowed. High-confidence SQL patterns (e.g. `UNION SELECT`, `; DROP TABLE`, quote-based injection) are blocked.
- **Sort/order** – Only explicitly allowlisted param names are validated; field names can include `.` and `-` by default.

---

## Development

```bash
git clone https://github.com/rick001/waf-middleware.git
cd waf-middleware
npm install
npm run build
npm test
```

See [docs/ORM_EXAMPLES.md](docs/ORM_EXAMPLES.md), [docs/BENCHMARKS.md](docs/BENCHMARKS.md), [docs/FASTIFY.md](docs/FASTIFY.md), and [SECURITY.md](SECURITY.md).

---

## License

MIT. See [LICENSE](LICENSE).
