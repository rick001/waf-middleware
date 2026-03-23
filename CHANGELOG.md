# Changelog

## [1.6.0] - 2026-03-23

### Changed

- **npm package renamed** to **`node-waf-middleware`**. Update imports: `from 'node-waf-middleware'`.
- Prior publish name was **`request-hardening-middleware`** (v1.5.0); before that **`waf-middleware-express`**.

## [1.5.0] - 2026-03-23

### Changed

- **npm package renamed** from `waf-middleware-express` to **`request-hardening-middleware`** (broader discoverability). Update imports: `from 'request-hardening-middleware'`.
- Expanded **`keywords`** in `package.json` for npm search.

## [1.4.0] - 2026-03-23

### Added

- **`createFastifyWafPreHandler`** / **`createFastifyWafPreHandlerWithMerge`** — Fastify `preHandler` with full option parity; optional peer `fastify` (^4 || ^5).
- **`resolveEffectiveWafOptions`** — shared `policies[]` + `policyResolver` resolution for Express/Fastify/custom adapters.
- **Evasion corpus tests** (`evasion-corpus.test.ts`) — SQLi/XSS/path/HTML-entity regression cases.
- **`npm run bench:ci`** + GitHub Actions **`bench`** job — loose in-process throughput gate (`scripts/perf-gate.mjs`).
- **`docs/FASTIFY.md`** and **`examples/fastify-basic`**.

## [1.3.0] - 2026-03-12

### Added

- **`rulesetVersion`** / **`RULESET_VERSION`** — manifest default plus optional override; included on every `WafAuditEvent`.
- **`queryDecode.htmlEntities`** (and expansion bounds) — bounded decode of common HTML entities on query values after URL decode.
- **`waf-engine`**: `runWafOnRequest()` shared by middleware and Nest guard.
- **`WafPolicyGuard`** — applies `@WafPolicy()` (class then handler) after `policies[]` + `policyResolver`; exported from `WafModule`.
- **`examples/`** — `express-basic` and `nest-basic` sample apps.
- **Supertest** integration tests; **HTML entity** unit tests.
- **`@nestjs/core`** dependency (for `Reflector` in the guard).
- **`experimentalDecorators` / `emitDecoratorMetadata`** in library `tsconfig` (Nest-style DI).

### Fixed

- **`policyResolver`** wired again on `WafMiddleware` (merge after route policies).

## [1.2.0] - 2026-03-12

### Added

- `policyResolver(req)` on `WafOptions` — per-request partial merge after static `policies[]` (multi-tenant / canary).
- `mergeResolvedWafOptions` exported for custom policy chains.
- `WafAuditEvent.ruleId` stable identifiers (`RULE_IDS`, `ruleIdForRuleName`).
- `PolicyRequestContext` for resolver typing.
- `SECURITY.md` and GitHub Actions CI (Node 18 / 20 / 22).
- Integration test (Express + real HTTP) and regression payload tests.

## [1.1.0] - 2026-03-12

### Added

- `mode`: `monitor` | `sanitize` | `block` for safe rollout and XSS sanitization on rich fields.
- `auditLogger(WafAuditEvent)` and `policyVersion`; optional `metrics.increment()`.
- `inspectionLimits` (max string length, object depth, key count) for bounded scans.
- `queryDecode` (bounded URL-decode of query values before checks).
- Opt-in `pathTraversal` and `commandInjection` heuristics on path / query / body.
- `xss.richHtmlBodyKeys` + `xss.sanitizeHtml` for sanitize mode.
- `WafModule.forRoot()` and `WafPolicy()` decorator (metadata).
- Docs: `ORM_EXAMPLES.md`, `BENCHMARKS.md`.
- Tests for path/command rules.

### Notes

- SQLi / XSS wording in README emphasizes **signals** and defense-in-depth; primary DB defense remains parameterized queries.

## [1.0.3] and earlier

See git history.
