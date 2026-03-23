# Benchmarks (methodology)

Production WAF-style middleware should add **predictable** CPU and memory overhead. This document defines how to measure it; numbers are environment-specific—run locally before trusting.

## What to measure

- **Latency**: p50 / p95 / p99 of request time with middleware **on** vs **off** (same route, same payload sizes).
- **Throughput**: requests/sec under load (e.g. `autocannon` or `k6`) with empty vs large JSON bodies.
- **Worst case**: deeply nested JSON hitting `inspectionLimits.maxObjectDepth` / `maxObjectKeys`; strings at `maxStringLength`.

## Suggested commands

```bash
# Example with autocannon (install globally or npx)
npx autocannon -c 50 -d 10 http://localhost:3000/health
```

Compare two builds of the same app: one without `WafMiddleware`, one with default options and one with `mode: 'monitor'`.

## Configuration knobs

- Lower `inspectionLimits` for hot paths.
- Use `pathAllowlist` for static/health routes.
- Use `mode: 'monitor'` while validating false-positive rate.

## Targets (guidelines, not guarantees)

- Aim for **&lt; 1 ms p95** added latency on small JSON payloads on typical hardware.
- If p99 grows with body size, ensure `contentTypeSkipList` and body parser limits align (Express `limit` option).

## CI perf gate (library)

The repo runs a **very loose** synthetic gate so catastrophic regressions fail CI:

```bash
npm run bench:ci
```

It executes thousands of in-process `runWafOnRequest` calls on clean synthetic requests. Tune with:

- `WAF_BENCH_ITERATIONS` (default `4000`)
- `WAF_BENCH_MAX_MS` (default `15000`)

This does **not** replace real app benchmarks (autocannon/k6) from your own services.
