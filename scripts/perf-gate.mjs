#!/usr/bin/env node
/**
 * Loose CI perf gate: many clean `runWafOnRequest` passes must finish within a wall-clock budget.
 * Tune with env: WAF_BENCH_ITERATIONS (default 4000), WAF_BENCH_MAX_MS (default 15000).
 * See docs/BENCHMARKS.md.
 */

import { performance } from 'node:perf_hooks';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { mergeOptions, runWafOnRequest } = require('../dist/index.js');

const iterations = Number(process.env.WAF_BENCH_ITERATIONS || 4000);
const maxMs = Number(process.env.WAF_BENCH_MAX_MS || 15000);

function makeReq(i) {
  return {
    method: 'GET',
    path: '/api/items',
    query: { page: String(i % 50), sort: 'asc' },
    body: undefined,
    get: () => undefined,
    socket: { remoteAddress: '127.0.0.1' },
  };
}

function makeRes() {
  return {
    _code: 200,
    status(c) {
      this._code = c;
      return this;
    },
    json() {
      /* noop */
    },
  };
}

const opts = mergeOptions({ mode: 'block' });

// Warmup
for (let i = 0; i < 200; i++) {
  runWafOnRequest(makeReq(i), makeRes(), opts);
}

const t0 = performance.now();
for (let i = 0; i < iterations; i++) {
  runWafOnRequest(makeReq(i), makeRes(), opts);
}
const ms = performance.now() - t0;

if (ms > maxMs) {
  console.error(
    `WAF perf gate FAILED: ${iterations} clean inspections in ${ms.toFixed(1)}ms (max ${maxMs}ms). Set WAF_BENCH_MAX_MS to adjust.`
  );
  process.exit(1);
}

const perSec = (iterations / (ms / 1000)).toFixed(0);
console.log(`WAF perf gate OK: ${iterations} iterations in ${ms.toFixed(1)}ms (~${perSec} req/s equivalent)`);
