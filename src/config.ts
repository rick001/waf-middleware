/**
 * Configuration types and defaults for production-grade WAF middleware.
 */

import { resolveInspectionLimits, type InspectionLimits } from './limits';
import { RULESET_VERSION } from './ruleset-manifest';

export type Sensitivity = 'strict' | 'balanced' | 'lenient';

/** monitor = log only; sanitize = XSS rich fields may be sanitized; block = reject on match (default). */
export type WafMode = 'monitor' | 'sanitize' | 'block';

export interface WafAuditEvent {
  action: 'allow' | 'monitor' | 'sanitize' | 'block';
  rule: string;
  /** Stable id for dashboards / SIEM (see `ruleIdForRuleName`). */
  ruleId: string;
  reason: string;
  mode: WafMode;
  method: string;
  path: string;
  policyVersion?: string;
  /** Package ruleset revision (see `RULESET_VERSION` / `ruleset-manifest`). */
  rulesetVersion?: string;
  requestId?: string;
  clientIp?: string;
  field?: string;
}

export interface MetricsHooks {
  increment(name: string, labels?: Record<string, string>): void;
}

export interface QueryDecodeOptions {
  /** URL-decode query string values (bounded rounds) before SQLi/XSS/command checks. */
  enabled?: boolean;
  maxRounds?: number;
  /**
   * After URL decode, decode a bounded set of HTML entities (e.g. `&lt;`, `&#39;`, `&#x27;`) so
   * encoded injection fragments are visible to heuristics. Off by default; enable with `enabled: true`
   * when hardening against double-encoded query evasion.
   */
  htmlEntities?: boolean;
  /** Max entity decode passes per value (default 2). */
  maxHtmlEntityRounds?: number;
  /** Max extra characters added vs input length per pass (caps expansion; default 256). */
  maxHtmlEntityExpansion?: number;
}

export interface PathTraversalOptions {
  enabled?: boolean;
}

export interface CommandInjectionOptions {
  enabled?: boolean;
}

export interface SqlInjectionOptions {
  enabled?: boolean;
  sensitivity?: Sensitivity;
  /** Body keys that match these (substring, case-insensitive) skip SQLi checks (e.g. password). */
  skipBodyKeys?: string[];
}

export interface XssOptions {
  enabled?: boolean;
  /** Body keys that may contain HTML/scripts (e.g. 'content', 'bio') - skip XSS check for these. */
  allowlistedBodyKeys?: string[];
  /** Keys (substring match) for sanitize mode: run sanitizeHtml instead of blocking when XSS-like. */
  richHtmlBodyKeys?: string[];
  /** Server-side HTML sanitizer (e.g. sanitize-html). Required for meaningful sanitize mode on rich fields. */
  sanitizeHtml?: (value: string, fieldPath: string) => string;
}

export interface SortValidationOptions {
  enabled?: boolean;
  /** Query param names that are sort direction (e.g. sort, order). */
  sortParamNames?: string[];
  /** Query param names that are order/field names (e.g. order_field, orderBy). */
  orderFieldParamNames?: string[];
  /** Allowed pattern for field names (default allows letters, numbers, _, ., -). */
  fieldNamePattern?: RegExp;
}

/** Match condition for a route-level policy. First matching policy wins. */
export interface RoutePolicyMatch {
  /** Path: exact string, prefix (e.g. "/api"), or RegExp. */
  path: string | RegExp;
  /** Optional HTTP method (e.g. "GET", "POST"). Omit to match all methods. */
  method?: string;
}

/** Route-level policy: overrides and optional mode for a matching path/method. */
export interface RoutePolicy {
  match: RoutePolicyMatch;
  /** Per-route overrides; merged with global options. */
  overrides?: Partial<WafOptions>;
}

export interface WafOptions {
  sqlInjection?: SqlInjectionOptions;
  xss?: XssOptions;
  sortValidation?: SortValidationOptions;
  /** Paths that skip WAF (string prefix or RegExp). */
  pathAllowlist?: (string | RegExp)[];
  /** Content-Types for which body is not scanned (e.g. multipart/form-data). */
  contentTypeSkipList?: string[];
  blockStatus?: number;
  blockMessage?: string;
  /** Called when a request is blocked. reason: rule name; meta: safe request info (no body/query). */
  logger?: (reason: string, meta: { method: string; path: string }) => void;
  /** Route-level policies. First matching policy is merged over global options. */
  policies?: RoutePolicy[];
  /** Default block; use monitor to roll out without rejecting traffic. */
  mode?: WafMode;
  /** Included in audit logs for traceability across rule changes. */
  policyVersion?: string;
  /** Ruleset revision for SIEM (defaults to built-in `RULESET_VERSION`). */
  rulesetVersion?: string;
  /** Structured audit trail (monitor + block + sanitize). Prefer over logger for production. */
  auditLogger?: (event: WafAuditEvent) => void;
  /** Optional counters (Prometheus, Datadog, etc.) — no dependency bundled. */
  metrics?: MetricsHooks;
  /** Bounds for scanning body/query (DoS / latency protection). */
  inspectionLimits?: Partial<InspectionLimits>;
  queryDecode?: QueryDecodeOptions;
  pathTraversal?: PathTraversalOptions;
  commandInjection?: CommandInjectionOptions;
  /**
   * Per-request policy merge (after static `policies[]`). Use for multi-tenant or A/B flags.
   * Return partial options merged over route-resolved config. Keep work O(1); avoid heavy I/O.
   */
  policyResolver?: (req: PolicyRequestContext) => Partial<WafOptions> | undefined;
}

const DEFAULT_SORT_PARAM_NAMES = ['sort', 'order', 'sortorder', 'sort_order', 'dir', 'direction'];
const DEFAULT_ORDER_FIELD_PARAM_NAMES = ['order_field', 'orderby', 'order_by', 'field', 'sort_by', 'sortby'];

export const defaultWafOptions: Required<
  Omit<
    WafOptions,
    | 'pathAllowlist'
    | 'contentTypeSkipList'
    | 'logger'
    | 'policies'
    | 'auditLogger'
    | 'metrics'
    | 'policyVersion'
    | 'rulesetVersion'
    | 'inspectionLimits'
    | 'policyResolver'
  >
> &
  Pick<WafOptions, 'pathAllowlist' | 'contentTypeSkipList' | 'logger'> = {
  sqlInjection: {
    enabled: true,
    sensitivity: 'balanced',
    skipBodyKeys: ['password', 'passwordConfirm', 'currentPassword', 'newPassword', 'token', 'secret'],
  },
  xss: {
    enabled: true,
    allowlistedBodyKeys: [],
    richHtmlBodyKeys: [],
  },
  sortValidation: {
    enabled: true,
    sortParamNames: DEFAULT_SORT_PARAM_NAMES,
    orderFieldParamNames: DEFAULT_ORDER_FIELD_PARAM_NAMES,
    fieldNamePattern: /^[a-zA-Z0-9_.-]+$/,
  },
  pathAllowlist: [],
  contentTypeSkipList: ['multipart/form-data'],
  blockStatus: 403,
  blockMessage: 'Request blocked by security policy.',
  logger: undefined,
  mode: 'block',
  queryDecode: {
    enabled: false,
    maxRounds: 2,
    htmlEntities: false,
    maxHtmlEntityRounds: 2,
    maxHtmlEntityExpansion: 256,
  },
  pathTraversal: { enabled: false },
  commandInjection: { enabled: false },
};

export interface ResolvedXssOptions {
  enabled: boolean;
  allowlistedBodyKeys: string[];
  richHtmlBodyKeys: string[];
  sanitizeHtml?: (value: string, fieldPath: string) => string;
}

export interface ResolvedWafOptions {
  sqlInjection: Required<SqlInjectionOptions>;
  xss: ResolvedXssOptions;
  sortValidation: Required<SortValidationOptions>;
  pathAllowlist: (string | RegExp)[];
  contentTypeSkipList: string[];
  blockStatus: number;
  blockMessage: string;
  logger: ((reason: string, meta: { method: string; path: string }) => void) | undefined;
  mode: WafMode;
  policyVersion: string | undefined;
  rulesetVersion: string;
  auditLogger: ((event: WafAuditEvent) => void) | undefined;
  metrics: MetricsHooks | undefined;
  inspectionLimits: InspectionLimits;
  queryDecode: Required<QueryDecodeOptions>;
  pathTraversal: Required<PathTraversalOptions>;
  commandInjection: Required<CommandInjectionOptions>;
}

export function mergeOptions(user?: WafOptions): ResolvedWafOptions {
  const pathAllowlist = user?.pathAllowlist ?? defaultWafOptions.pathAllowlist;
  const contentTypeSkipList = user?.contentTypeSkipList ?? defaultWafOptions.contentTypeSkipList;
  const sqlInjection = { ...defaultWafOptions.sqlInjection, ...user?.sqlInjection };
  const xss = { ...defaultWafOptions.xss, ...user?.xss };
  const sortValidation = { ...defaultWafOptions.sortValidation, ...user?.sortValidation };
  const queryDecode = { ...defaultWafOptions.queryDecode, ...user?.queryDecode };
  const pathTraversal = { ...defaultWafOptions.pathTraversal, ...user?.pathTraversal };
  const commandInjection = { ...defaultWafOptions.commandInjection, ...user?.commandInjection };
  return {
    sqlInjection: {
      enabled: sqlInjection.enabled ?? true,
      sensitivity: sqlInjection.sensitivity ?? 'balanced',
      skipBodyKeys: (sqlInjection.skipBodyKeys ?? defaultWafOptions.sqlInjection.skipBodyKeys) as string[],
    },
    xss: {
      enabled: xss.enabled ?? true,
      allowlistedBodyKeys: (xss.allowlistedBodyKeys ?? []) as string[],
      richHtmlBodyKeys: (xss.richHtmlBodyKeys ?? []) as string[],
      sanitizeHtml: xss.sanitizeHtml,
    },
    sortValidation: {
      enabled: sortValidation.enabled ?? true,
      sortParamNames: (sortValidation.sortParamNames ?? defaultWafOptions.sortValidation.sortParamNames) as string[],
      orderFieldParamNames: (sortValidation.orderFieldParamNames ?? defaultWafOptions.sortValidation.orderFieldParamNames) as string[],
      fieldNamePattern: (sortValidation.fieldNamePattern ?? defaultWafOptions.sortValidation.fieldNamePattern) as RegExp,
    },
    pathAllowlist: (Array.isArray(pathAllowlist) ? pathAllowlist : []) as (string | RegExp)[],
    contentTypeSkipList: (Array.isArray(contentTypeSkipList) ? contentTypeSkipList : defaultWafOptions.contentTypeSkipList) as string[],
    blockStatus: user?.blockStatus ?? defaultWafOptions.blockStatus,
    blockMessage: user?.blockMessage ?? defaultWafOptions.blockMessage,
    logger: user?.logger ?? defaultWafOptions.logger,
    mode: user?.mode ?? defaultWafOptions.mode,
    policyVersion: user?.policyVersion,
    rulesetVersion: user?.rulesetVersion ?? RULESET_VERSION,
    auditLogger: user?.auditLogger,
    metrics: user?.metrics,
    inspectionLimits: resolveInspectionLimits(user?.inspectionLimits),
    queryDecode: {
      enabled: queryDecode.enabled ?? false,
      maxRounds: queryDecode.maxRounds ?? 2,
      htmlEntities: queryDecode.htmlEntities ?? false,
      maxHtmlEntityRounds: queryDecode.maxHtmlEntityRounds ?? 2,
      maxHtmlEntityExpansion: queryDecode.maxHtmlEntityExpansion ?? 256,
    },
    pathTraversal: {
      enabled: pathTraversal.enabled ?? false,
    },
    commandInjection: {
      enabled: commandInjection.enabled ?? false,
    },
  };
}

/** Request-like shape for policy matching (no body/query). */
export interface RequestLike {
  method: string;
  path: string;
}

/** Extended context for `policyResolver` (e.g. `req.get('host')`, `x-tenant-id`). */
export interface PolicyRequestContext extends RequestLike {
  get?: (headerName: string) => string | undefined;
}

function matchRoutePolicy(req: RequestLike, policy: RoutePolicy): boolean {
  const { path, method } = req;
  const { match } = policy;
  const pathMatch =
    typeof match.path === 'string'
      ? path === match.path || path.startsWith(match.path + '/') || path.startsWith(match.path + '?')
      : match.path.test(path);
  if (!pathMatch) return false;
  if (match.method != null && match.method.toUpperCase() !== method.toUpperCase()) return false;
  return true;
}

/**
 * Merge partial `WafOptions` onto an already-resolved config (route policies, `policyResolver`, etc.).
 * Nested options (sqlInjection, xss, sortValidation) are merged; primitives and arrays replaced.
 * Ignores `policies` and `policyResolver` keys if present on `overrides`.
 */
export function mergeResolvedWafOptions(base: ResolvedWafOptions, overrides: Partial<WafOptions>): ResolvedWafOptions {
  if (!overrides || Object.keys(overrides).length === 0) return base;
  const { policies: _policies, policyResolver: _policyResolver, ...o } = overrides;
  if (Object.keys(o).length === 0) return base;
  const mergedXss = o.xss ? { ...base.xss, ...o.xss } : base.xss;
  const mergedQueryDecode = o.queryDecode ? { ...base.queryDecode, ...o.queryDecode } : base.queryDecode;
  const mergedPathTrav = o.pathTraversal ? { ...base.pathTraversal, ...o.pathTraversal } : base.pathTraversal;
  const mergedCmd = o.commandInjection ? { ...base.commandInjection, ...o.commandInjection } : base.commandInjection;
  return {
    sqlInjection: o.sqlInjection ? { ...base.sqlInjection, ...o.sqlInjection } : base.sqlInjection,
    xss: mergedXss,
    sortValidation: o.sortValidation ? { ...base.sortValidation, ...o.sortValidation } : base.sortValidation,
    pathAllowlist: o.pathAllowlist ?? base.pathAllowlist,
    contentTypeSkipList: o.contentTypeSkipList ?? base.contentTypeSkipList,
    blockStatus: o.blockStatus ?? base.blockStatus,
    blockMessage: o.blockMessage ?? base.blockMessage,
    logger: o.logger ?? base.logger,
    mode: o.mode ?? base.mode,
    policyVersion: o.policyVersion ?? base.policyVersion,
    rulesetVersion: o.rulesetVersion ?? base.rulesetVersion,
    auditLogger: o.auditLogger ?? base.auditLogger,
    metrics: o.metrics ?? base.metrics,
    inspectionLimits: o.inspectionLimits
      ? resolveInspectionLimits({ ...base.inspectionLimits, ...o.inspectionLimits })
      : base.inspectionLimits,
    queryDecode: {
      enabled: mergedQueryDecode.enabled ?? false,
      maxRounds: mergedQueryDecode.maxRounds ?? 2,
      htmlEntities: mergedQueryDecode.htmlEntities ?? false,
      maxHtmlEntityRounds: mergedQueryDecode.maxHtmlEntityRounds ?? 2,
      maxHtmlEntityExpansion: mergedQueryDecode.maxHtmlEntityExpansion ?? 256,
    },
    pathTraversal: {
      enabled: mergedPathTrav.enabled ?? false,
    },
    commandInjection: {
      enabled: mergedCmd.enabled ?? false,
    },
  };
}

/**
 * Resolve effective options for a request by merging the first matching route policy over global options.
 * Use this when options.policies is set; otherwise use the single merged global options.
 */
export function resolvePolicyForRequest(
  req: RequestLike,
  globalResolved: ResolvedWafOptions,
  policies: RoutePolicy[]
): ResolvedWafOptions {
  if (!policies?.length) return globalResolved;
  const policy = policies.find((p) => matchRoutePolicy(req, p));
  if (!policy?.overrides) return globalResolved;
  return mergeResolvedWafOptions(globalResolved, policy.overrides);
}
