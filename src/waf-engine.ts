/**
 * Shared WAF inspection pipeline for Express middleware and Nest guards.
 */

import { Request, Response } from 'express';
import type { ResolvedWafOptions, WafAuditEvent } from './config';
import { ruleIdForRuleName } from './rule-ids';
import {
  normalizeQuery,
  isPathAllowlisted,
  getContentType,
  shouldSkipBodyScan,
  decodeQueryValues,
  getClientIp,
  getRequestId,
} from './utils';
import { checkQueryParams, checkBody } from './rules/sql-injection';
import { checkQueryAndBody, sanitizeRichHtmlFieldsInBody } from './rules/xss';
import { checkSortValidation } from './rules/sort';
import { looksLikePathTraversal } from './rules/path-traversal';
import { checkCommandInjectionQuery, checkCommandInjectionBody } from './rules/command-injection';

/**
 * Run all enabled checks. Returns `true` if the request may proceed (`next()`), `false` if the response was ended (blocked).
 */
export function runWafOnRequest(req: Request, res: Response, opts: ResolvedWafOptions): boolean {
  const pathAllowlist = opts.pathAllowlist ?? [];
  if (pathAllowlist.length > 0 && isPathAllowlisted(req.path, pathAllowlist)) {
    return true;
  }

  const limits = opts.inspectionLimits;
  let standardizedQuery = normalizeQuery((req.query as Record<string, unknown>) || {});
  if (opts.queryDecode.enabled) {
    const qd = opts.queryDecode;
    standardizedQuery = decodeQueryValues(standardizedQuery, {
      maxUrlRounds: qd.maxRounds ?? 2,
      htmlEntities: qd.htmlEntities ?? false,
      maxHtmlEntityRounds: qd.maxHtmlEntityRounds ?? 2,
      maxHtmlEntityExpansion: qd.maxHtmlEntityExpansion ?? 256,
    });
  }

  if (opts.pathTraversal.enabled && looksLikePathTraversal(req.path)) {
    if (onViolation(req, res, opts, 'path_traversal', 'suspicious_path_segment')) return false;
  }

  if (opts.sortValidation.enabled) {
    const sortResult = checkSortValidation(standardizedQuery, {
      sortParamNames: opts.sortValidation.sortParamNames,
      orderFieldParamNames: opts.sortValidation.orderFieldParamNames,
      fieldNamePattern: opts.sortValidation.fieldNamePattern,
    });
    if (sortResult.block) {
      if (onViolation(req, res, opts, sortResult.reason, 'invalid_sort_or_order_field')) return false;
    }
  }

  if (opts.sqlInjection.enabled) {
    const sensitivity = opts.sqlInjection.sensitivity ?? 'balanced';
    if (checkQueryParams(standardizedQuery, sensitivity, limits.maxStringLength)) {
      if (onViolation(req, res, opts, 'sql_injection', 'query_signal')) return false;
    }

    const body = req.body;
    if (body && typeof body === 'object' && !shouldSkipBodyScan(getContentType(req), opts.contentTypeSkipList)) {
      const bodyResult = checkBody(body as Record<string, unknown>, {
        sensitivity: opts.sqlInjection.sensitivity ?? 'balanced',
        skipBodyKeys: opts.sqlInjection.skipBodyKeys ?? [],
        limits,
      });
      if (bodyResult.block) {
        if (onViolation(req, res, opts, 'sql_injection', 'body_signal')) return false;
      }
    }
  }

  if (opts.commandInjection.enabled) {
    if (checkCommandInjectionQuery(standardizedQuery, limits.maxStringLength)) {
      if (onViolation(req, res, opts, 'command_injection', 'query_signal')) return false;
    }
    const body = req.body;
    if (body && typeof body === 'object' && !shouldSkipBodyScan(getContentType(req), opts.contentTypeSkipList)) {
      if (
        checkCommandInjectionBody(body as Record<string, unknown>, opts.sqlInjection.skipBodyKeys ?? [], limits)
      ) {
        if (onViolation(req, res, opts, 'command_injection', 'body_signal')) return false;
      }
    }
  }

  if (opts.xss.enabled) {
    const body = req.body;
    const skipBody = shouldSkipBodyScan(getContentType(req), opts.contentTypeSkipList);
    const xssHit = checkQueryAndBody(standardizedQuery, skipBody ? undefined : body, {
      allowlistedBodyKeys: opts.xss.allowlistedBodyKeys ?? [],
      limits,
    });
    if (xssHit) {
      if (
        opts.mode === 'sanitize' &&
        !skipBody &&
        body &&
        typeof body === 'object' &&
        !Array.isArray(body) &&
        opts.xss.richHtmlBodyKeys.length > 0 &&
        typeof opts.xss.sanitizeHtml === 'function'
      ) {
        const changed = sanitizeRichHtmlFieldsInBody(
          body as Record<string, unknown>,
          opts.xss.richHtmlBodyKeys,
          opts.xss.sanitizeHtml,
          limits
        );
        const stillBad = checkQueryAndBody(standardizedQuery, body, {
          allowlistedBodyKeys: opts.xss.allowlistedBodyKeys ?? [],
          limits,
        });
        if (changed) {
          audit(opts, req, {
            action: 'sanitize',
            rule: 'xss',
            reason: 'rich_html_sanitized',
          });
          opts.metrics?.increment('waf_sanitize_total', { rule: 'xss' });
        }
        if (!stillBad) {
          return true;
        }
      }
      if (onViolation(req, res, opts, 'xss', 'xss_signal')) return false;
    }
  }

  return true;
}

/** @returns true if request should be stopped (blocked); false if only monitored (still allow). */
function onViolation(
  req: Request,
  res: Response,
  opts: ResolvedWafOptions,
  rule: string,
  reason: string
): boolean {
  opts.metrics?.increment('waf_signal_total', { rule, mode: opts.mode });

  if (opts.mode === 'monitor') {
    audit(opts, req, { action: 'monitor', rule, reason });
    return false;
  }

  block(req, res, rule, opts);
  return true;
}

function audit(opts: ResolvedWafOptions, req: Request, partial: Pick<WafAuditEvent, 'action' | 'rule' | 'reason'>): void {
  if (!opts.auditLogger) return;
  const event: WafAuditEvent = {
    ...partial,
    ruleId: ruleIdForRuleName(partial.rule),
    mode: opts.mode,
    method: req.method,
    path: req.path,
    policyVersion: opts.policyVersion,
    rulesetVersion: opts.rulesetVersion,
    requestId: getRequestId(req),
    clientIp: getClientIp(req),
  };
  opts.auditLogger(event);
}

function block(req: Request, res: Response, rule: string, opts: ResolvedWafOptions): void {
  opts.metrics?.increment('waf_block_total', { rule });
  if (opts.logger) {
    opts.logger(rule, { method: req.method, path: req.path });
  }
  audit(opts, req, { action: 'block', rule, reason: 'request_rejected' });
  res.status(opts.blockStatus).json({ message: opts.blockMessage });
}
