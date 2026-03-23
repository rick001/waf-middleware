/**
 * Shared WAF inspection pipeline for Express middleware and Nest guards.
 */
import { Request, Response } from 'express';
import type { ResolvedWafOptions } from './config';
/**
 * Run all enabled checks. Returns `true` if the request may proceed (`next()`), `false` if the response was ended (blocked).
 */
export declare function runWafOnRequest(req: Request, res: Response, opts: ResolvedWafOptions): boolean;
