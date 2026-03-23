/**
 * Heuristic command-injection signals in string input (secondary control).
 */
import type { InspectionLimits } from '../limits';
export declare function looksLikeCommandInjection(input: unknown, maxLen: number): boolean;
export declare function checkCommandInjectionQuery(query: Record<string, unknown>, maxStringLength: number): boolean;
export declare function checkCommandInjectionBody(body: Record<string, unknown>, skipKeys: string[], limits: InspectionLimits): boolean;
