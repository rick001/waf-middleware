/** Bounds for scanning body/query (DoS / latency protection). */
export interface InspectionLimits {
    maxStringLength: number;
    maxObjectDepth: number;
    maxObjectKeys: number;
}
/** Defaults for bounded inspection (DoS / latency protection). */
export declare const DEFAULT_INSPECTION_LIMITS: InspectionLimits;
export declare function resolveInspectionLimits(partial?: Partial<InspectionLimits>): InspectionLimits;
