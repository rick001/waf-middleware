/** Bounds for scanning body/query (DoS / latency protection). */
export interface InspectionLimits {
  maxStringLength: number;
  maxObjectDepth: number;
  maxObjectKeys: number;
}

/** Defaults for bounded inspection (DoS / latency protection). */
export const DEFAULT_INSPECTION_LIMITS: InspectionLimits = {
  maxStringLength: 10_000,
  maxObjectDepth: 20,
  maxObjectKeys: 500,
};

export function resolveInspectionLimits(partial?: Partial<InspectionLimits>): InspectionLimits {
  return {
    maxStringLength: partial?.maxStringLength ?? DEFAULT_INSPECTION_LIMITS.maxStringLength,
    maxObjectDepth: partial?.maxObjectDepth ?? DEFAULT_INSPECTION_LIMITS.maxObjectDepth,
    maxObjectKeys: partial?.maxObjectKeys ?? DEFAULT_INSPECTION_LIMITS.maxObjectKeys,
  };
}
