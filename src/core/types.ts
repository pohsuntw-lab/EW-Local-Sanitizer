export type Severity = "low" | "medium" | "high" | "critical";
export type FindingType =
  | "private-key"
  | "api-token"
  | "credential"
  | "email"
  | "phone"
  | "taiwan-id"
  | "address"
  | "ip-address"
  | "bank-account"
  | "contract-id"
  | "exact-data"
  | "spreadsheet-formula";
export type Action = "delete" | "tokenize" | "generalize" | "keep";
export type Classification = "P0" | "P1" | "P2" | "P3";
export type AllowedRoute = "cloud-approved" | "cloud-sanitized" | "local-only";
export type CoverageStatus = "complete" | "incomplete" | "unknown";
export type ReasonCode = "PUBLICLY_APPROVED" | "OPERATIONAL_CONTEXT" | "LOW_SENSITIVITY_ACCEPTED";

export interface Finding {
  readonly findingId: string;
  readonly type: FindingType;
  readonly severity: Severity;
  readonly start: number;
  readonly end: number;
  readonly value: string;
  readonly maskedPreview: string;
  readonly detector: string;
}

export interface PublicFinding {
  finding_id: string;
  type: FindingType;
  severity: Severity;
  masked_preview: string;
  detector: string;
  action: Action;
  token?: string;
  reason_code?: ReasonCode;
  generalization_rule?: string;
}

export interface Decision {
  findingId: string;
  action: Action;
  tokenLabel?: string;
  generalizationRuleId?: string;
  reasonCode?: ReasonCode;
  localReasonDetail?: string;
}

export interface TokenEntry {
  token: string;
  original: string;
  normalizedOriginal: string;
  findingType: FindingType;
}

export type UnresolvedCode =
  | "MISSING_DECISION"
  | "HIGH_OR_CRITICAL_KEEP"
  | "FORCED_DELETE_REQUIRED"
  | "COVERAGE_NOT_COMPLETE"
  | "TRANSFORMATION_FAILED"
  | "SECOND_SCAN_FAILED"
  | "SECOND_SCAN_BLOCKING_FINDING"
  | "P3_LOCAL_ONLY"
  | "ROUTE_NOT_ALLOWED"
  | "SOURCE_HASH_CHANGED"
  | "ZIP_INSPECTION_FAILED"
  | "TOKEN_MAP_REQUIRED"
  | "HUMAN_CONFIRMATION_REQUIRED";

export interface UnresolvedItem {
  code: UnresolvedCode;
  findingId?: string;
}

export interface TransformResult {
  projectId: string;
  findingCount: number;
  sanitizedText: string;
  sourceTextHash: string;
  publicFindings: readonly PublicFinding[];
  tokenEntries: readonly TokenEntry[];
  unresolved: readonly UnresolvedItem[];
  residualRisk: number;
  policyVersion: string;
  dictionaryVersion: string;
  dictionaryHash: string;
}
