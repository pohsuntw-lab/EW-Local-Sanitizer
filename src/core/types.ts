export type Severity = "low" | "medium" | "high" | "critical";
export type FindingType =
  | "private-key"
  | "api-token"
  | "credential"
  | "email"
  | "phone"
  | "taiwan-id"
  | "ip-address"
  | "exact-data";
export type Action = "delete" | "tokenize" | "generalize" | "keep";
export type Classification = "P0" | "P1" | "P2" | "P3";

export interface Finding {
  findingId: string;
  type: FindingType;
  severity: Severity;
  start: number;
  end: number;
  value: string;
  maskedPreview: string;
  detector: string;
}

export interface PublicFinding {
  finding_id: string;
  type: FindingType;
  severity: Severity;
  masked_preview: string;
  detector: string;
  action: Action;
  token?: string;
  reason?: string;
}

export interface Decision {
  findingId: string;
  action: Action;
  tokenLabel?: string;
  replacement?: string;
  reason?: string;
}

export interface TokenEntry {
  token: string;
  original: string;
  findingType: FindingType;
}

export interface TransformResult {
  sanitizedText: string;
  publicFindings: PublicFinding[];
  tokenEntries: TokenEntry[];
  unresolved: Finding[];
  residualRisk: number;
}

