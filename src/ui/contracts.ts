import type { Action, AllowedRoute, Classification, FindingType, ReasonCode, Severity, UnresolvedCode } from "../core/types.js";

export type OcrLanguage = "eng" | "chi_tra";
export interface ScanOptions {
  dictionaryTerms: string[];
  latinCaseSensitive: boolean;
  ocrLanguage: OcrLanguage;
  approveAllVisibleWorksheets: boolean;
}
export interface UiFinding {
  findingId: string;
  sourceId: string;
  type: FindingType;
  severity: Severity;
  maskedPreview: string;
  detector: string;
  allowedActions: Action[];
  generalizationRules: string[];
}
export interface UiSource { sourceId: string; displayName: string; format: string; coverage: string; findingCount: number }
export interface ScanResult { status: "ready"; sessionId: string; sources: UiSource[]; findings: UiFinding[] }
export interface UiDecision { findingId: string; action: Action; reasonCode?: ReasonCode; generalizationRuleId?: string }
export interface ExportOptions {
  sessionId: string;
  classification: Classification;
  allowedRoute: AllowedRoute;
  p2Confirmed: boolean;
  tokenMapPassphrase?: string;
  decisions: UiDecision[];
}
export type ExportResult =
  | { status: "exported"; packagePath: string; checksumPath: string; receiptPath: string; tokenMapPath?: string; packageHash: string; residualRisk: number }
  | { status: "blocked"; unresolved: UnresolvedCode[] }
  | { status: "cancelled" }
  | { status: "error"; code: "NO_SESSION" | "INVALID_REQUEST" | "PROCESSING_FAILED" | "OUTPUT_EXISTS" };
export type ScanResponse = ScanResult | { status: "cancelled" } | { status: "error"; code: "INVALID_REQUEST" | "PROCESSING_FAILED" };

export interface EwDesktopApi {
  pickAndScan(options: ScanOptions): Promise<ScanResponse>;
  exportReviewed(options: ExportOptions): Promise<ExportResult>;
  closeSession(): Promise<void>;
}
