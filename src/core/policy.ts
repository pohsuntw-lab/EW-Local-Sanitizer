import type { AllowedRoute, Classification, FindingType, ReasonCode, Severity } from "./types.js";

export const CONTENT_POLICY_VERSION = "ew-content-policy-0.2";
export const PLAIN_TEXT_POLICY_VERSION = CONTENT_POLICY_VERSION;
export const MAX_PLAIN_TEXT_BYTES = 10 * 1024 * 1024;
export const MAX_SESSION_FILES = 100;
export const MAX_SESSION_TOTAL_BYTES = 100 * 1024 * 1024;
export const MAX_ZIP_ENTRY_BYTES = 16 * 1024 * 1024;
export const MAX_SAFE_PACKAGE_BYTES = 128 * 1024 * 1024;
export const MAX_SAFE_PACKAGE_ENTRIES = MAX_SESSION_FILES + 3;
export const MAX_DETECTION_TEXT_BYTES = MAX_ZIP_ENTRY_BYTES;
export const MAX_FINDINGS_PER_FILE = 10_000;
export const MAX_SESSION_FINDINGS = 50_000;
export const MAX_DICTIONARY_ENTRIES = 5_000;
export const MAX_DICTIONARY_ALIASES_PER_ENTRY = 16;
export const MAX_DICTIONARY_TERMS = 10_000;
export const MAX_DICTIONARY_TERM_CHARS = 256;
export const MAX_DICTIONARY_TOTAL_CHARS = 1024 * 1024;
export const MAX_TABULAR_ROWS = 100_000;
export const MAX_TABULAR_COLUMNS = 1_000;
export const MAX_TABULAR_CELLS = 1_000_000;
export const MAX_TABULAR_CELL_CHARS = 1_000_000;

export const CONTROLLED_REASON_CODES = new Set<ReasonCode>([
  "PUBLICLY_APPROVED",
  "OPERATIONAL_CONTEXT",
  "LOW_SENSITIVITY_ACCEPTED",
]);

export const DEFAULT_TOKEN_LABELS: Readonly<Record<FindingType, string>> = {
  "private-key": "SECRET",
  "api-token": "SECRET",
  credential: "SECRET",
  email: "EMAIL",
  phone: "PHONE",
  "taiwan-id": "PERSON",
  address: "ADDRESS",
  "ip-address": "HOST",
  "bank-account": "BANK",
  "contract-id": "CONTRACT",
  "exact-data": "ENTITY",
  "spreadsheet-formula": "FORMULA",
};

export const ALLOWED_TOKEN_LABELS = new Set([
  "EMAIL",
  "PHONE",
  "PERSON",
  "ADDRESS",
  "HOST",
  "BANK",
  "CONTRACT",
  "ENTITY",
  "CUSTOMER",
  "SUPPLIER",
  "EMPLOYEE",
  "PROJECT",
  "PRODUCT",
  "FACILITY",
]);

export interface GeneralizationRule {
  id: string;
  findingTypes: readonly FindingType[];
  replacement: string;
}

export const GENERALIZATION_RULES: Readonly<Record<string, GeneralizationRule>> = {
  IP_PRIVATE_NETWORK: { id: "IP_PRIVATE_NETWORK", findingTypes: ["ip-address"], replacement: "[PRIVATE NETWORK]" },
  CONTACT_REDACTED: { id: "CONTACT_REDACTED", findingTypes: ["email", "phone"], replacement: "[CONTACT REDACTED]" },
  COMMERCIAL_IDENTIFIER: {
    id: "COMMERCIAL_IDENTIFIER",
    findingTypes: ["bank-account", "contract-id"],
    replacement: "[COMMERCIAL IDENTIFIER]",
  },
  FORMULA_AS_LITERAL: {
    id: "FORMULA_AS_LITERAL",
    findingTypes: ["spreadsheet-formula"],
    replacement: "'",
  },
};

export function isBlockingSeverity(severity: Severity): boolean {
  return severity === "high" || severity === "critical";
}

export function assertSessionFindingCount(count: number): void {
  if (!Number.isSafeInteger(count) || count < 0 || count > MAX_SESSION_FINDINGS) {
    throw new Error("Session exceeds 50,000-finding policy limit");
  }
}

export function routeAllowed(classification: Classification, route: AllowedRoute): boolean {
  if (classification === "P3") return route === "local-only";
  if (classification === "P0") return route === "cloud-approved" || route === "cloud-sanitized";
  return route === "cloud-sanitized";
}

export function validateTokenLabel(label: string): void {
  if (!/^[A-Z][A-Z0-9_-]{1,31}$/.test(label) || !ALLOWED_TOKEN_LABELS.has(label)) {
    throw new Error("Token label is not an approved controlled value");
  }
}
