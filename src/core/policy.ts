import type { AllowedRoute, Classification, FindingType, ReasonCode, Severity } from "./types.js";

export const PLAIN_TEXT_POLICY_VERSION = "ew-plaintext-policy-0.1";
export const MAX_PLAIN_TEXT_BYTES = 10 * 1024 * 1024;
export const MAX_SESSION_FILES = 100;
export const MAX_ZIP_ENTRY_BYTES = 16 * 1024 * 1024;

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
};

export function isBlockingSeverity(severity: Severity): boolean {
  return severity === "high" || severity === "critical";
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
