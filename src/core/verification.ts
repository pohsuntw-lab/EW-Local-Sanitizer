import { createHash } from "node:crypto";
import { detectText, type DetectionContext } from "./detectors.js";
import { isAuthenticDictionarySnapshot } from "./dictionary.js";
import { assertSessionFileCount, isAuthenticSource, sourceHashStillMatches, type PlainTextSource } from "./intake.js";
import { PLAIN_TEXT_POLICY_VERSION, isBlockingSeverity, routeAllowed } from "./policy.js";
import { isAuthenticTransformation } from "./transform.js";
import type { AllowedRoute, Classification, PublicFinding, TransformResult, UnresolvedItem } from "./types.js";

export interface VerificationItem {
  source: PlainTextSource;
  transformation: TransformResult;
}

export interface VerificationRequest {
  projectId: string;
  classification: Classification;
  allowedRoute: AllowedRoute;
  humanConfirmed: boolean;
  tokenMapCreated: boolean;
  items: readonly VerificationItem[];
  detection: DetectionContext;
}

interface VerifiedPayload extends VerificationRequest {
  verifiedAt: string;
  secondScanBlockingFindings: 0;
}

export interface VerifiedPackageData {
  readonly projectId: string;
  readonly classification: Exclude<Classification, "P3">;
  readonly allowedRoute: Exclude<AllowedRoute, "local-only">;
  readonly tokenMapCreated: boolean;
  readonly verifiedAt: string;
  readonly secondScanBlockingFindings: 0;
  readonly dictionary: { readonly version: string; readonly hash: string };
  readonly items: readonly {
    readonly source: { readonly sourceId: string; readonly originalHash: string; readonly coverage: "complete" };
    readonly derivative: {
      readonly sanitizedText: string;
      readonly publicFindings: readonly PublicFinding[];
      readonly residualRisk: number;
      readonly policyVersion: string;
    };
  }[];
}

declare const verifiedExportBrand: unique symbol;
export interface VerifiedExport { readonly [verifiedExportBrand]: true }

const verifiedCapabilities = new WeakSet<object>();
const verifiedStates = new WeakMap<object, { packageData: VerifiedPackageData; detection: DetectionContext }>();

export function verifiedPayloadForPackaging(capability: VerifiedExport): VerifiedPackageData {
  if (!verifiedCapabilities.has(capability)) throw new Error("Unverified export capability");
  const state = verifiedStates.get(capability);
  if (!state) throw new Error("Verified export payload unavailable");
  return state.packageData;
}

export function assertVerifiedPublicOutput(capability: VerifiedExport, value: string): void {
  if (!verifiedCapabilities.has(capability)) throw new Error("Unverified export capability");
  const state = verifiedStates.get(capability);
  if (!state) throw new Error("Verified export state unavailable");
  if (detectText(value, state.detection).some((finding) => isBlockingSeverity(finding.severity))) {
    throw new Error("Public output second scan found a blocking finding");
  }
}

export type VerificationOutcome =
  | { status: "verified"; capability: VerifiedExport; residualRisk: number }
  | { status: "blocked"; unresolved: UnresolvedItem[] };

export function verifyForExport(request: VerificationRequest): VerificationOutcome {
  assertSessionFileCount(request.items.length);
  const unresolved: UnresolvedItem[] = [];
  if (!isUuid(request.projectId)) throw new Error("Project ID must be a UUID");
  if (!isAuthenticDictionarySnapshot(request.detection.dictionary)) throw new Error("Untrusted dictionary snapshot");
  if (request.classification === "P3") unresolved.push({ code: "P3_LOCAL_ONLY" });
  else if (request.allowedRoute === "local-only" || !routeAllowed(request.classification, request.allowedRoute)) unresolved.push({ code: "ROUTE_NOT_ALLOWED" });
  if (request.classification === "P2" && !request.humanConfirmed) unresolved.push({ code: "HUMAN_CONFIRMATION_REQUIRED" });

  let residualRisk = 0;
  for (const item of request.items) {
    if (!isAuthenticSource(item.source) || item.source.coverage !== "complete" || item.source.policyVersion !== PLAIN_TEXT_POLICY_VERSION) {
      unresolved.push({ code: "COVERAGE_NOT_COMPLETE" });
    }
    if (!sourceHashStillMatches(item.source)) unresolved.push({ code: "SOURCE_HASH_CHANGED" });
    if (!isAuthenticTransformation(item.transformation)) unresolved.push({ code: "TRANSFORMATION_FAILED" });
    if (item.transformation.sourceTextHash !== hashText(item.source.text)) unresolved.push({ code: "TRANSFORMATION_FAILED" });
    if (
      item.transformation.policyVersion !== PLAIN_TEXT_POLICY_VERSION ||
      item.transformation.dictionaryVersion !== request.detection.dictionary.dictionaryVersion ||
      item.transformation.dictionaryHash !== request.detection.dictionary.dictionaryHash
    ) unresolved.push({ code: "SECOND_SCAN_FAILED" });
    unresolved.push(...item.transformation.unresolved);
    residualRisk += item.transformation.residualRisk;
    try {
      const secondScan = detectText(item.transformation.sanitizedText, request.detection);
      if (secondScan.some((finding) => isBlockingSeverity(finding.severity))) unresolved.push({ code: "SECOND_SCAN_BLOCKING_FINDING" });
      scanPublicReportFields(item.transformation.publicFindings, request.detection, unresolved);
    } catch {
      unresolved.push({ code: "SECOND_SCAN_FAILED" });
    }
  }
  if (unresolved.length > 0) return { status: "blocked", unresolved: deduplicate(unresolved) };
  return {
    status: "verified",
    capability: issueVerifiedExport({ ...request, verifiedAt: new Date().toISOString(), secondScanBlockingFindings: 0 }),
    residualRisk,
  };
}

function scanPublicReportFields(findings: readonly PublicFinding[], detection: DetectionContext, unresolved: UnresolvedItem[]): void {
  for (const finding of findings) {
    const fields = [finding.finding_id, finding.type, finding.severity, finding.masked_preview, finding.detector, finding.action,
      finding.token ?? "", finding.reason_code ?? "", finding.generalization_rule ?? ""];
    for (const field of fields) {
      if (detectText(field, detection).some((detected) => isBlockingSeverity(detected.severity))) {
        unresolved.push({ code: "SECOND_SCAN_BLOCKING_FINDING", findingId: finding.finding_id });
      }
    }
  }
  if (detectText(JSON.stringify(findings), detection).some((detected) => isBlockingSeverity(detected.severity))) {
    unresolved.push({ code: "SECOND_SCAN_BLOCKING_FINDING" });
  }
}

function deduplicate(items: UnresolvedItem[]): UnresolvedItem[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.code}:${item.findingId ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function issueVerifiedExport(payload: VerifiedPayload): VerifiedExport {
  const capability = Object.freeze({}) as VerifiedExport;
  const packageData = snapshotPackageData(payload);
  verifiedCapabilities.add(capability);
  verifiedStates.set(capability, { packageData, detection: Object.freeze({ dictionary: payload.detection.dictionary }) });
  return capability;
}

function snapshotPackageData(payload: VerifiedPayload): VerifiedPackageData {
  const items = payload.items.map((item) => Object.freeze({
    source: Object.freeze({ sourceId: item.source.sourceId, originalHash: item.source.originalHash, coverage: "complete" as const }),
    derivative: Object.freeze({
      sanitizedText: item.transformation.sanitizedText,
      publicFindings: Object.freeze(item.transformation.publicFindings.map((finding) => Object.freeze({ ...finding }))),
      residualRisk: item.transformation.residualRisk,
      policyVersion: item.transformation.policyVersion,
    }),
  }));
  return Object.freeze({
    projectId: payload.projectId,
    classification: payload.classification as Exclude<Classification, "P3">,
    allowedRoute: payload.allowedRoute as Exclude<AllowedRoute, "local-only">,
    tokenMapCreated: payload.tokenMapCreated,
    verifiedAt: payload.verifiedAt,
    secondScanBlockingFindings: 0,
    dictionary: Object.freeze({ version: payload.detection.dictionary.dictionaryVersion, hash: payload.detection.dictionary.dictionaryHash }),
    items: Object.freeze(items),
  });
}

function hashText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}
