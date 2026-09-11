import { detectText, type DetectionContext } from "./detectors.js";
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

const verifiedCapabilities = new WeakSet<VerifiedExport>();
const verifiedPayloads = new WeakMap<VerifiedExport, VerifiedPayload>();

export class VerifiedExport {
  private constructor(payload: VerifiedPayload) { verifiedPayloads.set(this, snapshotPayload(payload)); }
  static issue(payload: VerifiedPayload): VerifiedExport {
    const result = new VerifiedExport(payload);
    verifiedCapabilities.add(result);
    Object.freeze(result);
    return result;
  }
}

export function verifiedPayloadForPackaging(capability: VerifiedExport): VerifiedPayload {
  if (!verifiedCapabilities.has(capability)) throw new Error("Unverified export capability");
  const payload = verifiedPayloads.get(capability);
  if (!payload) throw new Error("Verified export payload unavailable");
  return payload;
}

export type VerificationOutcome =
  | { status: "verified"; capability: VerifiedExport; residualRisk: number }
  | { status: "blocked"; unresolved: UnresolvedItem[] };

export function verifyForExport(request: VerificationRequest): VerificationOutcome {
  assertSessionFileCount(request.items.length);
  const unresolved: UnresolvedItem[] = [];
  if (!isUuid(request.projectId)) throw new Error("Project ID must be a UUID");
  if (request.classification === "P3" || request.allowedRoute === "local-only" || !routeAllowed(request.classification, request.allowedRoute)) {
    unresolved.push({ code: "P3_LOCAL_ONLY" });
  }
  if (request.classification === "P2" && !request.humanConfirmed) unresolved.push({ code: "HUMAN_CONFIRMATION_REQUIRED" });

  let residualRisk = 0;
  for (const item of request.items) {
    if (!isAuthenticSource(item.source) || item.source.coverage !== "complete" || item.source.policyVersion !== PLAIN_TEXT_POLICY_VERSION) {
      unresolved.push({ code: "COVERAGE_NOT_COMPLETE" });
    }
    if (!sourceHashStillMatches(item.source)) unresolved.push({ code: "SOURCE_HASH_CHANGED" });
    if (!isAuthenticTransformation(item.transformation)) unresolved.push({ code: "TRANSFORMATION_FAILED" });
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
    capability: VerifiedExport.issue({ ...request, verifiedAt: new Date().toISOString(), secondScanBlockingFindings: 0 }),
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

function snapshotPayload(payload: VerifiedPayload): VerifiedPayload {
  const items = payload.items.map((item) => Object.freeze({
    source: item.source,
    transformation: Object.freeze({
      ...item.transformation,
      publicFindings: Object.freeze(item.transformation.publicFindings.map((finding) => Object.freeze({ ...finding }))),
      tokenEntries: Object.freeze(item.transformation.tokenEntries.map((entry) => Object.freeze({ ...entry }))),
      unresolved: Object.freeze(item.transformation.unresolved.map((entry) => Object.freeze({ ...entry }))),
    }) as unknown as TransformResult,
  }));
  return Object.freeze({
    ...payload,
    items: Object.freeze(items),
    detection: Object.freeze({ dictionary: payload.detection.dictionary }),
  });
}
