import { createHash } from "node:crypto";
import { areAuthenticFindingsFor } from "./detectors.js";
import { isAuthenticDictionarySnapshot, type DictionarySnapshot } from "./dictionary.js";
import {
  CONTROLLED_REASON_CODES,
  DEFAULT_TOKEN_LABELS,
  GENERALIZATION_RULES,
  MAX_FINDINGS_PER_FILE,
  PLAIN_TEXT_POLICY_VERSION,
  isBlockingSeverity,
  validateTokenLabel,
} from "./policy.js";
import type { ProjectTokenRegistry } from "./token-vault.js";
import type { Decision, Finding, PublicFinding, TokenEntry, TransformResult, UnresolvedItem } from "./types.js";

const FORCED_DELETE = new Set(["private-key", "api-token", "credential"]);
const authenticTransformations = new WeakSet<TransformResult>();

export interface TransformContext {
  dictionary: DictionarySnapshot;
  tokenRegistry: ProjectTokenRegistry;
}

export function transformText(text: string, findings: Finding[], decisions: Decision[], context: TransformContext): TransformResult {
  if (!isAuthenticDictionarySnapshot(context.dictionary)) throw new Error("Untrusted dictionary snapshot");
  if (context.tokenRegistry.projectId() !== context.dictionary.projectId) throw new Error("Token registry and dictionary belong to different projects");
  if (findings.length > MAX_FINDINGS_PER_FILE) throw new Error("Finding limit exceeded; transformation coverage is incomplete");
  if (!areAuthenticFindingsFor(findings, text, context.dictionary)) throw new Error("Untrusted or mismatched findings");
  validateFindingRanges(text, findings);
  const decisionMap = new Map(decisions.map((decision) => [decision.findingId, decision]));
  if (decisionMap.size !== decisions.length) throw new Error("Duplicate finding decision");
  const findingIds = new Set(findings.map((finding) => finding.findingId));
  if (decisions.length > findings.length || decisions.some((decision) => !findingIds.has(decision.findingId))) {
    throw new Error("Decision does not reference a current finding");
  }
  const unresolved: UnresolvedItem[] = [];
  const publicFindings: PublicFinding[] = [];
  const tokenEntries: TokenEntry[] = [];
  let output = "";
  let cursor = 0;
  let residualRisk = 0;

  for (const finding of findings) {
    output += text.slice(cursor, finding.start);
    const decision = decisionMap.get(finding.findingId);
    if (!decision) {
      unresolved.push({ code: "MISSING_DECISION", findingId: finding.findingId });
      output += finding.value;
      cursor = finding.end;
      continue;
    }
    if (FORCED_DELETE.has(finding.type) && decision.action !== "delete") {
      throw new Error(`${finding.type} findings must be deleted`);
    }
    validateDecision(decision, finding);
    const applied = applyDecision(finding, decision, context);
    output += applied.replacement;
    cursor = finding.end;
    if (applied.tokenEntry) tokenEntries.push(applied.tokenEntry);
    if (decision.action === "keep") {
      residualRisk += 1;
      if (isBlockingSeverity(finding.severity)) unresolved.push({ code: "HIGH_OR_CRITICAL_KEEP", findingId: finding.findingId });
    }
    publicFindings.push({
      finding_id: finding.findingId,
      type: finding.type,
      severity: finding.severity,
      masked_preview: finding.maskedPreview,
      detector: finding.detector,
      action: decision.action,
      ...(applied.tokenEntry ? { token: applied.tokenEntry.token } : {}),
      ...(decision.reasonCode ? { reason_code: decision.reasonCode } : {}),
      ...(decision.generalizationRuleId ? { generalization_rule: decision.generalizationRuleId } : {}),
    });
  }
  output += text.slice(cursor);
  const result: TransformResult = Object.freeze({
    projectId: context.tokenRegistry.projectId(),
    findingCount: findings.length,
    sanitizedText: output,
    sourceTextHash: createHash("sha256").update(text, "utf8").digest("hex"),
    publicFindings: Object.freeze(publicFindings.map((finding) => Object.freeze({ ...finding }))),
    tokenEntries: Object.freeze(tokenEntries.map((entry) => Object.freeze({ ...entry }))),
    unresolved: Object.freeze(unresolved.map((item) => Object.freeze({ ...item }))),
    residualRisk,
    policyVersion: PLAIN_TEXT_POLICY_VERSION,
    dictionaryVersion: context.dictionary.dictionaryVersion,
    dictionaryHash: context.dictionary.dictionaryHash,
  });
  authenticTransformations.add(result);
  return result;
}

export function isAuthenticTransformation(result: TransformResult): boolean {
  return authenticTransformations.has(result);
}

function applyDecision(finding: Finding, decision: Decision, context: TransformContext): { replacement: string; tokenEntry?: TokenEntry } {
  if (decision.action === "delete") return { replacement: "[REMOVED]" };
  if (decision.action === "keep") return { replacement: finding.value };
  if (decision.action === "tokenize") {
    const label = decision.tokenLabel ?? DEFAULT_TOKEN_LABELS[finding.type];
    validateTokenLabel(label);
    const tokenEntry = context.tokenRegistry.tokenFor(finding.value, finding.type, label);
    return { replacement: tokenEntry.token, tokenEntry };
  }
  const rule = decision.generalizationRuleId ? GENERALIZATION_RULES[decision.generalizationRuleId] : undefined;
  if (!rule || !rule.findingTypes.includes(finding.type)) throw new Error("Generalization must use an approved rule for the finding type");
  return { replacement: rule.replacement };
}

function validateDecision(decision: Decision, finding: Finding): void {
  if (decision.localReasonDetail !== undefined && typeof decision.localReasonDetail !== "string") throw new Error("Invalid local reason detail");
  if (decision.reasonCode !== undefined && !CONTROLLED_REASON_CODES.has(decision.reasonCode)) throw new Error("Invalid reason code");
  if (decision.action !== "keep" && (decision.reasonCode !== undefined || decision.localReasonDetail !== undefined)) {
    throw new Error("Review reasons are only valid for keep decisions");
  }
  if (decision.action === "keep" && isBlockingSeverity(finding.severity) && !decision.reasonCode) {
    throw new Error("High/critical keep requires a controlled reason code");
  }
  if (decision.action !== "tokenize" && decision.tokenLabel !== undefined) throw new Error("Token label is only valid for tokenization");
  if (decision.action !== "generalize" && decision.generalizationRuleId !== undefined) throw new Error("Generalization rule is only valid for generalization");
}

function validateFindingRanges(text: string, findings: Finding[]): void {
  let end = 0;
  const ids = new Set<string>();
  for (const finding of findings) {
    if (ids.has(finding.findingId)) throw new Error("Duplicate finding ID");
    ids.add(finding.findingId);
    if (finding.start < end || finding.end <= finding.start || finding.end > text.length || text.slice(finding.start, finding.end) !== finding.value) {
      throw new Error("Invalid or stale finding range");
    }
    end = finding.end;
  }
}
