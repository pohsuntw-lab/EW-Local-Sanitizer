import { decryptEnvelope, encryptEnvelope } from "./crypto-envelope.js";
import { CONTROLLED_REASON_CODES, GENERALIZATION_RULES, MAX_SESSION_FILES, MAX_SESSION_FINDINGS, validateTokenLabel } from "./policy.js";
import type { Decision } from "./types.js";

export interface LocalSessionRecord {
  schema: "ewsession-1";
  projectId: string;
  sourceIds: string[];
  decisions: Decision[];
  createdAt: string;
}

export function encryptLocalSession(session: LocalSessionRecord, passphrase: string): Buffer {
  validateSession(session);
  return encryptEnvelope("ewsession", session, passphrase);
}

export function decryptLocalSession(payload: Buffer, passphrase: string): LocalSessionRecord {
  const session = decryptEnvelope(payload, "ewsession", passphrase) as LocalSessionRecord;
  validateSession(session);
  return session;
}

function validateSession(session: LocalSessionRecord): void {
  if (session.schema !== "ewsession-1" || !Array.isArray(session.sourceIds) || !Array.isArray(session.decisions)) throw new Error("Invalid local session");
  if (!isUuid(session.projectId) || session.sourceIds.length > MAX_SESSION_FILES || new Set(session.sourceIds).size !== session.sourceIds.length ||
    session.sourceIds.some((sourceId) => !isUuid(sourceId)) || session.decisions.length > MAX_SESSION_FINDINGS ||
    typeof session.createdAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(session.createdAt) ||
    !Number.isFinite(Date.parse(session.createdAt))) {
    throw new Error("Invalid local session fields");
  }
  const decisionIds = new Set(session.decisions.map((decision) => decision.findingId));
  if (decisionIds.size !== session.decisions.length) throw new Error("Duplicate saved decision");
  for (const decision of session.decisions) validateDecision(decision);
}

function validateDecision(decision: Decision): void {
  if (!isUuid(decision.findingId) || !new Set(["delete", "tokenize", "generalize", "keep"]).has(decision.action)) throw new Error("Invalid saved decision");
  if (decision.reasonCode !== undefined && !CONTROLLED_REASON_CODES.has(decision.reasonCode)) throw new Error("Invalid saved reason code");
  if (decision.action !== "keep" && (decision.reasonCode !== undefined || decision.localReasonDetail !== undefined)) {
    throw new Error("Saved review reasons are only valid for keep decisions");
  }
  if (decision.action !== "tokenize" && decision.tokenLabel !== undefined) throw new Error("Saved token label is only valid for tokenization");
  if (decision.tokenLabel !== undefined) validateTokenLabel(decision.tokenLabel);
  if (decision.action !== "generalize" && decision.generalizationRuleId !== undefined) throw new Error("Saved generalization rule is only valid for generalization");
  if (decision.generalizationRuleId !== undefined && !GENERALIZATION_RULES[decision.generalizationRuleId]) throw new Error("Invalid saved generalization rule");
  if (decision.localReasonDetail !== undefined && (typeof decision.localReasonDetail !== "string" || decision.localReasonDetail.length > 4096)) {
    throw new Error("Invalid saved local reason detail");
  }
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
