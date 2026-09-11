import { decryptEnvelope, encryptEnvelope } from "./crypto-envelope.js";
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
  if (session.sourceIds.some((sourceId) => typeof sourceId !== "string") || typeof session.projectId !== "string" || typeof session.createdAt !== "string") {
    throw new Error("Invalid local session fields");
  }
}
