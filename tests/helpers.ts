import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { createDictionarySnapshot, type ProjectDictionary } from "../src/core/dictionary.js";
import { detectText, type DetectionContext } from "../src/core/detectors.js";
import { intakePlainText, intakeTabular, type PlainTextSource } from "../src/core/intake.js";
import { detectSource } from "../src/core/source-scan.js";
import { ProjectTokenRegistry } from "../src/core/token-vault.js";
import type { EncryptedTokenMap } from "../src/core/token-vault.js";
import { transformText } from "../src/core/transform.js";
import type { Action, Decision, Finding, TransformResult } from "../src/core/types.js";
import { recordP2HumanConfirmation, type VerificationRequest } from "../src/core/verification.js";

export function dictionary(terms: string[] = [], latinCaseSensitive = false, version = "dict-1", projectId = randomUUID()): DetectionContext {
  const projectDictionary: ProjectDictionary = {
    formatVersion: "ewdict-1", projectId,
    dictionaryVersion: version,
    latinCaseSensitive,
    entries: terms.map((term) => ({ canonical: term, aliases: [] })),
  };
  return { dictionary: createDictionarySnapshot(projectDictionary) };
}

export function writeSource(directory: string, text: string | Buffer, name = "source.txt"): PlainTextSource {
  const path = join(directory, name);
  writeFileSync(path, text, { mode: 0o640 });
  return intakePlainText(path);
}

export function writeTabularSource(directory: string, text: string | Buffer, name = "source.csv"): PlainTextSource {
  const path = join(directory, name);
  writeFileSync(path, text, { mode: 0o640 });
  return intakeTabular(path);
}

export function transformAll(
  source: PlainTextSource,
  detection: DetectionContext,
  action: Action = "delete",
  projectId = detection.dictionary.projectId,
): { findings: Finding[]; transformation: TransformResult; registry: ProjectTokenRegistry } {
  const findings = detectSource(source, detection);
  const registry = ProjectTokenRegistry.create(projectId, detection.dictionary);
  const decisions: Decision[] = findings.map((finding) => ({
    findingId: finding.findingId,
    action,
    ...(action === "keep" ? { reasonCode: "OPERATIONAL_CONTEXT" as const } : {}),
  }));
  return { findings, transformation: transformText(source.text, findings, decisions, { dictionary: detection.dictionary, tokenRegistry: registry }), registry };
}

export function verificationRequest(
  source: PlainTextSource,
  transformation: TransformResult,
  detection: DetectionContext,
  tokenMapArtifact?: EncryptedTokenMap,
  confirmed = true,
): VerificationRequest {
  const request: VerificationRequest = {
    projectId: transformation.projectId,
    classification: "P2" as const,
    allowedRoute: "cloud-sanitized" as const,
    ...(tokenMapArtifact ? { tokenMapArtifact } : {}),
    items: [{ source, transformation }],
    detection,
  };
  return confirmed ? { ...request, humanConfirmation: recordP2HumanConfirmation(request) } : request;
}
