import { randomUUID } from "node:crypto";
import { basename, extname } from "node:path";
import { createDictionarySnapshot, type DictionarySnapshot, type ProjectDictionary } from "../core/dictionary.js";
import { intakeImage, intakeOffice, intakePdf, intakePlainText, intakeTabular, releaseSourceResources, type PlainTextSource } from "../core/intake.js";
import { GENERALIZATION_RULES } from "../core/policy.js";
import { createSafePackage } from "../core/safe-package.js";
import { detectSource } from "../core/source-scan.js";
import { encryptTokenMap, ProjectTokenRegistry } from "../core/token-vault.js";
import { transformText } from "../core/transform.js";
import type { Decision, Finding, FindingType } from "../core/types.js";
import { recordP2HumanConfirmation, verifyForExport, type VerificationRequest } from "../core/verification.js";
import { removeWrittenFile, writeExclusiveFile, type WrittenFileIdentity } from "../core/exclusive-write.js";
import type { ExportOptions, ExportResult, ScanOptions, ScanResult, UiFinding } from "../ui/contracts.js";

interface SessionItem { source: PlainTextSource; findings: Finding[]; displayName: string }
interface Session { id: string; projectId: string; dictionary: DictionarySnapshot; registry: ProjectTokenRegistry; items: SessionItem[] }
const TOKENIZABLE = new Set<FindingType>(["email", "phone", "taiwan-id", "address", "ip-address", "bank-account", "contract-id", "exact-data"]);

export class LocalSessionService {
  #session: Session | undefined;

  async scanPaths(paths: readonly string[], options: ScanOptions): Promise<ScanResult> {
    this.close();
    validateScanOptions(paths, options);
    const projectId = randomUUID();
    const dictionary = createDictionarySnapshot({ formatVersion: "ewdict-1", projectId, dictionaryVersion: "ui-session-1",
      latinCaseSensitive: options.latinCaseSensitive, entries: options.dictionaryTerms.map((canonical) => ({ canonical, aliases: [] })) } satisfies ProjectDictionary);
    const registry = ProjectTokenRegistry.create(projectId, dictionary);
    const items: SessionItem[] = [];
    try {
      for (const path of paths) {
        const source = await intakePath(path, options);
        items.push({ source, findings: detectSource(source, { dictionary }), displayName: basename(path) });
      }
      const session = { id: randomUUID(), projectId, dictionary, registry, items };
      this.#session = session;
      return {
        status: "ready", sessionId: session.id,
        sources: items.map((item) => ({ sourceId: item.source.sourceId, displayName: item.displayName, format: item.source.format,
          coverage: item.source.coverage, findingCount: item.findings.length })),
        findings: items.flatMap((item) => item.findings.map((finding) => publicFinding(item.source, finding))),
      };
    } catch (error) {
      for (const item of items) releaseSourceResources(item.source);
      registry.dispose();
      throw error;
    }
  }

  needsTokenMap(decisions: readonly { action: string }[]): boolean { return decisions.some((decision) => decision.action === "tokenize"); }

  export(options: ExportOptions, outputPath: string, tokenMapPath?: string): ExportResult {
    const session = this.#session;
    if (!session || options.sessionId !== session.id) return { status: "error", code: "NO_SESSION" };
    if (!Array.isArray(options.decisions)) return { status: "error", code: "INVALID_REQUEST" };
    let tokenMapIdentity: WrittenFileIdentity | undefined;
    try {
      const decisionById = new Map(options.decisions.map((decision) => [decision.findingId, decision]));
      if (decisionById.size !== options.decisions.length) return { status: "error", code: "INVALID_REQUEST" };
      const transformations = session.items.map((item) => transformText(item.source.text, item.findings,
        item.findings.flatMap((finding) => { const value = decisionById.get(finding.findingId); return value ? [toDecision(finding, value)] : []; }),
        { dictionary: session.dictionary, tokenRegistry: session.registry }));
      if (options.decisions.some((decision) => !session.items.some((item) => item.findings.some((finding) => finding.findingId === decision.findingId)))) {
        return { status: "error", code: "INVALID_REQUEST" };
      }
      const tokenized = transformations.some((transformation) => transformation.tokenEntries.length > 0);
      if (tokenMapPath && (!tokenized || !tokenMapPath.toLowerCase().endsWith(".ewmap") || tokenMapPath === outputPath)) return { status: "error", code: "INVALID_REQUEST" };
      const tokenMap = tokenized ? encryptTokenMap(session.registry, validatePassphrase(options.tokenMapPassphrase)) : undefined;
      const request: VerificationRequest = { projectId: session.projectId, classification: options.classification, allowedRoute: options.allowedRoute,
        items: session.items.map((item, index) => ({ source: item.source, transformation: transformations[index]! })), detection: { dictionary: session.dictionary },
        ...(tokenMap ? { tokenMapArtifact: tokenMap } : {}) };
      const withConfirmation = options.classification === "P2" && options.p2Confirmed ? { ...request, humanConfirmation: recordP2HumanConfirmation(request) } : request;
      const outcome = verifyForExport(withConfirmation);
      if (outcome.status === "blocked") return { status: "blocked", unresolved: [...new Set(outcome.unresolved.map((item) => item.code))] };
      if (tokenMap) {
        if (!tokenMapPath) return { status: "error", code: "INVALID_REQUEST" };
        tokenMapIdentity = writeExclusiveFile(tokenMapPath, tokenMap.payload);
      }
      const packaged = createSafePackage(outcome.capability, outputPath);
      return { status: "exported", packagePath: outputPath, checksumPath: packaged.checksumPath, receiptPath: packaged.receiptPath,
        ...(tokenMapPath ? { tokenMapPath } : {}), packageHash: packaged.packageHash, residualRisk: outcome.residualRisk };
    } catch (error) {
      if (tokenMapPath && tokenMapIdentity) removeWrittenFile(tokenMapPath, tokenMapIdentity);
      return { status: "error", code: error instanceof Error && /already exists/.test(error.message) ? "OUTPUT_EXISTS" : "PROCESSING_FAILED" };
    }
  }

  close(): void {
    if (!this.#session) return;
    for (const item of this.#session.items) releaseSourceResources(item.source);
    this.#session.registry.dispose();
    this.#session = undefined;
  }
}

async function intakePath(path: string, options: ScanOptions): Promise<PlainTextSource> {
  const extension = extname(path).toLowerCase();
  if (extension === ".txt" || extension === ".md" || extension === ".markdown") return intakePlainText(path);
  if (extension === ".csv" || extension === ".tsv") return intakeTabular(path);
  if (extension === ".docx" || extension === ".xlsx" || extension === ".pptx") return intakeOffice(path, { approveAllVisibleWorksheets: options.approveAllVisibleWorksheets });
  if (extension === ".pdf") return intakePdf(path);
  if (extension === ".png" || extension === ".jpg" || extension === ".jpeg") return intakeImage(path, options.ocrLanguage);
  throw new Error("Unsupported input format");
}

function publicFinding(source: PlainTextSource, finding: Finding): UiFinding {
  const image = source.format === "png" || source.format === "jpg" || source.format === "jpeg";
  const forced = image || new Set<FindingType>(["private-key", "api-token", "credential", "office-hidden-content", "office-formula", "office-external-link", "office-metadata", "pdf-active-content", "pdf-image-content", "image-metadata"]).has(finding.type);
  const formula = finding.type === "spreadsheet-formula";
  const rules = Object.values(GENERALIZATION_RULES).filter((rule) => rule.findingTypes.includes(finding.type)).map((rule) => rule.id);
  return { findingId: finding.findingId, sourceId: source.sourceId, type: finding.type, severity: finding.severity,
    maskedPreview: finding.maskedPreview, detector: finding.detector,
    allowedActions: forced ? ["delete"] : formula ? ["generalize"] : ["delete", ...(TOKENIZABLE.has(finding.type) ? ["tokenize" as const] : []), ...(rules.length ? ["generalize" as const] : []), "keep"],
    generalizationRules: rules };
}

function toDecision(finding: Finding, value: ExportOptions["decisions"][number]): Decision {
  return { findingId: finding.findingId, action: value.action, ...(value.reasonCode ? { reasonCode: value.reasonCode } : {}),
    ...(value.generalizationRuleId ? { generalizationRuleId: value.generalizationRuleId } : {}) };
}

function validatePassphrase(value: string | undefined): string {
  if (typeof value !== "string" || value.length < 12 || value.length > 1024) throw new Error("Invalid token-map passphrase");
  return value;
}

function validateScanOptions(paths: readonly string[], options: ScanOptions): void {
  if (!Array.isArray(paths) || paths.length < 1 || paths.length > 100 || !options || !Array.isArray(options.dictionaryTerms) ||
    options.dictionaryTerms.some((term) => typeof term !== "string") || typeof options.latinCaseSensitive !== "boolean" ||
    typeof options.approveAllVisibleWorksheets !== "boolean" || !new Set(["eng", "chi_tra"]).has(options.ocrLanguage)) throw new Error("Invalid scan request");
}
