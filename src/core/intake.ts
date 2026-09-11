import { createHash, randomUUID } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { extname } from "node:path";
import { MAX_PLAIN_TEXT_BYTES, MAX_SESSION_FILES, MAX_SESSION_TOTAL_BYTES, PLAIN_TEXT_POLICY_VERSION } from "./policy.js";
import { parseTabularText, type TabularDocument } from "./tabular.js";
import type { CoverageStatus } from "./types.js";

export interface PlainTextSource {
  readonly sourceId: string;
  readonly text: string;
  readonly originalHash: string;
  readonly size: number;
  readonly format: "txt" | "markdown" | "csv" | "tsv";
  readonly derivativeExtension: "md" | "csv" | "tsv";
  readonly encoding: "utf-8" | "utf-16le" | "utf-16be";
  readonly coverage: CoverageStatus;
  readonly policyVersion: string;
}

const sourcePaths = new WeakMap<object, string>();
const authenticSources = new WeakSet<object>();
const tabularDocuments = new WeakMap<object, TabularDocument>();
declare const sourceIntegrityProbeBrand: unique symbol;
export interface SourceIntegrityProbe { readonly [sourceIntegrityProbeBrand]: true }
const sourceIntegrityProbeStates = new WeakMap<object, { path: string; hash: string; size: number }>();

export function intakePlainText(path: string): PlainTextSource {
  return intakeSupportedText(path, "plain");
}

export function intakeTabular(path: string): PlainTextSource {
  return intakeSupportedText(path, "tabular");
}

function intakeSupportedText(path: string, kind: "plain" | "tabular"): PlainTextSource {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("Source must be a regular non-symbolic file");
  if (metadata.size > MAX_PLAIN_TEXT_BYTES) throw new Error("Plain-text source exceeds 10 MiB policy limit");
  const extension = extname(path).toLowerCase();
  const allowed = kind === "plain" ? new Set([".txt", ".md", ".markdown"]) : new Set([".csv", ".tsv"]);
  if (!allowed.has(extension)) throw new Error(`Unsupported ${kind === "plain" ? "plain-text" : "tabular"} extension`);

  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  let bytes: Buffer;
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.size !== metadata.size) throw new Error("Source changed during intake");
    bytes = readFileSync(descriptor);
    if (bytes.length !== opened.size || bytes.length > MAX_PLAIN_TEXT_BYTES) throw new Error("Source changed during intake");
  } finally {
    closeSync(descriptor);
  }
  rejectKnownBinary(bytes);
  const decoded = decodeSupportedUnicode(bytes);
  if (containsBinaryControls(decoded.text)) throw new Error("Binary content cannot masquerade as plain text");
  const format = extension === ".txt" ? "txt" : extension === ".md" || extension === ".markdown" ? "markdown" : extension.slice(1) as "csv" | "tsv";
  const tabular = kind === "tabular" ? parseTabularText(decoded.text, format as "csv" | "tsv") : undefined;
  const source = Object.freeze({
    sourceId: randomUUID(),
    text: decoded.text,
    originalHash: sha256(bytes),
    size: bytes.length,
    format,
    derivativeExtension: format === "csv" || format === "tsv" ? format : "md",
    encoding: decoded.encoding,
    coverage: "complete",
    policyVersion: PLAIN_TEXT_POLICY_VERSION,
  } satisfies PlainTextSource);
  sourcePaths.set(source, path);
  authenticSources.add(source);
  if (tabular) tabularDocuments.set(source, tabular);
  return source;
}

export function tabularDocumentFor(source: PlainTextSource): TabularDocument | undefined {
  return tabularDocuments.get(source);
}

export function assertSessionFileCount(count: number): void {
  if (!Number.isInteger(count) || count < 1 || count > MAX_SESSION_FILES) throw new Error("Session must contain between 1 and 100 files");
}

export function assertSessionTotalBytes(sizes: readonly number[]): void {
  let total = 0;
  for (const size of sizes) {
    if (!Number.isSafeInteger(size) || size < 0) throw new Error("Invalid source size");
    total += size;
    if (total > MAX_SESSION_TOTAL_BYTES) throw new Error("Session exceeds 100 MiB aggregate policy limit");
  }
}

export function sourceHashStillMatches(source: PlainTextSource): boolean {
  if (!authenticSources.has(source)) return false;
  const path = sourcePaths.get(source);
  if (!path) return false;
  return pathHashStillMatches(path, source.originalHash, source.size);
}

export function createSourceIntegrityProbe(source: PlainTextSource): SourceIntegrityProbe {
  if (!authenticSources.has(source)) throw new Error("Cannot create integrity probe for untrusted source");
  const path = sourcePaths.get(source);
  if (!path) throw new Error("Source path unavailable for integrity probe");
  const probe = Object.freeze({}) as SourceIntegrityProbe;
  sourceIntegrityProbeStates.set(probe, { path, hash: source.originalHash, size: source.size });
  return probe;
}

export function sourceIntegrityProbeMatches(probe: SourceIntegrityProbe): boolean {
  const state = sourceIntegrityProbeStates.get(probe);
  return state !== undefined && pathHashStillMatches(state.path, state.hash, state.size);
}

function pathHashStillMatches(path: string, expectedHash: string, expectedSize: number): boolean {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.size !== expectedSize || opened.size > MAX_PLAIN_TEXT_BYTES) return false;
    const bytes = readFileSync(descriptor);
    return bytes.length === expectedSize && sha256(bytes) === expectedHash;
  } catch {
    return false;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function isAuthenticSource(source: PlainTextSource): boolean {
  return authenticSources.has(source);
}

function decodeSupportedUnicode(bytes: Buffer): { text: string; encoding: PlainTextSource["encoding"] } {
  try {
    if (bytes.subarray(0, 2).equals(Buffer.from([0xff, 0xfe]))) {
      return { text: new TextDecoder("utf-16le", { fatal: true }).decode(bytes.subarray(2)), encoding: "utf-16le" };
    }
    if (bytes.subarray(0, 2).equals(Buffer.from([0xfe, 0xff]))) {
      return { text: new TextDecoder("utf-16be", { fatal: true }).decode(bytes.subarray(2)), encoding: "utf-16be" };
    }
    const content = bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])) ? bytes.subarray(3) : bytes;
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(content), encoding: "utf-8" };
  } catch {
    throw new Error("Unsupported or invalid Unicode encoding");
  }
}

function rejectKnownBinary(bytes: Buffer): void {
  const signatures = [
    Buffer.from([0x50, 0x4b, 0x03, 0x04]),
    Buffer.from("%PDF-", "ascii"),
    Buffer.from([0x89, 0x50, 0x4e, 0x47]),
    Buffer.from([0xff, 0xd8, 0xff]),
    Buffer.from("MZ", "ascii"),
  ];
  if (signatures.some((signature) => bytes.subarray(0, signature.length).equals(signature))) throw new Error("Known binary format is not plain text");
}

function containsBinaryControls(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if ((code < 0x20 && character !== "\n" && character !== "\r" && character !== "\t") || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
