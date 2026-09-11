import { randomUUID } from "node:crypto";
import { posix } from "node:path";
import { DOMParser, type Document as XmlDocument, type Element as XmlElement, type Node as XmlNode } from "@xmldom/xmldom";
import type { DetectionSegment } from "./detectors.js";
import { openOoxmlPackage, type OoxmlPackage } from "./ooxml-package.js";
import { parseTabularText } from "./tabular.js";
import type { CoverageStatus, FindingType, Severity } from "./types.js";

export type OfficeFormat = "docx" | "xlsx" | "pptx";

export interface OfficeDerivativeArtifact {
  readonly suffix: string;
  readonly extension: "md" | "csv" | "tsv";
  readonly text: string;
}

export interface OfficeParseState {
  readonly format: OfficeFormat;
  readonly segments: readonly DetectionSegment[];
  readonly derivatives: (sanitizedText: string) => readonly OfficeDerivativeArtifact[];
}

export interface OfficeExtraction {
  readonly format: OfficeFormat;
  readonly text: string;
  readonly coverage: CoverageStatus;
  readonly state: OfficeParseState;
}

export interface OfficeIntakeOptions {
  readonly approveAllVisibleWorksheets?: boolean;
}

interface Relationship { id: string; target: string; type: string; external: boolean }
interface SheetData { visible: boolean; rows: CellData[][]; hiddenText: string }
interface CellData { value: string; formula: boolean }

export function extractOfficeDocument(bytes: Buffer, format: OfficeFormat, options: OfficeIntakeOptions = {}): OfficeExtraction {
  const archive = openOoxmlPackage(bytes);
  assertOfficeIdentity(archive, format);
  const coverage = hasUnsupportedCoverage(archive) || (format === "xlsx" && options.approveAllVisibleWorksheets !== true) ? "incomplete" : "complete";
  const external = packageHasExternalRelationship(archive);
  const metadata = [...archive.entries.keys()].some((name) => name.startsWith("docProps/"));
  if (format === "docx") return extractDocx(archive, coverage, external, metadata);
  if (format === "xlsx") return extractXlsx(archive, coverage, external, metadata);
  return extractPptx(archive, coverage, external, metadata);
}

function extractDocx(archive: OoxmlPackage, coverage: CoverageStatus, external: boolean, metadata: boolean): OfficeExtraction {
  const builder = new CanonicalBuilder();
  builder.literal("# DOCX derivative\n\n");
  const main = requiredXml(archive, "word/document.xml");
  appendWordPart(builder, main, "Document", false);
  for (const name of sortedEntries(archive, /^word\/(?:header|footer)\d+\.xml$/)) {
    appendWordPart(builder, requiredXml(archive, name), name.includes("header") ? "Header" : "Footer", false);
  }
  for (const name of sortedEntries(archive, /^word\/(?:footnotes|endnotes)\.xml$/)) appendWordPart(builder, requiredXml(archive, name), "Note", false);
  for (const name of sortedEntries(archive, /^word\/comments(?:Extended)?\.xml$/)) {
    const hidden = wordText(requiredXml(archive, name), false);
    if (hidden) builder.structural(hidden, "office-hidden-content", "office-comment-content");
  }
  const deleted = wordText(main, true);
  if (deleted) builder.structural(deleted, "office-hidden-content", "office-revision-content");
  if (["del", "ins", "moveFrom", "moveTo"].some((name) => nodes(main, name).length > 0)) {
    builder.structural("[REVISION INDICATOR]", "office-metadata", "docx-revision-indicator");
  }
  appendRiskMarkers(builder, external, metadata);
  return finishOffice("docx", builder, coverage, (text) => [{ suffix: "", extension: "md", text }]);
}

function extractXlsx(archive: OoxmlPackage, coverage: CoverageStatus, external: boolean, metadata: boolean): OfficeExtraction {
  const workbook = requiredXml(archive, "xl/workbook.xml");
  const relationships = relationshipMap(archive, "xl/workbook.xml");
  const shared = archive.entries.has("xl/sharedStrings.xml") ? nodes(requiredXml(archive, "xl/sharedStrings.xml"), "si").map(joinTextNodes) : [];
  const sheets: SheetData[] = [];
  const sheetNames: string[] = [];
  for (const sheet of nodes(workbook, "sheet")) {
    const relationshipId = attributeByLocalName(sheet, "id");
    const relationship = relationships.get(relationshipId);
    if (!relationship || relationship.external || !relationship.type.endsWith("worksheet")) throw new Error("XLSX worksheet relationship is missing, external or has the wrong type");
    const path = resolvePart("xl/workbook.xml", relationship.target);
    const worksheet = extractWorksheet(requiredXml(archive, path), shared);
    sheets.push({ visible: (sheet.getAttribute("state") ?? "visible") === "visible", ...worksheet });
    sheetNames.push(sheet.getAttribute("name") ?? "");
  }
  if (sheets.length === 0) throw new Error("XLSX workbook contains no worksheets");
  const visibleSheets = sheets.filter((sheet) => sheet.visible).length;
  if (visibleSheets === 0) throw new Error("XLSX workbook contains no visible worksheets");
  if (visibleSheets > 99) throw new Error("XLSX exceeds visible worksheet derivative policy limit");

  const builder = new CanonicalBuilder();
  builder.literal("# XLSX derivative\n");
  const sections: Array<{ marker: string; visible: boolean; sheetNumber?: number }> = [];
  const hiddenBlocks: Array<{ value: string; detector: string }> = [];
  let visibleNumber = 0;
  for (const sheet of sheets) {
    const marker = `<!-- EW-OFFICE-SECTION-${randomUUID()} -->`;
    sections.push(sheet.visible ? { marker, visible: true, sheetNumber: ++visibleNumber } : { marker, visible: false });
    builder.literal(`\n${marker}\n`);
    const csv = csvSection(sheet.rows);
    if (sheet.visible) builder.appendMapped(csv.text, csv.segments);
    else hiddenBlocks.push({ value: csv.text || "[HIDDEN SHEET]", detector: "xlsx-hidden-sheet" });
    if (sheet.hiddenText) hiddenBlocks.push({ value: sheet.hiddenText, detector: "xlsx-hidden-row-or-column" });
  }
  const endMarker = `<!-- EW-OFFICE-END-${randomUUID()} -->`;
  builder.literal(`\n${endMarker}\n`);
  if (sheetNames.some(Boolean)) builder.structural(sheetNames.filter(Boolean).join("\n"), "office-metadata", "xlsx-worksheet-names");
  for (const block of hiddenBlocks) builder.structural(block.value, "office-hidden-content", block.detector);
  for (const name of sortedEntries(archive, /^xl\/comments\d+\.xml$/)) {
    const commentText = nodes(requiredXml(archive, name), "comment").map(joinTextNodes).filter(Boolean).join("\n");
    if (commentText) builder.structural(commentText, "office-hidden-content", "xlsx-comment-content");
  }
  appendRiskMarkers(builder, external, metadata);

  return finishOffice("xlsx", builder, coverage, (text) => {
    const artifacts: OfficeDerivativeArtifact[] = [{
      suffix: "-index", extension: "md",
      text: `# Workbook index\n\n${sections.filter((section) => section.visible).map((section) => `- Sheet ${String(section.sheetNumber).padStart(3, "0")}: sheet-${String(section.sheetNumber).padStart(3, "0")}.csv`).join("\n")}\n`,
    }];
    for (let index = 0; index < sections.length; index += 1) {
      const section = sections[index]!;
      if (!section.visible || section.sheetNumber === undefined) continue;
      const start = text.indexOf(`${section.marker}\n`);
      if (start < 0 || text.indexOf(section.marker, start + section.marker.length) >= 0) throw new Error("XLSX derivative section marker changed");
      const contentStart = start + section.marker.length + 1;
      const next = sections.slice(index + 1).map((candidate) => text.indexOf(`\n${candidate.marker}\n`, contentStart)).find((offset) => offset >= 0);
      const end = next ?? text.indexOf(`\n${endMarker}\n`, contentStart);
      if (end < 0) throw new Error("XLSX derivative end marker changed");
      artifacts.push({ suffix: `-sheet-${String(section.sheetNumber).padStart(3, "0")}`, extension: "csv", text: text.slice(contentStart, end) });
    }
    return artifacts;
  });
}

function extractPptx(archive: OoxmlPackage, coverage: CoverageStatus, external: boolean, metadata: boolean): OfficeExtraction {
  const presentation = requiredXml(archive, "ppt/presentation.xml");
  const relationships = relationshipMap(archive, "ppt/presentation.xml");
  const ordered: Array<{ path: string; visible: boolean }> = [];
  for (const slide of nodes(presentation, "sldId")) {
    const relationship = relationships.get(attributeByLocalName(slide, "id"));
    if (!relationship || relationship.external || !relationship.type.endsWith("slide")) throw new Error("PPTX slide relationship is missing, external or has the wrong type");
    ordered.push({ path: resolvePart("ppt/presentation.xml", relationship.target), visible: slide.getAttribute("show") !== "0" });
  }
  if (ordered.length === 0) throw new Error("PPTX presentation contains no slides");
  const builder = new CanonicalBuilder();
  builder.literal("# PPTX derivative\n");
  let visibleSlide = 0;
  for (const slide of ordered) {
    const document = requiredXml(archive, slide.path);
    const text = nodes(document, "t").map((node) => node.textContent ?? "").filter(Boolean).join("\n");
    if (!document.documentElement) throw new Error("PPTX slide XML has no document element");
    const visible = slide.visible && document.documentElement.getAttribute("show") !== "0";
    if (visible) {
      builder.literal(`\n## Slide ${String(++visibleSlide).padStart(3, "0")}\n\n`);
      builder.visible(text);
      builder.literal("\n");
    } else if (text) builder.structural(text, "office-hidden-content", "pptx-hidden-slide");
  }
  for (const name of sortedEntries(archive, /^ppt\/(?:notesSlides|comments)\/.*\.xml$/)) {
    const hidden = nodes(requiredXml(archive, name), "t").map((node) => node.textContent ?? "").filter(Boolean).join("\n");
    if (hidden) builder.structural(hidden, "office-hidden-content", name.includes("notesSlides") ? "pptx-speaker-notes" : "pptx-comment-content");
  }
  appendRiskMarkers(builder, external, metadata);
  return finishOffice("pptx", builder, coverage, (text) => [{ suffix: "", extension: "md", text }]);
}

function finishOffice(format: OfficeFormat, builder: CanonicalBuilder, coverage: CoverageStatus,
  derivatives: (text: string) => readonly OfficeDerivativeArtifact[]): OfficeExtraction {
  const text = builder.text();
  const segments = builder.segments().map((segment) => Object.freeze({
    ...segment,
    valueStarts: Object.freeze([...segment.valueStarts]),
    valueEnds: Object.freeze([...segment.valueEnds]),
    ...(segment.structuralFinding ? { structuralFinding: Object.freeze({ ...segment.structuralFinding }) } : {}),
  }));
  const state = Object.freeze({ format, segments: Object.freeze(segments), derivatives });
  return Object.freeze({ format, text, coverage, state });
}

class CanonicalBuilder {
  #text = "";
  #segments: DetectionSegment[] = [];
  literal(value: string): void { this.#text += value; }
  visible(value: string, formulaAware = false): void { this.add(value, formulaAware ? { formulaAware: true } : {}); }
  structural(value: string, type: FindingType, detector: string, severity: Severity = "critical"): void {
    this.add(value, { structuralFinding: { type, detector, severity } });
    this.literal("\n");
  }
  appendMapped(value: string, segments: readonly DetectionSegment[]): void {
    assertSafeXmlText(value);
    const offset = this.#text.length;
    this.#text += value;
    this.#segments.push(...segments.map((segment) => ({
      ...segment,
      valueStarts: Object.freeze(segment.valueStarts.map((position) => position + offset)),
      valueEnds: Object.freeze(segment.valueEnds.map((position) => position + offset)),
    })));
  }
  text(): string { return this.#text; }
  segments(): DetectionSegment[] { return [...this.#segments]; }
  private add(value: string, options: Pick<DetectionSegment, "formulaAware" | "structuralFinding">): void {
    assertSafeXmlText(value);
    const start = this.#text.length;
    this.#text += value;
    const starts = Array.from({ length: value.length }, (_, index) => start + index);
    const ends = Array.from({ length: value.length }, (_, index) => start + index + 1);
    this.#segments.push({ value, valueStarts: Object.freeze(starts), valueEnds: Object.freeze(ends), ...options });
  }
}

function csvSection(rows: readonly (readonly CellData[])[]): { text: string; segments: DetectionSegment[] } {
  const text = rows.map((row) => row.map((cell) => `"${cell.value.replaceAll('"', '""')}"`).join(",")).join("\n") + "\n";
  const parsed = parseTabularText(text, "csv");
  const segments: DetectionSegment[] = [];
  for (let row = 0; row < parsed.rows.length; row += 1) {
    for (let column = 0; column < (parsed.rows[row]?.length ?? 0); column += 1) {
      const cell = parsed.rows[row]![column]!;
      const source = rows[row]?.[column];
      segments.push(source?.formula ? {
        ...cell,
        structuralFinding: { type: "office-formula", severity: "critical", detector: "xlsx-formula-cell" },
      } : { ...cell, formulaAware: true });
    }
  }
  return { text, segments };
}

function extractWorksheet(document: XmlDocument, shared: readonly string[]): { rows: CellData[][]; hiddenText: string } {
  const hiddenColumns = new Set<number>();
  for (const column of nodes(document, "col")) {
    if (!isTrue(column.getAttribute("hidden"))) continue;
    const min = Number(column.getAttribute("min"));
    const max = Number(column.getAttribute("max"));
    if (!Number.isInteger(min) || !Number.isInteger(max) || min < 1 || max < min || max > 1_000) throw new Error("XLSX hidden-column range is unsupported");
    for (let value = min; value <= max; value += 1) hiddenColumns.add(value - 1);
  }
  const visible: CellData[][] = [];
  const hidden: CellData[] = [];
  for (const row of nodes(document, "row")) {
    const rowHidden = isTrue(row.getAttribute("hidden"));
    const output: CellData[] = [];
    for (const cell of childElements(row, "c")) {
      const column = cellColumn(cell.getAttribute("r"));
      const value = cellValue(cell, shared);
      if (rowHidden || hiddenColumns.has(column)) hidden.push(value);
      else {
        while (output.length < column) output.push({ value: "", formula: false });
        output[column] = value;
      }
    }
    if (!rowHidden && output.length > 0) visible.push(output.map((cell) => cell ?? { value: "", formula: false }));
  }
  return {
    rows: rectangular(visible.length > 0 ? visible : [[{ value: "", formula: false }]]),
    hiddenText: hidden.map((cell) => cell.value).filter(Boolean).join("\n"),
  };
}

function cellValue(cell: XmlElement, shared: readonly string[]): CellData {
  const formula = childElements(cell, "f")[0];
  if (formula) return { value: `=${formula.textContent ?? ""}`, formula: true };
  const type = cell.getAttribute("t") ?? "n";
  if (type === "inlineStr") return { value: childElements(cell, "is").map(joinTextNodes).join(""), formula: false };
  const raw = childElements(cell, "v")[0]?.textContent ?? "";
  if (type === "s") {
    const index = Number(raw);
    if (!Number.isInteger(index) || index < 0 || index >= shared.length) throw new Error("XLSX shared-string index is invalid");
    return { value: shared[index] ?? "", formula: false };
  }
  if (!new Set(["n", "b", "str", "e", "d"]).has(type)) throw new Error("XLSX cell type is unsupported");
  return { value: raw, formula: false };
}

function rectangular(rows: CellData[][]): CellData[][] {
  const width = Math.max(...rows.map((row) => row.length));
  return rows.map((row) => [...row, ...Array.from({ length: width - row.length }, () => ({ value: "", formula: false }))]);
}

function appendWordPart(builder: CanonicalBuilder, document: XmlDocument, label: string, deletedOnly: boolean): void {
  const text = wordText(document, deletedOnly);
  if (!text) return;
  builder.literal(`\n## ${label}\n\n`);
  builder.visible(text);
  builder.literal("\n");
}

function wordText(document: XmlDocument, deletedOnly: boolean): string {
  return nodes(document, "t").filter((node) => (["del", "moveFrom"].some((name) => hasAncestor(node, name))) === deletedOnly)
    .map((node) => node.textContent ?? "").filter(Boolean).join("\n");
}

function appendRiskMarkers(builder: CanonicalBuilder, external: boolean, metadata: boolean): void {
  if (external) builder.structural("[EXTERNAL RELATIONSHIP]", "office-external-link", "ooxml-external-relationship");
  if (metadata) builder.structural("[DOCUMENT METADATA]", "office-metadata", "ooxml-document-properties");
}

function assertOfficeIdentity(archive: OoxmlPackage, format: OfficeFormat): void {
  const contentTypes = requiredXml(archive, "[Content_Types].xml");
  const required = format === "docx" ? ["word/document.xml", "wordprocessingml.document.main+xml"]
    : format === "xlsx" ? ["xl/workbook.xml", "spreadsheetml.sheet.main+xml"]
      : ["ppt/presentation.xml", "presentationml.presentation.main+xml"];
  if (!archive.entries.has(required[0]!) ||
    !nodes(contentTypes, "Override").some((node) => (node.getAttribute("PartName") ?? "").replace(/^\//, "") === required[0] &&
      (node.getAttribute("ContentType") ?? "").includes(required[1]!))) {
    throw new Error("OOXML content type does not match its requested format");
  }
  if (nodes(contentTypes, "Override").some((node) => /macroEnabled|vbaProject/i.test(node.getAttribute("ContentType") ?? "")) ||
    [...archive.entries.keys()].some((name) => /(?:^|\/)vbaProject\.bin$/i.test(name))) {
    throw new Error("Macro-enabled Office packages are unsupported");
  }
}

function hasUnsupportedCoverage(archive: OoxmlPackage): boolean {
  return [...archive.entries.keys()].some((name) => /(?:^|\/)(?:media|embeddings|activeX|charts|diagrams|drawings|customXml|_xmlsignatures)(?:\/|$)/i.test(name));
}

function packageHasExternalRelationship(archive: OoxmlPackage): boolean {
  for (const [name] of archive.entries) {
    if (name.endsWith(".rels") && nodes(requiredXml(archive, name), "Relationship").some((node) => (node.getAttribute("TargetMode") ?? "").toLowerCase() === "external")) return true;
  }
  return false;
}

function relationshipMap(archive: OoxmlPackage, sourcePart: string): Map<string, Relationship> {
  const relationshipPath = posix.join(posix.dirname(sourcePart), "_rels", `${posix.basename(sourcePart)}.rels`);
  const document = requiredXml(archive, relationshipPath);
  const result = new Map<string, Relationship>();
  for (const node of nodes(document, "Relationship")) {
    const id = node.getAttribute("Id") ?? "";
    const target = node.getAttribute("Target") ?? "";
    const type = node.getAttribute("Type") ?? "";
    if (!id || !target || !type || result.has(id)) throw new Error("OOXML relationship is invalid or duplicated");
    result.set(id, { id, target, type, external: (node.getAttribute("TargetMode") ?? "").toLowerCase() === "external" });
  }
  return result;
}

function resolvePart(sourcePart: string, target: string): string {
  if (target.startsWith("/") || target.includes("\\") || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(target)) throw new Error("OOXML relationship target is unsafe");
  const resolved = posix.normalize(posix.join(posix.dirname(sourcePart), target));
  if (resolved === ".." || resolved.startsWith("../")) throw new Error("OOXML relationship target escapes the package");
  return resolved;
}

function requiredXml(archive: OoxmlPackage, name: string): XmlDocument {
  const bytes = archive.entries.get(name);
  if (!bytes) throw new Error("Required OOXML part is missing");
  const text = decodeXml(bytes);
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) throw new Error("OOXML DTD and entity declarations are unsupported");
  try {
    return new DOMParser({ onError: (_level, message) => { throw new Error(message); } }).parseFromString(text, "application/xml");
  } catch {
    throw new Error("OOXML XML parsing failed");
  }
}

function decodeXml(bytes: Buffer): string {
  try {
    if (bytes.subarray(0, 2).equals(Buffer.from([0xff, 0xfe]))) return new TextDecoder("utf-16le", { fatal: true }).decode(bytes.subarray(2));
    if (bytes.subarray(0, 2).equals(Buffer.from([0xfe, 0xff]))) return new TextDecoder("utf-16be", { fatal: true }).decode(bytes.subarray(2));
    const content = bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])) ? bytes.subarray(3) : bytes;
    const text = new TextDecoder("utf-8", { fatal: true }).decode(content);
    const declared = /^\s*<\?xml[^>]*encoding=["']([^"']+)["']/i.exec(text)?.[1]?.toLowerCase();
    if (declared && !new Set(["utf-8", "utf8", "us-ascii"]).has(declared)) throw new Error("encoding");
    return text;
  } catch {
    throw new Error("OOXML XML encoding is unsupported or invalid");
  }
}

function nodes(document: XmlDocument | XmlElement, localName: string): XmlElement[] {
  return Array.from(document.getElementsByTagName("*")).filter((node) => node.localName === localName) as XmlElement[];
}

function childElements(element: XmlElement, localName: string): XmlElement[] {
  return Array.from(element.childNodes).filter((node): node is XmlElement => node.nodeType === 1 && (node as XmlElement).localName === localName);
}

function joinTextNodes(element: XmlElement): string { return nodes(element, "t").map((node) => node.textContent ?? "").join(""); }
function attributeByLocalName(element: XmlElement, localName: string): string {
  const attributes = Array.from(element.attributes);
  return attributes.find((attribute) => attribute.prefix === "r" && attribute.localName === localName)?.value ??
    attributes.find((attribute) => attribute.localName === localName)?.value ?? "";
}
function hasAncestor(node: XmlNode, localName: string): boolean {
  for (let current = node.parentNode; current; current = current.parentNode) if ((current as XmlElement).localName === localName) return true;
  return false;
}
function sortedEntries(archive: OoxmlPackage, pattern: RegExp): string[] { return [...archive.entries.keys()].filter((name) => pattern.test(name)).sort(); }
function isTrue(value: string | null): boolean { return value === "1" || value?.toLowerCase() === "true"; }
function cellColumn(reference: string | null): number {
  const letters = /^([A-Z]{1,3})\d+$/i.exec(reference ?? "")?.[1]?.toUpperCase();
  if (!letters) throw new Error("XLSX cell reference is invalid");
  let value = 0;
  for (const letter of letters) value = value * 26 + letter.charCodeAt(0) - 64;
  if (value < 1 || value > 1_000) throw new Error("XLSX column exceeds policy limit");
  return value - 1;
}
function assertSafeXmlText(value: string): void {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if ((code < 0x20 && !new Set(["\t", "\n", "\r"]).has(character)) || (code >= 0x7f && code <= 0x9f)) {
      throw new Error("OOXML text contains unsupported control characters");
    }
  }
}
