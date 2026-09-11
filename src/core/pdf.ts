import type { DetectionSegment } from "./detectors.js";
import { MAX_PDF_PAGES } from "./policy.js";
import type { CoverageStatus, FindingType } from "./types.js";

export interface PdfParseState {
  readonly segments: readonly DetectionSegment[];
  readonly derivatives: (sanitizedText: string) => readonly [{ suffix: ""; extension: "md"; text: string }];
}

export interface PdfExtraction { readonly text: string; readonly coverage: CoverageStatus; readonly state: PdfParseState }

export async function extractPdf(bytes: Buffer): Promise<PdfExtraction> {
  const { getDocument, OPS } = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const imageOperators = new Set<number>([
    OPS.paintImageMaskXObject, OPS.paintImageMaskXObjectGroup, OPS.paintImageXObject,
    OPS.paintInlineImageXObject, OPS.paintInlineImageXObjectGroup, OPS.paintSolidColorImageMask,
  ]);
  const task = getDocument({ data: new Uint8Array(bytes), useSystemFonts: false, disableFontFace: true });
  try {
    const document = await task.promise;
    if (document.numPages < 1 || document.numPages > MAX_PDF_PAGES) throw new Error("PDF page count is outside policy limits");
    const builder = new PdfBuilder();
    builder.literal("# PDF derivative\n");
    let incomplete = false;
    const javascript = await document.getJSActions();
    if (javascript && Object.keys(javascript).length > 0) builder.structural("[PDF JAVASCRIPT]", "pdf-active-content", "pdf-javascript");
    const attachments = await document.getAttachments();
    if (attachments && Object.keys(attachments).length > 0) builder.structural("[PDF ATTACHMENT]", "pdf-active-content", "pdf-attachment");
    const fields = await document.getFieldObjects();
    if (fields && Object.keys(fields).length > 0) builder.structural("[PDF FORM]", "pdf-active-content", "pdf-form");
    for (let pageNumber = 1; pageNumber <= document.numPages; pageNumber += 1) {
      const page = await document.getPage(pageNumber);
      const content = await page.getTextContent({ disableNormalization: false });
      const text = content.items.map((item) => "str" in item ? item.str : "").filter(Boolean).join(" ").trim();
      builder.literal(`\n## Page ${String(pageNumber).padStart(3, "0")}\n\n`);
      if (text) builder.visible(text);
      const operators = await page.getOperatorList();
      const hasImage = operators.fnArray.some((operator) => imageOperators.has(operator));
      if (hasImage) {
        incomplete = true;
        builder.structural(text ? "[PDF PAGE IMAGE]" : "[PDF IMAGE-ONLY PAGE]", "pdf-image-content", text ? "pdf-page-image" : "pdf-image-only-page");
      } else if (!text) {
        incomplete = true;
        builder.structural("[PDF EMPTY OR UNSUPPORTED PAGE]", "pdf-image-content", "pdf-empty-or-unsupported-page");
      }
      const annotations = await page.getAnnotations({ intent: "display" });
      if (annotations.some((annotation) => annotation.subtype !== "Link" || Boolean(annotation.url) || Boolean(annotation.unsafeUrl))) {
        builder.structural("[PDF ANNOTATION]", "pdf-active-content", "pdf-annotation");
      }
      page.cleanup();
    }
    const text = builder.text();
    const state = Object.freeze({ segments: Object.freeze(builder.segments()), derivatives: (sanitizedText: string) => [{ suffix: "", extension: "md", text: sanitizedText }] as const });
    return Object.freeze({ text, coverage: incomplete ? "incomplete" : "complete", state });
  } catch (error) {
    throw new Error("PDF parsing failed closed", { cause: error });
  } finally {
    await task.destroy();
  }
}

class PdfBuilder {
  #text = "";
  #segments: DetectionSegment[] = [];
  literal(value: string): void { this.#text += value; }
  visible(value: string): void { this.add(value); this.literal("\n"); }
  structural(value: string, type: FindingType, detector: string): void {
    const start = this.#text.length;
    this.#text += value;
    this.#segments.push({ value, valueStarts: indexes(value.length, start), valueEnds: indexes(value.length, start + 1), structuralFinding: { type, severity: "critical", detector } });
    this.literal("\n");
  }
  text(): string { return this.#text; }
  segments(): DetectionSegment[] { return this.#segments.map((segment) => Object.freeze(segment)); }
  private add(value: string): void {
    const start = this.#text.length;
    this.#text += value;
    this.#segments.push({ value, valueStarts: indexes(value.length, start), valueEnds: indexes(value.length, start + 1) });
  }
}

function indexes(length: number, offset: number): readonly number[] {
  return Object.freeze(Array.from({ length }, (_, index) => offset + index));
}
