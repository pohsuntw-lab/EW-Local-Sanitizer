import { detectText, detectTextSegments, type DetectionContext } from "./detectors.js";
import { imageStateFor, officeStateFor, pdfStateFor, tabularDocumentFor, type PlainTextSource } from "./intake.js";
import { parseTabularText } from "./tabular.js";
import type { Finding, TransformResult } from "./types.js";

export type DerivativeArtifact =
  | { readonly suffix: string; readonly extension: "md" | "csv" | "tsv"; readonly text: string }
  | { readonly suffix: string; readonly extension: "png"; readonly bytes: Buffer };

export function detectSource(source: PlainTextSource, context: DetectionContext): Finding[] {
  if (source.format === "docx" || source.format === "xlsx" || source.format === "pptx") {
    const state = officeStateFor(source);
    if (!state) throw new Error("Authenticated Office parse state is unavailable");
    return detectTextSegments(source.text, state.segments, context, "office");
  }
  if (source.format === "pdf") {
    const state = pdfStateFor(source);
    if (!state) throw new Error("Authenticated PDF parse state is unavailable");
    return detectTextSegments(source.text, state.segments, context, "pdf");
  }
  if (source.format === "png" || source.format === "jpg" || source.format === "jpeg") {
    const state = imageStateFor(source);
    if (!state) throw new Error("Authenticated image OCR state is unavailable");
    return detectTextSegments(source.text, state.segments, context, "image");
  }
  if (source.format !== "csv" && source.format !== "tsv") return detectText(source.text, context);
  const document = tabularDocumentFor(source);
  if (!document) throw new Error("Authenticated tabular parse state is unavailable");
  return detectDocument(source.text, document, context);
}

export function detectDerivative(transformation: TransformResult, source: PlainTextSource, context: DetectionContext): Finding[] {
  const text = transformation.sanitizedText;
  if (source.format === "docx" || source.format === "xlsx" || source.format === "pptx") {
    return derivativeArtifactsFor(source, transformation).flatMap((artifact) => artifact.extension === "csv" && "text" in artifact
      ? detectDocument(artifact.text, parseTabularText(artifact.text, "csv"), context)
      : "text" in artifact ? detectText(artifact.text, context) : []);
  }
  if (source.format === "pdf") return derivativeArtifactsFor(source, transformation).flatMap((artifact) => "text" in artifact ? detectText(artifact.text, context) : []);
  if (source.format === "png" || source.format === "jpg" || source.format === "jpeg") {
    const state = imageStateFor(source);
    if (!state) throw new Error("Authenticated image OCR state is unavailable");
    const scan = state.secondScan(transformation);
    return detectTextSegments(scan.text, scan.segments, context, "image");
  }
  const format = source.format;
  if (format !== "csv" && format !== "tsv") return detectText(text, context);
  return detectDocument(text, parseTabularText(text, format), context);
}

export function derivativeArtifactsFor(source: PlainTextSource, transformation: TransformResult): readonly DerivativeArtifact[] {
  const sanitizedText = transformation.sanitizedText;
  const state = officeStateFor(source);
  if (state) return state.derivatives(sanitizedText);
  const pdf = pdfStateFor(source);
  if (pdf) return pdf.derivatives(sanitizedText);
  const image = imageStateFor(source);
  if (image) return image.derivatives(transformation);
  if (source.derivativeExtension === "png") throw new Error("Authenticated image derivative state is unavailable");
  return [{ suffix: "", extension: source.derivativeExtension, text: sanitizedText }];
}

function detectDocument(text: string, document: ReturnType<typeof parseTabularText>, context: DetectionContext): Finding[] {
  return detectTextSegments(text, document.rows.flatMap((row) => row.map((cell) => ({ ...cell, formulaAware: true }))), context, "tabular");
}
