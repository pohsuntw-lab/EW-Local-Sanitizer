import { detectText, detectTextSegments, type DetectionContext } from "./detectors.js";
import { officeStateFor, tabularDocumentFor, type PlainTextSource } from "./intake.js";
import type { OfficeDerivativeArtifact } from "./office.js";
import { parseTabularText } from "./tabular.js";
import type { Finding } from "./types.js";

export function detectSource(source: PlainTextSource, context: DetectionContext): Finding[] {
  if (source.format === "docx" || source.format === "xlsx" || source.format === "pptx") {
    const state = officeStateFor(source);
    if (!state) throw new Error("Authenticated Office parse state is unavailable");
    return detectTextSegments(source.text, state.segments, context, "office");
  }
  if (source.format !== "csv" && source.format !== "tsv") return detectText(source.text, context);
  const document = tabularDocumentFor(source);
  if (!document) throw new Error("Authenticated tabular parse state is unavailable");
  return detectDocument(source.text, document, context);
}

export function detectDerivative(text: string, source: PlainTextSource, context: DetectionContext): Finding[] {
  if (source.format === "docx" || source.format === "xlsx" || source.format === "pptx") {
    return derivativeArtifactsFor(source, text).flatMap((artifact) => artifact.extension === "csv"
      ? detectDocument(artifact.text, parseTabularText(artifact.text, "csv"), context)
      : detectText(artifact.text, context));
  }
  const format = source.format;
  if (format !== "csv" && format !== "tsv") return detectText(text, context);
  return detectDocument(text, parseTabularText(text, format), context);
}

export function derivativeArtifactsFor(source: PlainTextSource, sanitizedText: string): readonly OfficeDerivativeArtifact[] {
  const state = officeStateFor(source);
  if (state) return state.derivatives(sanitizedText);
  return [{ suffix: "", extension: source.derivativeExtension, text: sanitizedText }];
}

function detectDocument(text: string, document: ReturnType<typeof parseTabularText>, context: DetectionContext): Finding[] {
  return detectTextSegments(text, document.rows.flatMap((row) => row.map((cell) => ({ ...cell, formulaAware: true }))), context, "tabular");
}
