import { detectText, detectTextSegments, type DetectionContext } from "./detectors.js";
import { tabularDocumentFor, type PlainTextSource } from "./intake.js";
import { parseTabularText } from "./tabular.js";
import type { Finding } from "./types.js";

export function detectSource(source: PlainTextSource, context: DetectionContext): Finding[] {
  if (source.format !== "csv" && source.format !== "tsv") return detectText(source.text, context);
  const document = tabularDocumentFor(source);
  if (!document) throw new Error("Authenticated tabular parse state is unavailable");
  return detectDocument(source.text, document, context);
}

export function detectDerivative(text: string, format: PlainTextSource["format"], context: DetectionContext): Finding[] {
  if (format !== "csv" && format !== "tsv") return detectText(text, context);
  return detectDocument(text, parseTabularText(text, format), context);
}

function detectDocument(text: string, document: ReturnType<typeof parseTabularText>, context: DetectionContext): Finding[] {
  return detectTextSegments(text, document.rows.flatMap((row) => row.map((cell) => ({ ...cell, formulaAware: true }))), context);
}
