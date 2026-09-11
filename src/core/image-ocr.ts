import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import jpeg from "jpeg-js";
import { PNG } from "pngjs";
import { createOCREngine, layoutFlags, supportsFastBuild, type OCREngine, type TextItem } from "tesseract-wasm";
import type { DetectionSegment } from "./detectors.js";
import { MAX_IMAGE_PIXELS } from "./policy.js";
import type { TransformResult } from "./types.js";

export type OcrLanguage = "eng" | "chi_tra";
export interface ImageDerivativeArtifact { readonly suffix: ""; readonly extension: "png"; readonly bytes: Buffer }
export interface ImageOcrState {
  readonly segments: readonly DetectionSegment[];
  readonly language: OcrLanguage;
  readonly modelHash: string;
  derivatives(transformation: TransformResult): readonly ImageDerivativeArtifact[];
  secondScan(transformation: TransformResult): { text: string; segments: readonly DetectionSegment[] };
  destroy(): void;
}
export interface ImageOcrExtraction { readonly text: string; readonly state: ImageOcrState }

export async function extractImageOcr(bytes: Buffer, extension: string, language: OcrLanguage = "eng"): Promise<ImageOcrExtraction> {
  const image = decodeImage(bytes, extension);
  if (image.width * image.height > MAX_IMAGE_PIXELS) throw new Error("Image exceeds pixel policy limit");
  const wasm = await loadWasm();
  const model = loadModel(language);
  const engine = await createOCREngine({ wasmBinary: wasm });
  try {
    engine.loadModel(model);
    const ocr = recognize(engine, image);
    const recognized = image.hasMetadata ? withMetadataFinding(ocr) : ocr;
    const state: ImageOcrState = Object.freeze({
      segments: recognized.segments,
      language,
      modelHash: sha256(model),
      derivatives: (transformation: TransformResult) => [renderDerivative(image, recognized.words, transformation)],
      secondScan: (transformation: TransformResult) => {
        const derivative = renderDerivative(image, recognized.words, transformation);
        return recognize(engine, decodeImage(derivative.bytes, ".png"));
      },
      destroy: () => engine.destroy(),
    });
    return Object.freeze({ text: recognized.text, state });
  } catch (error) {
    engine.destroy();
    throw new Error("Local OCR failed closed", { cause: error });
  } finally {
    wasm.fill(0);
    model.fill(0);
  }
}

interface Pixels { width: number; height: number; data: Uint8Array; hasMetadata: boolean }
interface Recognized { text: string; segments: readonly DetectionSegment[]; words: readonly WordRange[] }
interface WordRange { start: number; end: number; box: TextItem["rect"] }

function recognize(engine: OCREngine, image: Pixels): Recognized {
  engine.loadImage(image as unknown as ImageData);
  const boxes = engine.getTextBoxes("word").filter((box) => box.text.trim().length > 0);
  let text = "";
  const segments: DetectionSegment[] = [];
  const words: WordRange[] = [];
  for (const box of boxes) {
    const value = box.text.trim();
    if (text && !text.endsWith("\n")) text += " ";
    const start = text.length;
    text += value;
    const end = text.length;
    segments.push({ value, valueStarts: indexes(value.length, start), valueEnds: indexes(value.length, start + 1) });
    words.push({ start, end, box: box.rect });
    if ((box.flags & layoutFlags.EndOfLine) !== 0) text += "\n";
  }
  return { text, segments: Object.freeze(segments), words: Object.freeze(words) };
}

function renderDerivative(image: Pixels, words: readonly WordRange[], transformation: TransformResult): ImageDerivativeArtifact {
  if (transformation.scanProfile !== "image") throw new Error("Image derivative requires an image transformation");
  const data = Uint8Array.from(image.data);
  for (const application of transformation.applications) {
    if (application.action !== "delete") throw new Error("Image derivative permits deletion only");
    if (application.type === "image-metadata") continue;
    const matches = words.filter((word) => application.start < word.end && application.end > word.start);
    if (matches.length === 0) throw new Error("Image finding has no authenticated OCR bounding box");
    for (const word of matches) fillBlack(data, image.width, image.height, word.box);
  }
  const output = new PNG({ width: image.width, height: image.height, colorType: 6 });
  output.data = Buffer.from(data);
  return { suffix: "", extension: "png", bytes: PNG.sync.write(output, { colorType: 6 }) };
}

function fillBlack(data: Uint8Array, width: number, height: number, box: TextItem["rect"]): void {
  const left = Math.max(0, Math.floor(box.left) - 2), top = Math.max(0, Math.floor(box.top) - 2);
  const right = Math.min(width, Math.ceil(box.right) + 2), bottom = Math.min(height, Math.ceil(box.bottom) + 2);
  for (let y = top; y < bottom; y += 1) for (let x = left; x < right; x += 1) {
    const offset = (y * width + x) * 4; data[offset] = 0; data[offset + 1] = 0; data[offset + 2] = 0; data[offset + 3] = 255;
  }
}

function decodeImage(bytes: Buffer, extension: string): Pixels {
  if (extension === ".png") {
    if (!bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) throw new Error("PNG signature mismatch");
    const decoded = PNG.sync.read(bytes, { checkCRC: true });
    return { width: decoded.width, height: decoded.height, data: Uint8Array.from(decoded.data), hasMetadata: pngHasMetadata(bytes) };
  }
  if (extension === ".jpg" || extension === ".jpeg") {
    if (!bytes.subarray(0, 3).equals(Buffer.from([255, 216, 255]))) throw new Error("JPEG signature mismatch");
    const decoded = jpeg.decode(bytes, { useTArray: true, formatAsRGBA: true, tolerantDecoding: false });
    return { width: decoded.width, height: decoded.height, data: decoded.data, hasMetadata: jpegHasMetadata(bytes) };
  }
  throw new Error("Unsupported image extension");
}

async function loadWasm(): Promise<Uint8Array> {
  const packageEntry = import.meta.resolve("tesseract-wasm");
  const filename = supportsFastBuild() ? "tesseract-core.wasm" : "tesseract-core-fallback.wasm";
  return Uint8Array.from(await import("node:fs/promises").then(({ readFile }) => readFile(join(dirname(fileURLToPath(packageEntry)), filename))));
}

function loadModel(language: OcrLanguage): Uint8Array {
  const require = createRequire(import.meta.url);
  const entry = require.resolve(`@tesseract.js-data/${language}`);
  return Uint8Array.from(gunzipSync(require("node:fs").readFileSync(join(dirname(entry), "4.0.0", `${language}.traineddata.gz`))));
}

function indexes(length: number, offset: number): readonly number[] { return Object.freeze(Array.from({ length }, (_, index) => offset + index)); }
function sha256(value: Uint8Array): string { return createHash("sha256").update(value).digest("hex"); }

function withMetadataFinding(recognized: Recognized): Recognized {
  const prefix = recognized.text && !recognized.text.endsWith("\n") ? `${recognized.text}\n` : recognized.text;
  const value = "[IMAGE METADATA]";
  const start = prefix.length;
  return { text: `${prefix}${value}\n`, words: recognized.words, segments: Object.freeze([...recognized.segments, {
    value, valueStarts: indexes(value.length, start), valueEnds: indexes(value.length, start + 1),
    structuralFinding: { type: "image-metadata", severity: "critical", detector: "image-metadata-present" },
  }]) };
}

function pngHasMetadata(bytes: Buffer): boolean {
  let offset = 8;
  while (offset + 12 <= bytes.length) {
    const length = bytes.readUInt32BE(offset); const type = bytes.toString("ascii", offset + 4, offset + 8);
    if (new Set(["eXIf", "tEXt", "zTXt", "iTXt", "tIME"]).has(type)) return true;
    offset += 12 + length;
  }
  return false;
}

function jpegHasMetadata(bytes: Buffer): boolean {
  let offset = 2;
  while (offset + 4 <= bytes.length && bytes[offset] === 0xff) {
    const marker = bytes[offset + 1] ?? 0;
    if (marker === 0xda || marker === 0xd9) break;
    const length = bytes.readUInt16BE(offset + 2);
    if (length < 2 || offset + 2 + length > bytes.length) break;
    if (marker === 0xe1 || marker === 0xed || marker === 0xfe) return true;
    offset += 2 + length;
  }
  return false;
}
