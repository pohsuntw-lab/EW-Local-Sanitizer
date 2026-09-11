declare module "tesseract-wasm" {
  export interface IntRect { left: number; top: number; right: number; bottom: number }
  export interface TextItem { rect: IntRect; flags: number; confidence: number; text: string }
  export interface OCREngine {
    destroy(): void;
    loadModel(model: Uint8Array | ArrayBuffer): void;
    loadImage(image: ImageData): void;
    getTextBoxes(unit: "line" | "word"): TextItem[];
  }
  export const layoutFlags: { StartOfLine: number; EndOfLine: number };
  export function supportsFastBuild(): boolean;
  export function createOCREngine(options: { wasmBinary: Uint8Array | ArrayBuffer }): Promise<OCREngine>;
}
