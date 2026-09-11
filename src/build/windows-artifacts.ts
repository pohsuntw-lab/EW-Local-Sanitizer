import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { removeWrittenFile, writeExclusiveFile, type WrittenFileIdentity } from "../core/exclusive-write.js";

export interface WindowsArtifactRecord {
  readonly filename: string;
  readonly bytes: number;
  readonly sha256: string;
  readonly checksumFilename: string;
}

export interface WindowsBuildReceipt {
  readonly schema: "ew-windows-build-receipt-0.1";
  readonly productVersion: string;
  readonly sourceCommit: string;
  readonly platform: "win32";
  readonly architecture: "x64";
  readonly signed: false;
  readonly distributionStatus: "UNSIGNED_TEST_ONLY";
  readonly artifacts: readonly WindowsArtifactRecord[];
}

const MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024;

export function assertPackagedRuntime(entries: readonly string[]): void {
  const normalized = new Set(entries.map((entry) => entry.replaceAll("\\", "/").replace(/^\//u, "")));
  const required = [
    "dist/electron/main.js", "dist/electron/preload.js", "dist/renderer/app.js", "dist/renderer/index.html", "dist/renderer/styles.css",
    "schemas/ew-safe-package-manifest-v0.1.schema.json", "node_modules/tesseract-wasm/dist/tesseract-core.wasm",
    "node_modules/tesseract-wasm/dist/tesseract-core-fallback.wasm", "node_modules/@tesseract.js-data/eng/4.0.0/eng.traineddata.gz",
    "node_modules/@tesseract.js-data/chi_tra/4.0.0/chi_tra.traineddata.gz",
  ];
  for (const path of required) if (!normalized.has(path)) throw new Error(`Packaged runtime is missing ${path}`);
  for (const path of normalized) {
    if (path.endsWith(".map") || path.endsWith(".d.ts") || /node_modules\/(electron-builder|electron-publish|simple-update-notifier)(?:\/|$)/u.test(path)) {
      throw new Error(`Development-only content entered packaged runtime: ${path}`);
    }
  }
}

export function assertWindowsDistributionFiles(filenames: readonly string[], productVersion: string): void {
  const expected = new Set([
    `EW-Local-Sanitizer-${productVersion}-Windows-x64-Setup-UNSIGNED-TEST-ONLY.exe`,
    `EW-Local-Sanitizer-${productVersion}-Windows-x64-Setup-UNSIGNED-TEST-ONLY.exe.sha256`,
    `EW-Local-Sanitizer-${productVersion}-Windows-x64-Portable-UNSIGNED-TEST-ONLY.exe`,
    `EW-Local-Sanitizer-${productVersion}-Windows-x64-Portable-UNSIGNED-TEST-ONLY.exe.sha256`,
    "WINDOWS-BUILD-RECEIPT.json",
  ]);
  if (filenames.length !== expected.size || filenames.some((filename) => !expected.delete(filename)) || expected.size !== 0) {
    throw new Error("Windows distribution directory contains unexpected or missing content");
  }
}

export function recordUnsignedWindowsArtifacts(
  artifactPaths: readonly string[], outputDirectory: string, productVersion: string, sourceCommit: string,
): WindowsBuildReceipt {
  const output = resolve(outputDirectory);
  const expected = new Set([
    `EW-Local-Sanitizer-${productVersion}-Windows-x64-Setup-UNSIGNED-TEST-ONLY.exe`,
    `EW-Local-Sanitizer-${productVersion}-Windows-x64-Portable-UNSIGNED-TEST-ONLY.exe`,
  ]);
  if (!/^[0-9a-f]{40}$/u.test(sourceCommit) || artifactPaths.length !== expected.size) throw new Error("Invalid Windows build evidence");
  const created: { path: string; identity: WrittenFileIdentity }[] = [];
  try {
    const records = artifactPaths.map((path) => {
      const absolute = resolve(path);
      const filename = basename(absolute);
      if (dirname(absolute) !== output || !expected.delete(filename)) throw new Error("Unexpected Windows artifact path");
      const linked = lstatSync(absolute);
      if (!linked.isFile() || linked.isSymbolicLink() || linked.size < 2 || linked.size > MAX_ARTIFACT_BYTES) throw new Error("Invalid Windows artifact file");
      const bytes = readFileSync(absolute);
      assertUnsignedWindowsPe(bytes);
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      const checksumFilename = `${filename}.sha256`;
      const checksumPath = resolve(output, checksumFilename);
      const identity = writeExclusiveFile(checksumPath, `${sha256}  ${filename}\n`);
      created.push({ path: checksumPath, identity });
      return Object.freeze({ filename, bytes: bytes.length, sha256, checksumFilename });
    }).sort((left, right) => left.filename.localeCompare(right.filename));
    if (expected.size !== 0) throw new Error("Missing Windows artifact");
    const receipt: WindowsBuildReceipt = Object.freeze({
      schema: "ew-windows-build-receipt-0.1", productVersion, sourceCommit, platform: "win32", architecture: "x64",
      signed: false, distributionStatus: "UNSIGNED_TEST_ONLY", artifacts: Object.freeze(records),
    });
    const receiptPath = resolve(output, "WINDOWS-BUILD-RECEIPT.json");
    const identity = writeExclusiveFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
    created.push({ path: receiptPath, identity });
    return receipt;
  } catch (error) {
    for (const file of created.reverse()) removeWrittenFile(file.path, file.identity);
    throw error;
  }
}

export function assertUnsignedWindowsPe(bytes: Buffer): void {
  if (bytes.length < 256 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) throw new Error("Windows artifact lacks a PE signature");
  const peOffset = bytes.readUInt32LE(0x3c);
  if (peOffset < 0x40 || peOffset + 24 > bytes.length || bytes.toString("binary", peOffset, peOffset + 4) !== "PE\0\0") {
    throw new Error("Windows artifact has an invalid PE header");
  }
  const optionalHeader = peOffset + 24;
  const optionalSize = bytes.readUInt16LE(peOffset + 20);
  const magic = bytes.readUInt16LE(optionalHeader);
  const directories = optionalHeader + (magic === 0x20b ? 112 : magic === 0x10b ? 96 : 0);
  const securityDirectory = directories + (4 * 8);
  if (directories === optionalHeader || securityDirectory + 8 > optionalHeader + optionalSize || securityDirectory + 8 > bytes.length) {
    throw new Error("Windows artifact has an invalid optional header");
  }
  const certificateOffset = bytes.readUInt32LE(securityDirectory);
  const certificateSize = bytes.readUInt32LE(securityDirectory + 4);
  if (certificateOffset !== 0 || certificateSize !== 0) throw new Error("Unsigned test artifact unexpectedly contains Authenticode data");
}
