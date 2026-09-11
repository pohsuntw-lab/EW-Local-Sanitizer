import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { PNG } from "pngjs";
import { assertPackagedRuntime, assertUnsignedWindowsPe, assertWindowsDistributionFiles, recordUnsignedWindowsArtifacts } from "../../src/build/windows-artifacts.js";

const version = "0.1.0";
const commit = "a".repeat(40);

test("records checksums for exactly the unsigned setup and portable PE artifacts", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-win-artifacts-"));
  const paths = ["Setup", "Portable"].map((kind, index) => {
    const path = join(directory, `EW-Local-Sanitizer-${version}-Windows-x64-${kind}-UNSIGNED-TEST-ONLY.exe`);
    writeFileSync(path, syntheticPe(index));
    return path;
  });
  const receipt = recordUnsignedWindowsArtifacts(paths, directory, version, commit);
  assert.equal(receipt.signed, false);
  assert.equal(receipt.distributionStatus, "UNSIGNED_TEST_ONLY");
  assert.equal(receipt.artifacts.length, 2);
  for (const artifact of receipt.artifacts) {
    const bytes = readFileSync(join(directory, artifact.filename));
    assert.equal(artifact.sha256, createHash("sha256").update(bytes).digest("hex"));
    assert.equal(readFileSync(join(directory, artifact.checksumFilename), "utf8"), `${artifact.sha256}  ${artifact.filename}\n`);
  }
  assert.deepEqual(JSON.parse(readFileSync(join(directory, "WINDOWS-BUILD-RECEIPT.json"), "utf8")), receipt);
});

test("rejects unexpected, duplicate and symlinked Windows artifacts without leaving evidence", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-win-reject-"));
  const setup = join(directory, `EW-Local-Sanitizer-${version}-Windows-x64-Setup-UNSIGNED-TEST-ONLY.exe`);
  const portable = join(directory, `EW-Local-Sanitizer-${version}-Windows-x64-Portable-UNSIGNED-TEST-ONLY.exe`);
  writeFileSync(setup, syntheticPe(1));
  writeFileSync(portable, syntheticPe(2));
  assert.throws(() => recordUnsignedWindowsArtifacts([setup, setup], directory, version, commit), /Unexpected/);
  assert.equal(existsSync(`${setup}.sha256`), false);
  const target = join(directory, "target.exe");
  writeFileSync(target, syntheticPe(3));
  writeFileSync(setup, syntheticPe(1));
  unlinkSync(portable);
  symlinkSync(target, portable);
  assert.throws(() => recordUnsignedWindowsArtifacts([setup, portable], directory, version, commit), /Invalid Windows artifact file/);
  assert.equal(existsSync(`${setup}.sha256`), false);
  assert.equal(existsSync(join(directory, "WINDOWS-BUILD-RECEIPT.json")), false);
});

test("rejects an Authenticode-bearing PE from the unsigned test channel", () => {
  const unsigned = syntheticPe(1);
  assert.doesNotThrow(() => assertUnsignedWindowsPe(unsigned));
  const signed = Buffer.from(unsigned);
  signed.writeUInt32LE(256, 0x98 + 112 + 32);
  signed.writeUInt32LE(32, 0x98 + 112 + 36);
  assert.throws(() => assertUnsignedWindowsPe(signed), /Authenticode/);
});

test("Windows builder config cannot publish or silently sign", () => {
  const config = readFileSync(join(process.cwd(), "electron-builder.yml"), "utf8");
  const script = readFileSync(join(process.cwd(), "scripts/package-win.mjs"), "utf8");
  const eulaManifest = JSON.parse(readFileSync(join(process.cwd(), "build", "generated", "eula-manifest.json"), "utf8")) as {
    format: string;
    formatVersion: string;
    agreementVersion: string;
    agreements: Array<{ locale: string; sourcePath: string; plainTextPath: string; sha256: string }>;
  };
  const nsisEula = readFileSync(join(process.cwd(), "build", "generated", "nsis-eula.nsh"), "utf8");
  const smokeScript = readFileSync(join(process.cwd(), "scripts", "windows-smoke.ps1"), "utf8");
  const iconBytes = readFileSync(join(process.cwd(), "build", "icon.png"));
  const icon = PNG.sync.read(iconBytes);
  assert.match(config, /UNSIGNED-TEST-ONLY/);
  assert.match(config, /forceCodeSigning: false/);
  assert.match(config, /signAndEditExecutable: true/);
  assert.match(config, /signExecutable: false/);
  assert.match(config, /nsis: 1\.2\.1/);
  assert.match(config, /include: build\/generated\/nsis-eula\.nsh/);
  assert.match(config, /installerLanguages:\s*\n\s*- zh_TW\s*\n\s*- en_US/);
  assert.match(config, /multiLanguageInstaller: true/);
  assert.match(config, /icon: build\/icon\.png/);
  assert.match(config, /legalTrademarks: Embodied Worker/);
  assert.equal(createHash("sha256").update(iconBytes).digest("hex"), "1b8718012d27b7a2ef4c18278a5d90efc01346cff585a877e305a0e0d5818a72");
  assert.equal(icon.width, icon.height);
  assert.ok(icon.width >= 512);
  assert.equal(icon.alpha, true);
  assert.equal(eulaManifest.format, "ewls-eula-manifest");
  assert.equal(eulaManifest.formatVersion, "1.0");
  assert.match(eulaManifest.agreementVersion, /^EWLS-EULA-[0-9]+\.[0-9]+$/);
  assert.deepEqual(eulaManifest.agreements.map(({ locale }) => locale), ["zh-TW", "en-US"]);
  for (const agreement of eulaManifest.agreements) {
    const source = readFileSync(join(process.cwd(), agreement.sourcePath));
    const plainText = readFileSync(join(process.cwd(), agreement.plainTextPath), "utf8");
    assert.equal(agreement.sha256, createHash("sha256").update(source).digest("hex"));
    assert.match(plainText, /具象職人股份有限公司|Embodied Worker Co\., Ltd\./);
    assert.match(plainText, /第三方元件|Third-party and open-source components/);
    assert.match(plainText, /不保證完全偵測|does not guarantee perfect detection/);
  }
  assert.match(nsisEula, /MUI_LICENSEPAGE_CHECKBOX/);
  assert.match(nsisEula, /EWLSACCEPTEULA/);
  assert.match(nsisEula, /SetErrorLevel 2/);
  assert.match(nsisEula, /eula-acceptance\.ini/);
  assert.match(nsisEula, /explicitAcceptance" "true/);
  for (const agreement of eulaManifest.agreements) assert.match(nsisEula, new RegExp(agreement.sha256));
  assert.match(smokeScript, /\/EWLSACCEPTEULA=\$silentEulaToken/);
  assert.match(smokeScript, /\/LANG=1033/);
  assert.match(script, /publish: "never"/);
  assert.match(script, /CSC_IDENTITY_AUTO_DISCOVERY = "false"/);
  assert.match(script, /WIN_CSC_LINK/);
  assert.match(script, /"\.icon-ico"/);
});

test("packaged runtime allowlist requires local schema/OCR assets and excludes build tooling", () => {
  const required = [
    "dist/electron/main.js", "dist/electron/preload.js", "dist/renderer/app.js", "dist/renderer/index.html", "dist/renderer/styles.css",
    "schemas/ew-safe-package-manifest-v0.1.schema.json", "node_modules/tesseract-wasm/dist/tesseract-core.wasm",
    "node_modules/tesseract-wasm/dist/tesseract-core-fallback.wasm", "node_modules/@tesseract.js-data/eng/4.0.0/eng.traineddata.gz",
    "node_modules/@tesseract.js-data/chi_tra/4.0.0/chi_tra.traineddata.gz",
  ];
  assert.doesNotThrow(() => assertPackagedRuntime(required));
  assert.throws(() => assertPackagedRuntime(required.filter((path) => !path.includes("schema.json"))), /missing/);
  assert.throws(() => assertPackagedRuntime([...required, "node_modules/electron-publish/index.js"]), /Development-only/);
  assert.throws(() => assertPackagedRuntime([...required, "dist/electron/main.js.map"]), /Development-only/);
});

test("Windows distribution directory permits only two executables, checksums and receipt", () => {
  const expected = [
    `EW-Local-Sanitizer-${version}-Windows-x64-Setup-UNSIGNED-TEST-ONLY.exe`,
    `EW-Local-Sanitizer-${version}-Windows-x64-Setup-UNSIGNED-TEST-ONLY.exe.sha256`,
    `EW-Local-Sanitizer-${version}-Windows-x64-Portable-UNSIGNED-TEST-ONLY.exe`,
    `EW-Local-Sanitizer-${version}-Windows-x64-Portable-UNSIGNED-TEST-ONLY.exe.sha256`,
    "WINDOWS-BUILD-RECEIPT.json",
  ];
  assert.doesNotThrow(() => assertWindowsDistributionFiles(expected, version));
  assert.throws(() => assertWindowsDistributionFiles([...expected, "latest.yml"], version), /unexpected or missing/);
});

function syntheticPe(marker: number): Buffer {
  const bytes = Buffer.alloc(512);
  bytes.write("MZ", 0, "ascii");
  bytes.writeUInt32LE(0x80, 0x3c);
  bytes.write("PE\0\0", 0x80, "binary");
  bytes.writeUInt16LE(0x8664, 0x84);
  bytes.writeUInt16LE(240, 0x94);
  bytes.writeUInt16LE(0x20b, 0x98);
  bytes[0x200 - 1] = marker;
  return bytes;
}
