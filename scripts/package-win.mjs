import { lstatSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { listPackage } from "@electron/asar";
import { Arch, build, Platform } from "electron-builder";
import manifest from "../package.json" with { type: "json" };
import { assertPackagedRuntime, assertWindowsDistributionFiles, recordUnsignedWindowsArtifacts } from "../dist/build/windows-artifacts.js";

const repositoryRoot = resolve(".");
const outputDirectory = resolve("release/windows-unsigned-test");
if (relative(repositoryRoot, outputDirectory) !== "release/windows-unsigned-test") throw new Error("Unsafe Windows output directory");
for (const variable of ["CSC_LINK", "CSC_NAME", "WIN_CSC_LINK", "WIN_CSC_KEY_PASSWORD"]) {
  if (process.env[variable]) throw new Error(`Signing input ${variable} is forbidden for the unsigned test build`);
}
process.env.CSC_IDENTITY_AUTO_DISCOVERY = "false";
process.env.NO_UPDATE_NOTIFIER = "1";

rmSync(outputDirectory, { recursive: true, force: true });
mkdirSync(outputDirectory, { recursive: true });
try {
  const artifacts = await build({
    targets: Platform.WINDOWS.createTarget(["nsis", "portable"], Arch.x64),
    config: "electron-builder.yml",
    publish: "never",
  });
  const resources = join(outputDirectory, "win-unpacked", "resources");
  assertPackagedRuntime(listPackage(join(resources, "app.asar")));
  for (const path of [
    "app.asar.unpacked/node_modules/tesseract-wasm/dist/tesseract-core.wasm",
    "app.asar.unpacked/node_modules/tesseract-wasm/dist/tesseract-core-fallback.wasm",
    "app.asar.unpacked/node_modules/@tesseract.js-data/eng/4.0.0/eng.traineddata.gz",
    "app.asar.unpacked/node_modules/@tesseract.js-data/chi_tra/4.0.0/chi_tra.traineddata.gz",
  ]) {
    const linked = lstatSync(join(resources, path));
    if (!linked.isFile() || linked.isSymbolicLink() || linked.size === 0) throw new Error(`Invalid unpacked OCR resource: ${path}`);
  }
  const executables = artifacts.filter((path) => path.endsWith(".exe") && resolve(path).startsWith(`${outputDirectory}/`));
  rmSync(join(outputDirectory, "win-unpacked"), { recursive: true, force: true });
  for (const filename of ["builder-debug.yml", "builder-effective-config.yaml", "latest.yml"]) rmSync(join(outputDirectory, filename), { force: true });
  const sourceCommit = readSourceCommit(repositoryRoot);
  const receipt = recordUnsignedWindowsArtifacts(executables, outputDirectory, manifest.version, sourceCommit);
  assertWindowsDistributionFiles(readdirSync(outputDirectory), manifest.version);
  console.log(`Recorded ${receipt.artifacts.length} unsigned Windows test artifacts.`);
} catch (error) {
  rmSync(outputDirectory, { recursive: true, force: true });
  throw error;
}

function readSourceCommit(root) {
  const gitDirectory = resolve(root, ".git");
  const head = readFileSync(join(gitDirectory, "HEAD"), "utf8").trim();
  if (/^[0-9a-f]{40}$/u.test(head)) return head;
  if (!head.startsWith("ref: ")) throw new Error("Cannot identify source commit");
  const reference = head.slice(5);
  if (!/^refs\/[A-Za-z0-9._/-]+$/u.test(reference) || reference.includes("..")) throw new Error("Unsafe Git reference");
  try {
    const commit = readFileSync(join(gitDirectory, reference), "utf8").trim();
    if (/^[0-9a-f]{40}$/u.test(commit)) return commit;
  } catch { /* try packed refs */ }
  const packed = readFileSync(join(gitDirectory, "packed-refs"), "utf8").split(/\r?\n/u);
  const line = packed.find((entry) => entry.endsWith(` ${reference}`));
  const commit = line?.split(" ")[0] ?? "";
  if (!/^[0-9a-f]{40}$/u.test(commit)) throw new Error("Cannot identify source commit");
  return commit;
}
