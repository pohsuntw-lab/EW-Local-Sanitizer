import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync("package.json", "utf8"));
const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const dependencyNotes = readFileSync("SECURITY_DEPENDENCIES.md", "utf8");
const violations = [];
const exactVersion = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const approvedBuildOnlyInstallRisks = new Map([
  ["node_modules/electron-winstaller", "5.4.0"],
]);

if (lock.lockfileVersion !== 3 || lock.name !== manifest.name || lock.version !== manifest.version || !lock.packages?.[""]) {
  violations.push("package-lock.json does not match the versioned project manifest");
}

for (const scope of ["dependencies", "devDependencies"]) {
  const declared = manifest[scope] ?? {};
  const lockedRoot = lock.packages?.[""]?.[scope] ?? {};
  for (const [name, version] of Object.entries(declared)) {
    if (typeof version !== "string" || !exactVersion.test(version)) violations.push(`${scope}.${name} must use an exact version`);
    if (lockedRoot[name] !== version) violations.push(`${scope}.${name} does not match the lockfile root`);
    if (!dependencyNotes.includes(`\`${name}\``)) violations.push(`${name} is missing from SECURITY_DEPENDENCIES.md`);
  }
}

for (const [path, metadata] of Object.entries(lock.packages ?? {})) {
  if (!path.startsWith("node_modules/")) continue;
  const name = path.slice("node_modules/".length);
  if (!metadata || typeof metadata !== "object" || typeof metadata.version !== "string" || !exactVersion.test(metadata.version)) {
    violations.push(`${name} has an invalid locked version`);
  }
  if (typeof metadata.integrity !== "string" || !metadata.integrity.startsWith("sha512-")) violations.push(`${name} lacks SHA-512 lock integrity`);
  if (typeof metadata.license !== "string" || metadata.license.length === 0) violations.push(`${name} lacks lockfile license metadata`);
  if (metadata.hasInstallScript === true || metadata.gypfile === true) {
    if (approvedBuildOnlyInstallRisks.get(path) !== metadata.version) violations.push(`${name} introduces unapproved install-script or native-build risk`);
  }
}

if (violations.length > 0) {
  console.error(violations.join("\n"));
  process.exit(1);
}

console.log("Dependency policy check passed: exact lock, integrity, licenses and only documented build-only install/native exceptions.");
