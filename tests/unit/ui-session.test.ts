import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { LocalSessionService } from "../../src/electron/session-service.js";
import type { ExportOptions, ScanOptions } from "../../src/ui/contracts.js";

const scanOptions: ScanOptions = { dictionaryTerms: [], latinCaseSensitive: false, ocrLanguage: "eng", approveAllVisibleWorksheets: false };

test("UI session keeps paths and raw findings out of renderer contracts and exports only after explicit P2 confirmation", async () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-ui-session-"));
  const sourcePath = join(directory, "synthetic-review.txt");
  const raw = "Contact synthetic.person@example.com before the review.";
  writeFileSync(sourcePath, raw);
  const service = new LocalSessionService();
  try {
    const scan = await service.scanPaths([sourcePath], scanOptions);
    const serialized = JSON.stringify(scan);
    assert.ok(!serialized.includes(directory));
    assert.ok(!serialized.includes("synthetic.person@example.com"));
    assert.equal(scan.findings.length, 1);
    const decisions = scan.findings.map((finding) => ({ findingId: finding.findingId, action: "delete" as const }));
    const base: ExportOptions = { sessionId: scan.sessionId, classification: "P2", allowedRoute: "cloud-sanitized", p2Confirmed: false, decisions };
    const blocked = service.export(base, join(directory, "blocked-SAFE-PACKAGE.zip"));
    assert.equal(blocked.status, "blocked");
    if (blocked.status === "blocked") assert.ok(blocked.unresolved.includes("HUMAN_CONFIRMATION_REQUIRED"));
    const exported = service.export({ ...base, p2Confirmed: true }, join(directory, "reviewed-SAFE-PACKAGE.zip"));
    assert.equal(exported.status, "exported");
    if (exported.status === "exported") assert.ok(readFileSync(exported.packagePath).length > 0);
  } finally { service.close(); }
});

test("UI session preserves missing decisions as unresolved and rejects stale session IDs", async () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-ui-block-"));
  const path = join(directory, "source.txt");
  writeFileSync(path, "synthetic.person@example.com");
  const service = new LocalSessionService();
  try {
    const scan = await service.scanPaths([path], scanOptions);
    const missing = service.export({ sessionId: scan.sessionId, classification: "P1", allowedRoute: "cloud-sanitized", p2Confirmed: false, decisions: [] }, join(directory, "missing-SAFE-PACKAGE.zip"));
    assert.equal(missing.status, "blocked");
    if (missing.status === "blocked") assert.ok(missing.unresolved.includes("MISSING_DECISION"));
    const stale = service.export({ sessionId: "00000000-0000-4000-8000-000000000000", classification: "P1", allowedRoute: "cloud-sanitized", p2Confirmed: false, decisions: [] }, join(directory, "stale-SAFE-PACKAGE.zip"));
    assert.deepEqual(stale, { status: "error", code: "NO_SESSION" });
    service.close();
    const closed = service.export({ sessionId: scan.sessionId, classification: "P1", allowedRoute: "cloud-sanitized", p2Confirmed: false, decisions: [] }, join(directory, "closed-SAFE-PACKAGE.zip"));
    assert.deepEqual(closed, { status: "error", code: "NO_SESSION" });
  } finally { service.close(); }
});

test("UI export rolls back a newly written token map when the package target already exists", async () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-ui-rollback-"));
  const sourcePath = join(directory, "synthetic-token.txt");
  const packagePath = join(directory, "existing-SAFE-PACKAGE.zip");
  const tokenMapPath = join(directory, "rolled-back.ewmap");
  writeFileSync(sourcePath, "synthetic.person@example.com");
  writeFileSync(packagePath, "preserve me");
  const service = new LocalSessionService();
  try {
    const scan = await service.scanPaths([sourcePath], scanOptions);
    const result = service.export({ sessionId: scan.sessionId, classification: "P1", allowedRoute: "cloud-sanitized", p2Confirmed: false,
      tokenMapPassphrase: "synthetic-passphrase", decisions: scan.findings.map((finding) => ({ findingId: finding.findingId, action: "tokenize" })) }, packagePath, tokenMapPath);
    assert.deepEqual(result, { status: "error", code: "OUTPUT_EXISTS" });
    assert.equal(existsSync(tokenMapPath), false);
    assert.equal(readFileSync(packagePath, "utf8"), "preserve me");
  } finally { service.close(); }
});

test("Electron boundary uses sandboxed isolated renderer, deny-all permissions and no-connect CSP", () => {
  const main = readFileSync(join(process.cwd(), "src/electron/main.ts"), "utf8");
  const preload = readFileSync(join(process.cwd(), "src/electron/preload.ts"), "utf8");
  const html = readFileSync(join(process.cwd(), "src/renderer/index.html"), "utf8");
  assert.match(main, /contextIsolation:\s*true/);
  assert.match(main, /nodeIntegration:\s*false/);
  assert.match(main, /sandbox:\s*true/);
  assert.match(main, /setPermissionRequestHandler/);
  assert.match(main, /action:\s*"deny"/);
  assert.match(main, /render-process-gone/);
  assert.match(preload, /contextBridge\.exposeInMainWorld/);
  assert.doesNotMatch(preload, /sendSync|on\s*\(/);
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /object-src 'none'/);
});
