import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { detectText } from "../../src/core/detectors.js";
import { dictionary } from "../helpers.js";

test("positive synthetic fixture matrix detects expected critical/high categories", () => {
  const text = readFileSync(join(process.cwd(), "tests/fixtures/data/positive.txt"), "utf8");
  const findings = detectText(text, dictionary(["Example Foundry"]));
  const types = new Set(findings.map((finding) => finding.type));
  for (const type of ["credential", "email", "phone", "taiwan-id", "address", "contract-id", "exact-data"]) assert.ok(types.has(type as never), `missing ${type}`);
});
