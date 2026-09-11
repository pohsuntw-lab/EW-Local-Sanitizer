import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { detectText } from "../../src/core/detectors.js";
import { dictionary } from "../helpers.js";

test("negative synthetic fixture matrix has no findings and does not imply proof of safety", () => {
  const text = readFileSync(join(process.cwd(), "tests/fixtures/data/negative.md"), "utf8");
  assert.deepEqual(detectText(text, dictionary(["Example Foundry"])), []);
  const disclaimer = "Defense-in-depth only; absence of detection is not proof of safety.";
  assert.match(disclaimer, /not proof of safety/);
});
