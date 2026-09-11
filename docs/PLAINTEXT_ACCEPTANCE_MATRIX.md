# Plain-text acceptance matrix

Evidence for branch `codex/plaintext-hardening-v0.1`. All fixtures use synthetic values.

| Requirement | Automated evidence | Status |
| --- | --- | --- |
| A1–A3, I3 local-only/no telemetry | Source policy lint plus `core workflow completes when network entry points are denied` | Pass for the core; desktop/runtime delivery remains pending |
| B1–B3b, F14, I2 read-only integrity and fail-closed text intake | `intake.test.ts` source hash/mode, mutation, size, extension, encoding, sparse C0/C1 controls and binary tests plus `verification-package.test.ts` post-verification mutation and artifact-cleanup test | Pass for TXT/Markdown |
| C1–C7 deterministic detection, random IDs and encrypted dictionary | `detection-transform.test.ts` private-key armor, quoted/unquoted credential, overlap and identity tests plus positive/negative fixtures | Pass for implemented plain-text detectors |
| D1–D5a controlled transformation and residual risk | transformation injection/forced-delete tests plus verification high/medium keep tests | Pass for text derivatives |
| E1–E7 authenticated versioned vault and project token scope | dictionary/token registry unit tests and tamper fixture | Pass; JavaScript zeroization limitation documented |
| F1–F5, F7–F14 verified export, schema/semantic validation, allowlist, ZIP inspection and hashes | `verification-package.test.ts` | Pass for the repository v0.1 schema and single/multiple plain-text item model |
| I5–I6 exclusive output and post-write identity | `verification-package.test.ts` write-conflict, cleanup and path-replacement tests | Pass for regular local files |
| F6 cross-project Forge compatibility | No external schema or integration harness supplied | Pending integration; no compatibility claim |
| G1–G4 Windows delivery | Out of scope for this branch | Not started |
| H1–H4 nontechnical UI journey | Electron UI is out of scope for this branch | Not started |
| B4–B8 and D6 rich documents/images | CSV/Office/PDF/OCR/image work is out of scope for this branch | Not started |

`npm run package:win` remains a deliberate failing placeholder. No release, merge, installer or upload is produced by this branch.
