# Plain-text core security review — 2026-09-11

Scope: phase 0 and phase 1 on `codex/plaintext-hardening-v0.1`. The review did not cover CSV, Office, PDF, OCR, Electron or Windows packaging.

## Remediated findings

| Severity | Finding | Resolution |
| --- | --- | --- |
| Critical | The exported verified-capability class exposed a public issuance method, allowing a caller to mint a capability without verification. | Replaced it with a module-private issuer, opaque branded interface, `WeakSet` authenticity check and private `WeakMap` state. |
| High | An authentic transformation was not cryptographically bound to the source text supplied to verification. | Transformation records a source-text SHA-256; verification compares it to the authentic intake source before issuing a capability. |
| High | A structurally forged dictionary snapshot could remove exact-data terms from the second scan. | Dictionary snapshots now carry runtime authenticity in a module-private `WeakSet`; detection, transformation and verification reject forged snapshots. |
| Critical | Overlap removal preferred an earlier high finding over a later critical credential, which could permit credential tokenization under an exact-data type. | Overlap selection now prioritizes severity and length before location; a regression test covers a dictionary term overlapping a password assignment. |
| High | ZIP comments and extra fields could carry bytes outside the entry allowlist. | Inspection now rejects EOCD comments, local/central extras, central comments, nonzero disk starts, malformed UTF-8 names, drive paths, controls and empty path segments. |
| High | Verified package state retained original source text, token-map originals and raw normalized dictionary terms. | Packaging receives a deeply frozen safe-only snapshot; the private state retains only the dictionary snapshot needed for final public-output scanning. |
| Medium | Exact dictionary offset mapping normalized individual code points and could miss composed/decomposed Unicode graphemes. | Mapping now segments grapheme clusters, applies NFKC to each cluster and preserves UTF-16 offsets. |
| Medium | Encrypted envelope headers were validated but not included as AES-GCM additional authenticated data. | The complete version/KDF/cipher/salt/IV header is now AEAD-authenticated; encrypted artifact size limits were added. |
| Medium | JSON Schema validated fields independently but did not verify route, second-scan binding or allowlist/source relationships. | Added local semantic validation after strict schema validation. |
| Medium | Only individual report fields were rescanned. | Verification scans serialized public findings, and packaging rescans the complete manifest, DLP report and README before writing the archive. |

## Residual risks and release gates

- Detection remains deterministic and incomplete by design; a pass is not proof of safety.
- JavaScript strings, caller-owned values and runtime copies cannot be guaranteed to be zeroized. Owned buffers are cleared where possible.
- The custom stored-ZIP implementation has focused negative/tamper tests but has not yet undergone fuzzing or third-party audit.
- Worst-case sessions can consume substantial memory because derivatives and the ZIP are currently assembled in memory. Streaming/resource-budget work is recommended before broad deployment.
- Dictionary SHA-256 values can reveal equality and may permit offline guessing of very low-entropy dictionaries; manifests contain no dictionary text, but a future project-keyed commitment should be considered.
- Network-denied evidence currently covers static source policy and denied JavaScript network entry points. OS-level denial on supported Windows systems remains pending.
- Windows filesystem behavior, installer/runtime behavior, Authenticode and cross-project Forge validation remain pending acceptance gates.
