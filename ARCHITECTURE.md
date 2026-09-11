# Architecture

Version: 0.1.0 MVP

## Delivery architecture

- Windows 10/11 x64 desktop application.
- Electron shell with React and TypeScript UI.
- Node/TypeScript local processing core shared by UI and CLI tests.
- Electron Builder outputs a signed installer and a portable build for controlled testing.
- No server component and no runtime dependency on an external API.

Electron is selected for the first release because Office/PDF parsing, OCR integration and Windows packaging are more practical than a browser-only application. Binary size is secondary to verifiable local processing.

## Security boundary

```text
Enterprise device
├── Original files                  never modified
├── EW Local Sanitizer process      local parsing and decisions
├── encrypted .ewmap                local-only
└── SAFE-PACKAGE.zip                only allowed outbound artifact
                                      ↓ user-controlled upload
                                  ChatGPT / approved AI
```

The application must contain no HTTP client path used by the scanning workflow. External fonts, scripts, OCR services, crash reporting and analytics are prohibited. Update checking is outside MVP.

## Modules

### 1. Intake

- Validates file type, size and parser support.
- Computes SHA-256 before parsing.
- Opens sources read-only.
- Creates stable local source IDs without embedding full paths into exported reports.
- Enforces the versioned content policy limits: TXT/Markdown/CSV/TSV, 10 MiB per file, 100 files and 100 MiB total source bytes per session.
- Uses 25 MiB format limits for Office, PDF and image sources; PDF page count and decoded image pixels have separate resource ceilings.
- Validates content and supported Unicode decoding independently of the extension; binary or uncertain input fails closed. Any C0/C1 control character other than tab, carriage return or line feed is sufficient to reject the file rather than relying on a percentage threshold.

### 2. Format adapters

- Plain text adapter for TXT/Markdown.
- Strict cell-aware CSV/TSV adapter with fixed delimiters, bounded rows/columns/cells, quoted-field mapping back to source offsets and fail-closed malformed-row handling.
- Local OOXML package gate and DOCX/XLSX/PPTX adapters. ZIP central/local headers, entry identities, compression, paths and expanded sizes are validated before XML parsing; DTD/entity declarations are rejected.
- PDF adapter for text, page structure and risk indicators.
- Image adapter for EXIF inspection, OCR and bounding boxes.

Parser failure is fail-closed: the file cannot be labelled safe.

The tabular adapter preserves CSV/TSV syntax in the derivative and scans decoded cells independently. It maps finding ranges back to the immutable source representation before transformation. Formula-like cells require a controlled apostrophe-prefix transformation; this changes the derivative intentionally so spreadsheet software treats the value as literal text.

Office adapters generate a canonical semantic representation in memory and bind every finding set to an `office` scan profile. DOCX extracts body, tables, headers, footers and supported notes; XLSX resolves workbook relationships, shared strings, visible cells, hidden rows/columns/sheets, formulas and comments; PPTX resolves ordered slides, hidden slides, notes and comments. Non-visible content, formulas, external relationships and metadata indicators are forced-delete findings. XLSX emits a generic Markdown index and CSV files only for explicitly approved visible worksheets. Unsupported embedded structures set coverage to incomplete and prevent export.

The PDF adapter uses Mozilla PDF.js on in-memory bytes with font rendering disabled. It extracts text page-by-page and inspects JavaScript actions, attachments, forms, annotations and image paint operators. Any image-bearing, image-only, empty or otherwise uncertain page sets coverage incomplete and blocks export; v0.4 does not rasterize or OCR PDF pages.

The image adapter validates PNG/JPEG signatures, byte and pixel ceilings, decodes locally, and runs pinned `tesseract-wasm` bytes with a pinned local `eng` or `chi_tra` model. OCR words are mapped to source ranges and bounding boxes. Image findings are delete-only; boxes are painted opaque black into a new RGBA buffer and encoded as PNG, discarding source metadata. Verification OCRs that flattened buffer again with the same retained engine/model and scans the result with the same policy and dictionary. Session teardown destroys the WASM engine; JavaScript/WASM memory cannot guarantee full zeroization.

### 3. Detection engine

Combines:

- regex and checksum-aware detectors, including case-insensitive checksum-valid Taiwan IDs and local/`+886`/`886` Taiwan mobile formats;
- context-bound bank-account detection for controlled unquoted and single/double-quoted single-line assignments;
- high-confidence secret patterns;
- local exact-data dictionaries;
- enterprise vocabulary rules;
- hidden-content and metadata findings;
- cross-field context scoring.

Every finding contains a session-random UUID `finding_id`, type, severity, source ID, logical location, detector, masked preview and confidence. IDs are not derived from sensitive values. Exported reports never contain the original value or free-form review reason.

Detector-issued findings are immutable runtime capabilities bound to the source-text hash, policy version and dictionary version/hash. Transformation rejects cloned, modified, cross-text or cross-dictionary findings, as well as decisions that do not reference the current finding set.

Project dictionaries are encrypted local artifacts and carry a project UUID that participates in their snapshot hash. Matching normalizes Unicode with NFKC, trims and collapses whitespace, applies the configured Latin case rule and supports explicit aliases only. Fuzzy matching is disabled for the MVP. Project UUID, dictionary version and hash bind the dictionary, findings, token registry, transformations and both scans; only the manifest's existing project ID plus dictionary version/hash are exported.

Exact-data matching uses a literal trie with failure links so scan cost is linear in normalized input plus reported matches. Versioned policy limits bound dictionary entries, aliases, normalized term volume and findings per file; exceeding a limit is incomplete coverage and fails closed.

### 4. Policy and classification

Suggests P0-P3 but requires a user decision. Hard rules:

- credential, password, API-token and private-key findings are critical and must be deleted; GitHub token rules cover documented legacy, fine-grained and stateless installation formats, credential assignment detection covers controlled unquoted and single-line single/double-quoted key/value forms, and private-key armor requires matching BEGIN/END labels;
- P3 structural knowledge is local-only;
- unknown parser coverage or unresolved critical/high findings blocks export;
- `keep` on high/critical risk is permitted only as a local review decision with a controlled reason code and remains unresolved for cloud export;
- `keep` on low/medium risk records residual risk and can never result in a completely-safe claim.

### 5. Transformation engine

- Applies delete, tokenization and generalization to an intermediate semantic document.
- Generates stable project-scoped tokens from an encrypted registry. Independent project scope secrets prevent cross-project correlation.
- Binds each token registry and transformation to one project UUID; verification rejects cross-project registry reuse.
- Never writes transformed data back into the original source.
- For images, draws redactions into new pixels and re-encodes a new flattened PNG.

### 6. Token vault

- Serializes the rehydration map separately.
- Returns the encrypted bytes with an opaque runtime proof bound to their SHA-256, project UUID and included token set; verification rejects missing, forged, stale, cross-project or modified artifacts.
- Encrypts with AES-256-GCM.
- Derives the key from a user passphrase with `scrypt` and a random salt.
- Stores salt, nonce, authentication tag and ciphertext; never stores the passphrase.
- Stores a versioned, AEAD-authenticated header with explicit scrypt parameters so future readers can reproduce the KDF safely and header tampering fails closed.
- Serializes the outer envelope as canonical JSON with exact top-level and scrypt key sets; extra/duplicate keys, reordered encodings and trailing bytes fail closed instead of becoming unauthenticated data channels.
- Zeroizes in-memory plaintext buffers where the runtime permits; documents residual memory limitations honestly.

JavaScript strings, values retained by callers and runtime-managed copies cannot be guaranteed to be zeroized. The implementation clears owned key/plaintext buffers on success and exception paths and documents this residual limitation.

### 7. Verification and export

- Scans every safe derivative, controlled token label, generalization output and public report field again using the same detector, normalization, policy and dictionary snapshot as the first scan.
- Confirms no unresolved high/critical findings.
- Builds deterministic manifest and sanitized DLP report.
- Creates the Safe Package from an allowlist, not by zipping a working directory.
- Writes the ZIP, checksum and receipt exclusively with identity-scoped cleanup of call-created partial files on write failure; existing or path-substituted targets are never overwritten or removed. Each output is bound to its creation-time device/inode/size identity and reopened without following symbolic links before completion.
- Runs ZIP entry inspection after creation.
- Packaging accepts only an opaque verified-export capability created by verification; arbitrary text cannot be passed directly to the packager.
- The capability privately retains source path/hash/size integrity probes, without retaining source text in package state. Packaging reopens sources without following symlinks and rechecks them at entry, after ZIP inspection and after receipt creation; a mismatch fails closed and cleans up artifacts created by that call.
- Runtime validation rejects unknown classifications/routes, invalid confirmation values, duplicate source IDs and tokenized sessions without an authentic encrypted token-map artifact covering all used tokens.
- P2 confirmation is an opaque runtime capability bound to safe hashes of the exact reviewed project, dictionary, sources, derivatives, public findings and unresolved state; stale, forged or cross-session confirmation fails closed.
- Package basenames use a controlled ASCII format before they enter checksum or receipt metadata.
- Reopens the same created ZIP and checks its file identity, allowlist, duplicates, traversal/hidden names, canonical metadata headers, entry sizes and a 128 MiB aggregate package bound. The ZIP, checksum and receipt identities and bytes are rechecked before return. The SHA-256 of the actual completed ZIP bytes is written to a sibling `.sha256` file and local receipt, never into the ZIP itself.

## Safe Manifest minimum fields

- schema and tool version;
- project and package IDs;
- creation time;
- policy version;
- original source hashes and safe derivative hashes;
- parser coverage status;
- classification and allowed route;
- finding counts by type/severity/action;
- unresolved and residual-risk counts;
- second-scan status;
- token map presence recorded only as a boolean;
- package file allowlist and package hash.

Because an archive cannot contain its own final hash, the manifest records the package hash method (`sha256`) while the final value is stored in the sibling checksum and local receipt. Cross-project validation by EW Enterprise Secure Knowledge Forge is pending integration; the MVP validates `schemas/ew-safe-package-manifest-v0.1.schema.json` locally.

Local semantic validation supplements JSON Schema by requiring type, severity and action finding-count totals to agree, residual risk to equal the keep count, unique source IDs, source/derivative-format consistency, consistent route/second-scan bindings and an allowlist exactly derived from every source derivative entry.

## Core boundaries

Parsing, detection, policy, transformation, verification and packaging are separate modules. Session data is in memory by default and discarded when the session closes. Saving a project/session requires an encrypted local format. Logs and export receipts contain only source IDs, safe filenames, hashes, counts, status and controlled error/event codes; they never contain raw findings or full source paths.

The core can prove that a P2 confirmation was issued for an exact review-state hash, but without the later UI/IPC layer it cannot prove that the issuing call originated from a physical user gesture. The future narrow IPC handler must invoke confirmation only from the explicit review action.

The manifest records each source format and binds it to one or more allowlisted `.md`, `.csv`, `.tsv` or `.png` derivative paths. Verification reparses CSV/TSV derivatives, scans PDF Markdown and locally OCRs flattened PNG derivatives with the same policy and dictionary snapshot; malformed transformed structure, a mismatched `text`/`tabular`/`office`/`pdf`/`image` profile or a remaining blocking finding fails closed.

## Logging

Local logs must not contain original sensitive values or full source paths. Logs contain event IDs, source IDs, detector names, counts, decisions and errors. Users can delete local sessions. No telemetry leaves the device.

## Packaging and signing

- Test phase: clearly marked unsigned portable artifact for named testers only.
- Public website: Authenticode-signed Windows installer and portable package.
- Publish SHA-256 checksums and versioned release notes.
- The website must not describe an unsigned artifact as production-ready.

## Future phases

- macOS signed/notarized build.
- Enterprise policy bundles with administrator signatures.
- Local LLM assistance through an explicit optional connector.
- Enterprise Brain rehydration and RBAC integration.
- Endpoint/browser controls as a separate full AI-DLP product.
