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
- Enforces the versioned plain-text policy limits: TXT/Markdown, 10 MiB per file and 100 files per session.
- Validates content and supported Unicode decoding independently of the extension; binary or uncertain input fails closed.

### 2. Format adapters

- Plain text and tabular adapters.
- OOXML adapters for DOCX/XLSX/PPTX.
- PDF adapter for text, page structure and risk indicators.
- Image adapter for EXIF inspection, OCR and bounding boxes.

Parser failure is fail-closed: the file cannot be labelled safe.

### 3. Detection engine

Combines:

- regex and checksum-aware detectors;
- high-confidence secret patterns;
- local exact-data dictionaries;
- enterprise vocabulary rules;
- hidden-content and metadata findings;
- cross-field context scoring.

Every finding contains a session-random UUID `finding_id`, type, severity, source ID, logical location, detector, masked preview and confidence. IDs are not derived from sensitive values. Exported reports never contain the original value or free-form review reason.

Project dictionaries are encrypted local artifacts. Matching normalizes Unicode with NFKC, trims and collapses whitespace, applies the configured Latin case rule and supports explicit aliases only. Fuzzy matching is disabled for the MVP. A dictionary snapshot version and hash bind both scans; only those identifiers enter the manifest.

### 4. Policy and classification

Suggests P0-P3 but requires a user decision. Hard rules:

- credential, password, API-token and private-key findings are critical and must be deleted;
- P3 structural knowledge is local-only;
- unknown parser coverage or unresolved critical/high findings blocks export;
- `keep` on high/critical risk is permitted only as a local review decision with a controlled reason code and remains unresolved for cloud export;
- `keep` on low/medium risk records residual risk and can never result in a completely-safe claim.

### 5. Transformation engine

- Applies delete, tokenization and generalization to an intermediate semantic document.
- Generates stable project-scoped tokens from an encrypted registry. Independent project scope secrets prevent cross-project correlation.
- Never writes transformed data back into the original source.
- For images, draws redactions into new pixels and re-encodes a new flattened PNG.

### 6. Token vault

- Serializes the rehydration map separately.
- Encrypts with AES-256-GCM.
- Derives the key from a user passphrase with `scrypt` and a random salt.
- Stores salt, nonce, authentication tag and ciphertext; never stores the passphrase.
- Stores a versioned header with explicit scrypt parameters so future readers can reproduce the KDF safely.
- Zeroizes in-memory plaintext buffers where the runtime permits; documents residual memory limitations honestly.

JavaScript strings, values retained by callers and runtime-managed copies cannot be guaranteed to be zeroized. The implementation clears owned key/plaintext buffers on success and exception paths and documents this residual limitation.

### 7. Verification and export

- Scans every safe derivative, controlled token label, generalization output and public report field again using the same detector, normalization, policy and dictionary snapshot as the first scan.
- Confirms no unresolved high/critical findings.
- Builds deterministic manifest and sanitized DLP report.
- Creates the Safe Package from an allowlist, not by zipping a working directory.
- Runs ZIP entry inspection after creation.
- Packaging accepts only an opaque verified-export capability created by verification; arbitrary text cannot be passed directly to the packager.
- Reopens the ZIP and checks the allowlist, duplicates, traversal/hidden names and entry sizes. The SHA-256 of the actual completed ZIP bytes is written to a sibling `.sha256` file and local receipt, never into the ZIP itself.

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

## Plain-text core boundaries

Parsing, detection, policy, transformation, verification and packaging are separate modules. Session data is in memory by default and discarded when the session closes. Saving a project/session requires an encrypted local format. Logs and export receipts contain only source IDs, safe filenames, hashes, counts, status and controlled error/event codes; they never contain raw findings or full source paths.

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
