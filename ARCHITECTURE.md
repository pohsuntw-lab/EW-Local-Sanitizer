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

Every finding contains `finding_id`, type, severity, source ID, logical location, detector, masked preview and confidence. Exported reports never contain the original value.

### 4. Policy and classification

Suggests P0-P3 but requires a user decision. Hard rules:

- credential/private-key findings are critical and must be deleted;
- P3 structural knowledge is local-only;
- unknown parser coverage or unresolved critical/high findings blocks export;
- `keep` on high risk requires a reason and leaves the package residual risk non-green.

### 5. Transformation engine

- Applies delete, tokenization and generalization to an intermediate semantic document.
- Generates stable project-scoped tokens.
- Never writes transformed data back into the original source.
- For images, draws redactions into new pixels and re-encodes a new flattened PNG.

### 6. Token vault

- Serializes the rehydration map separately.
- Encrypts with AES-256-GCM.
- Derives the key from a user passphrase with `scrypt` and a random salt.
- Stores salt, nonce, authentication tag and ciphertext; never stores the passphrase.
- Zeroizes in-memory plaintext buffers where the runtime permits; documents residual memory limitations honestly.

### 7. Verification and export

- Scans every safe derivative again.
- Confirms no unresolved high/critical findings.
- Builds deterministic manifest and sanitized DLP report.
- Creates the Safe Package from an allowlist, not by zipping a working directory.
- Runs ZIP entry inspection after creation.

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

