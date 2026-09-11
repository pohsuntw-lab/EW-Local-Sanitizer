# Acceptance Criteria

Version: 0.1.0 MVP

## A. Local-only operation

- A1: Core scan, review, transformation and export complete while outbound network access is denied.
- A2: The application contains no telemetry, analytics, advertising, cloud OCR or remote AI call.
- A3: No source content is placed in a URL, log, crash report or update request.
- A4: UI states that already-uploaded content cannot be protected retroactively.

## B. Source integrity and parsing

- B1: Original source SHA-256 is identical before and after processing.
- B2: Supported formats are opened read-only and never overwritten.
- B3: Parser failure, encrypted input, unsupported feature or incomplete OCR coverage is visible and blocks a safe status.
- B3a: Plain-text intake supports TXT/Markdown only, rejects files over 10 MiB, rejects sessions over 100 files, and does not rely on extension alone.
- B3b: Unsupported encodings, binary content masquerading as text and uncertain decoding fail closed.
- B4: DOCX test detects text in body, table, header/footer and comment fixtures.
- B5: XLSX test identifies hidden sheets, hidden rows/columns, formulas, comments and external-link indicators in fixtures.
- B6: PPTX test identifies slide text, speaker notes, comments and document-property indicators in fixtures.
- B7: PDF test distinguishes text-layer and image-only pages and flags embedded active-content indicators when detectable.
- B8: Image test performs local OCR and strips supported EXIF/GPS metadata from the derivative.

## C. Detection

- C1: Synthetic private keys, OpenAI-style tokens, GitHub tokens, passwords and connection strings are critical findings.
- C2: Synthetic Taiwan ID, phone, email, address, bank and contract identifiers are detected according to published fixture expectations.
- C3: Local exact-data dictionaries find synthetic customer, employee, project and technical terms.
- C4: Reports show masked previews only; raw sensitive values do not appear in exported JSON.
- C5: No-finding output states that absence of detection is not proof of safety.
- C6: Finding IDs are random/session-scoped and are not derived from sensitive values.
- C7: Project exact-data dictionaries are encrypted locally; both scans use the same version/hash and normalization snapshot, and manifests expose no dictionary value.

## D. Transformation

- D1: Delete removes the value from the derivative and second scan.
- D2: Tokenize uses a stable project-scoped token without leaking the original.
- D3: Generalize replaces exact values according to a recorded rule.
- D4: Credentials and private keys cannot be kept or exported.
- D5: A high/critical local `keep` requires a controlled reason code and remains unresolved, permanently blocking cloud package creation. Free-form local detail is never packaged.
- D5a: Low/medium `keep` records residual risk and never produces a completely-safe status.
- D6: Image redactions are flattened into new pixels; recovering underlying text from layers is impossible.

## E. Token vault

- E1: `.ewmap` is AES-256-GCM encrypted with a scrypt-derived key, random salt and nonce.
- E2: Wrong passphrase or modified ciphertext fails authentication without partial output.
- E3: Passphrases are never stored or logged.
- E4: `.ewmap` is never placed inside the Safe Package.
- E5: The versioned `.ewmap` header records KDF, explicit scrypt parameters, cipher, salt, IV and authentication tag.
- E6: Equal normalized originals receive the same token in one project; independent project scope secrets prevent cross-project correlation.
- E7: Owned key/plaintext buffers are cleared on success and exception paths; documentation states JavaScript/caller memory limitations.

## F. Safe Package

- F1: Export is blocked when critical/high findings remain unresolved or parser coverage failed.
- F2: A second scan runs against derivatives before export.
- F3: ZIP construction uses an allowlist containing only `SAFE_SOURCE/`, `SAFE-MANIFEST.json`, `DLP-REPORT.json` and `README-SAFE-UPLOAD.md`.
- F4: Original files, full paths, raw findings, local session data and token maps are absent.
- F5: Package and derivative hashes verify successfully.
- F6: This repository validates manifests locally against the versioned v0.1 schema; EW Enterprise Secure Knowledge Forge cross-project validation remains pending integration.
- F7: Packaging accepts only a verified result; callers cannot bypass unresolved, coverage, source-integrity, policy or second-scan checks by supplying arbitrary derivative text.
- F8: ZIP post-write inspection rejects non-allowlisted, duplicate, traversal, hidden and oversized entries.
- F9: The package checksum is SHA-256 of the actual ZIP bytes and is stored in a sibling `.sha256` file and local receipt, not inside the ZIP.
- F10: Token labels, controlled generalizations and public report fields are validated and scanned before export.

For v0.1, F6 means local validation against `schemas/ew-safe-package-manifest-v0.1.schema.json`. Validation by EW Enterprise Secure Knowledge Forge is pending integration and must not be claimed complete.

## I. Plain-text hardening evidence

- I1: Positive, negative and tamper fixtures are independent test suites and contain synthetic data only.
- I2: Read-only intake proves source SHA-256 remains identical before and after processing.
- I3: The complete plain-text workflow passes with network APIs denied and the source policy scan finds no network/telemetry path.
- I4: Report reason, token-label and generalization injection attempts fail closed.

## G. Windows delivery

- G1: Application runs on supported Windows 10/11 x64 test systems without administrator rights for ordinary use.
- G2: Installer, uninstall and portable build are tested.
- G3: Public installer is Authenticode signed; unsigned builds are labelled test-only and are not linked as production downloads.
- G4: Website publishes version, file size, SHA-256, minimum OS and release notes.

## H. User acceptance journey

- H1: A nontechnical user can sanitize a supported synthetic document without command-line work.
- H2: The user can understand why a file is blocked and what action is required.
- H3: The user can locate the Safe Package and distinguish it from the local token map.
- H4: The application never uploads the package automatically.
