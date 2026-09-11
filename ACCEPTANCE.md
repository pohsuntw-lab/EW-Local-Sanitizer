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
- B3a: Plain-text intake supports TXT/Markdown only, rejects files over 10 MiB, sessions over 100 files or 100 MiB aggregate source bytes, and does not rely on extension alone.
- B3b: Unsupported encodings, binary content masquerading as text and uncertain decoding fail closed; a single disallowed C0/C1 control character is rejected even in otherwise valid Unicode text.
- B3c: CSV/TSV parsing uses fixed format delimiters, preserves quoted delimiters and newlines, scans decoded cells independently, and rejects malformed quotes, inconsistent columns, lone carriage returns and resource-limit overflow.
- B3d: Formula-like tabular cells cannot be kept, deleted, tokenized or generalized through an unrelated rule; the controlled literal-text transformation is visible in the public finding counts and leaves no formula prefix on second scan.
- B4: DOCX synthetic tests detect body, table, header/footer, deleted revision and comment content; cloud derivatives omit deleted/comment content and controlled transformations remove detected sensitive values.
- B5: XLSX synthetic tests identify hidden sheets, hidden rows/columns, formulas, comments and external-link indicators; export requires explicit visible-sheet approval and produces a Markdown index plus CSV per approved visible sheet.
- B6: PPTX synthetic tests identify visible/hidden slide text, speaker notes, comments, external links and document-property indicators; hidden/notes/comment content is absent from the derivative.
- B6a: OOXML intake validates extension/content-type agreement, central and local ZIP headers, duplicate/unsafe paths, encryption/compression/size limits and XML encoding; macros, DTD/entities and malformed packages fail closed.
- B6b: Office media, drawing, chart, diagram, embedded-object, ActiveX, custom-XML or signature entries make parser coverage incomplete until later format/OCR support is implemented.
- B7: PDF test distinguishes text-layer and image-only pages and flags embedded active-content indicators when detectable.
- B8: Image test performs offline local OCR from pinned WASM/model bytes, maps words to bounding boxes, emits a flattened PNG and strips supported PNG ancillary and JPEG EXIF/GPS metadata from the derivative.
- B9: PDF/image byte, page and pixel ceilings plus extension/signature mismatch fail closed; an image-bearing PDF remains blocked until PDF raster OCR is implemented.

## C. Detection

- C1: Synthetic standard/RSA/EC/DSA/OpenSSH/encrypted/PGP private-key blocks, OpenAI-style tokens, documented GitHub legacy/fine-grained/stateless token shapes, passwords and connection strings—including single-line quoted key/value assignments—are critical findings; prefix-only examples remain negative and mismatched key armor is not consumed as one block.
- C2: Synthetic checksum-valid Taiwan IDs in upper/lowercase, Taiwan mobile numbers in local and `+886`/`886` forms, email, address, quoted/unquoted contextual bank accounts and contract identifiers are detected according to published fixture expectations; a bank-account field name without a numeric value remains negative.
- C3: Local exact-data dictionaries find synthetic customer, employee, project and technical terms using bounded literal matching; dictionary or finding ceilings fail closed without partial-coverage claims.
- C4: Reports show masked previews only; raw sensitive values do not appear in exported JSON.
- C5: No-finding output states that absence of detection is not proof of safety.
- C6: Finding IDs are random/session-scoped and are not derived from sensitive values.
- C7: Project exact-data dictionaries are encrypted locally and bound to a project UUID; both scans use the same project/version/hash and normalization snapshot, cross-project substitution fails, and manifests expose no dictionary value.

## D. Transformation

- D1: Delete removes the value from the derivative and second scan.
- D2: Tokenize uses a stable project-scoped token without leaking the original.
- D3: Generalize replaces exact values according to a recorded rule.
- D4: Credentials and private keys cannot be kept or exported.
- D4a: Transformation accepts only immutable detector-issued findings bound to the same text, policy and dictionary; finding retyping, cloning, cross-dictionary reuse and unrelated decisions fail closed.
- D4b: Transformation requires the detector's complete finding-set capability and matching `text`, `tabular`, `office`, `pdf` or `image` scan profile; omitted findings or a generic-text scan substituted for structured input fail closed.
- D5: A high/critical local `keep` requires a controlled reason code and remains unresolved, permanently blocking cloud package creation. Free-form local detail is never packaged.
- D5a: Low/medium `keep` records residual risk and never produces a completely-safe status.
- D6: Image redactions are flattened into new pixels; recovering underlying text from layers is impossible.
- D7: Image findings accept delete only in the MVP; tokenize, generalize and keep cannot create an image export capability.

## E. Token vault

- E1: `.ewmap` is AES-256-GCM encrypted with a scrypt-derived key, random salt and nonce.
- E2: Wrong passphrase or modified ciphertext fails authentication without partial output.
- E3: Passphrases are never stored or logged.
- E4: `.ewmap` is never placed inside the Safe Package.
- E4a: A transformation containing project tokens cannot be verified for export unless an opaque proof from actual token-map encryption matches the project, encrypted payload hash and every used token; missing, forged, stale or tampered artifacts fail closed.
- E5: The versioned `.ewmap` header records KDF, explicit scrypt parameters, cipher, salt, IV and authentication tag.
- E6: Equal normalized originals receive the same token in one project; independent project scope secrets prevent cross-project correlation, and verification rejects a transformation produced by a registry bound to another project UUID.
- E7: Owned key/plaintext buffers are cleared on success and exception paths; documentation states JavaScript/caller memory limitations.
- E8: Encrypted envelopes accept only the canonical versioned JSON encoding with exact header/scrypt fields; extra or duplicate keys, field reordering and trailing bytes fail closed.

## F. Safe Package

- F1: Export is blocked when critical/high findings remain unresolved or parser coverage failed.
- F2: A second scan runs against derivatives before export.
- F3: ZIP construction uses an allowlist containing only `SAFE_SOURCE/`, `SAFE-MANIFEST.json`, `DLP-REPORT.json` and `README-SAFE-UPLOAD.md`.
- F4: Original files, full paths, raw findings, local session data and token maps are absent.
- F5: Package and derivative hashes verify successfully.
- F6: This repository validates manifests locally against the versioned v0.1 schema; EW Enterprise Secure Knowledge Forge cross-project validation remains pending integration.
- F7: Packaging accepts only a verified result; callers cannot bypass unresolved, coverage, source-integrity, authentic-finding, policy or second-scan checks by supplying arbitrary findings or derivative text.
- F8: ZIP post-write inspection rejects non-allowlisted, duplicate, traversal, hidden, noncanonical-header and oversized entries/packages; deterministic mutation fixtures fail closed for every single-byte change and truncation of a baseline archive.
- F9: The package checksum is SHA-256 of the actual ZIP bytes and is stored in a sibling `.sha256` file and local receipt, not inside the ZIP.
- F10: Token labels, controlled generalizations and public report fields are validated and scanned before export.
- F11: Verification rejects invalid runtime classification, route and confirmation fields plus duplicate source IDs; package basenames reject control characters and checksum-line injection.
- F12: Manifest finding-count maps accept only known finding types, severities and actions; their dimension totals agree, residual risk equals the keep count, and manifest source IDs are unique.
- F13: P2 does not accept a caller-provided boolean; its confirmation capability is bound to the exact project, dictionary, source and derivative/report review state, and missing, forged or stale confirmation blocks export.
- F14: Source identity, size and SHA-256 are rechecked through Safe Package completion. A source changed after verification blocks packaging and leaves no ZIP, checksum or receipt created by that call.
- F15: Verification tests the complete MVP route matrix: P0 permits approved or sanitized cloud routes, P1/P2 permit only sanitized cloud routes, and P3 never receives an export capability even when its requested route is local-only.
- F16: A multi-file session produces one ordered derivative and source/hash manifest record per source, aggregates finding counts correctly, and binds every source to package-time integrity checks.
- F17: CSV/TSV sources produce matching allowlisted derivative extensions, record their source format in the manifest, and are reparsed cell-by-cell during second scan before a verified export capability is issued.
- F18: Office manifests record all derivatives per source; XLSX index/sheet files are allowlisted and hashed individually, while DOCX/PPTX produce only structured Markdown derivatives.
- F19: Image derivatives are binary PNG allowlist entries and pass a second local OCR/dictionary scan with the same model and scan profile before packaging.

For v0.1, F6 means local validation against `schemas/ew-safe-package-manifest-v0.1.schema.json`. Validation by EW Enterprise Secure Knowledge Forge is pending integration and must not be claimed complete.

## I. Plain-text hardening evidence

- I1: Positive, negative and tamper fixtures are independent test suites and contain synthetic data only.
- I2: Read-only intake proves source SHA-256 remains identical before and after processing.
- I3: The complete plain-text workflow passes with network APIs denied and the source policy scan finds no network/telemetry path.
- I4: Report reason, token-label and generalization injection attempts fail closed.
- I5: Existing export targets are never overwritten; write conflicts clean up newly created package artifacts and preserve pre-existing files.
- I6: Post-write validation and failure cleanup are bound to the exact regular files created by the export call; path replacement or symbolic-link substitution fails closed without deleting the replacement, and ZIP/checksum/receipt bytes are rechecked before completion.
- I7: The offline dependency-policy check enforces exact direct versions, lockfile agreement, SHA-512 integrity, recorded licenses and documentation, and rejects unapproved install-script/native-build flags. Electron shell/install native artifacts are separately enumerated and reviewed; the recorded baseline audit has zero known vulnerabilities.
- I8: Independent synthetic CSV/TSV positive, negative and tamper fixtures cover sensitive-cell detection, formula neutralization, malformed/binary rejection and post-verification source mutation.
- I9: Independent synthetic DOCX/XLSX/PPTX positive, negative and tamper fixtures cover required structures, macro/content mismatch rejection, incomplete embedded-content coverage and source-integrity enforcement.
- I10: Synthetic PDF/image tests cover text-layer extraction, image-only and active-content indicators, real offline WASM OCR, metadata stripping, flattened pixel redaction, signature mismatch and format-aware second scan.

## G. Windows delivery

- G1: Application runs on supported Windows 10/11 x64 test systems without administrator rights for ordinary use.
- G2: Installer, uninstall and portable build are tested.
- G3: Public installer is Authenticode signed; unsigned builds are labelled test-only and are not linked as production downloads.
- G4: Website publishes version, file size, SHA-256, minimum OS and release notes.
- G5: The controlled cross-build emits exactly one Windows x64 NSIS installer and one portable executable, both named `UNSIGNED-TEST-ONLY`, plus SHA-256 sibling files and a local build receipt. Real-Windows execution remains required before G2 is complete.
- G6: Packaging refuses signing environment inputs, disables automatic signing discovery and never invokes publishing. Unsigned outputs are not a public release.
- G7: Artifact verification rejects missing, duplicate, unexpected, non-regular, symbolic-link, oversized or non-PE outputs and removes partial checksum/receipt evidence.
- G8: Packaged ASAR/runtime inspection confirms the manifest schema and local OCR model/WASM resources are present while Electron Builder, publisher/update tooling, source maps and declaration files are absent.

## H. User acceptance journey

- H1: A nontechnical user can sanitize a supported synthetic document without command-line work.
- H2: The user can understand why a file is blocked and what action is required.
- H3: The user can locate the Safe Package and distinguish it from the local token map.
- H4: The application never uploads the package automatically.

## J. Electron UI security and workflow

- J1: Renderer runs with sandbox enabled, context isolation enabled, Node integration disabled and a CSP with `connect-src 'none'`; permission requests, external navigation and new windows are denied.
- J2: Preload exposes only typed select/scan, reviewed export and session-close calls. Renderer data contains masked findings and local display metadata but no raw finding value, full source path, registry, dictionary snapshot or export capability.
- J3: Missing decisions, incomplete coverage, P3 routing, missing P2 confirmation and short/missing token-map passphrases remain visibly blocked.
- J4: The explicit reviewed-export IPC action creates the P2 confirmation, performs second scan and invokes packaging in the main process; renderer cannot call the package writer directly.
- J5: Closing or replacing a session destroys OCR resources and disposes the token registry. Automated UI-session and boundary tests pass without importing Electron into the core test runtime.
- J6: The built renderer's initial local preview has been reviewed for layout and readable blocked states. The complete synthetic click journey and native dialogs remain pending Windows UAT before packaging begins.
