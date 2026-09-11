# EW Local Sanitizer｜企業知識本地脫敏器

Version: 0.1.0 MVP  
Publisher: Embodied Worker Co., Ltd. / 具象職人股份有限公司  
Primary platform: Windows 10/11 x64

## Product purpose

EW Local Sanitizer prepares enterprise documents before they are uploaded to ChatGPT or another approved cloud AI service. All parsing, scanning, review, tokenization, redaction and export run on the user's computer. The application does not upload source content, use telemetry or require an external API key.

The product is a pre-upload sanitization tool, not a complete endpoint DLP platform. It does not monitor browsers, email, cloud drives or network traffic, and it cannot protect a file that was already uploaded elsewhere.

## Intended users

- Employees preparing SOPs, meeting records, reports and project documents for AI knowledge forging.
- Department knowledge stewards reviewing sanitization decisions.
- Enterprise administrators defining local dictionaries and export policy.

## Primary workflow

1. User drags files into the application.
2. Application parses visible text, supported hidden structures and image text locally.
3. Application reports findings by type, severity, file and location.
4. User chooses delete, tokenize, generalize or keep for each finding.
5. High- and critical-risk findings require resolution. A local review may record keep with a controlled reason code and separate local detail, but that finding remains unresolved for cloud export.
6. Application creates a safe derivative and scans the derivative again.
7. Application exports an uploadable Safe Package and a separate encrypted local token map.
8. EW Enterprise Secure Knowledge Forge consumes only the Safe Package.

## Supported MVP inputs

| Format | MVP treatment | Safe derivative |
| --- | --- | --- |
| TXT, Markdown | Direct text parsing | UTF-8 Markdown |
| CSV, TSV | Cell-aware parsing | Sanitized CSV/TSV |
| DOCX | Extract body, tables, headers, footers, comments and metadata indicators | Structured Markdown |
| XLSX | Inspect visible/hidden sheets, cells, comments, formulas and external-link indicators | CSV per approved sheet plus Markdown index |
| PPTX | Extract slide text, notes, comments and metadata indicators | Markdown by slide |
| PDF | Extract text layer; flag attachments, forms, JavaScript, annotations and image/image-only pages | Structured Markdown only when every page has supported text-only coverage; image-bearing PDF export is blocked in v0.4 |
| PNG, JPG, JPEG | Local OCR and flattened irreversible redaction | Sanitized PNG |

The MVP does not promise preservation of the original Office or PDF layout. Knowledge safety and semantic structure take priority over visual fidelity.

## Detection categories

- Credentials: passwords, API keys, access tokens, private keys and connection strings, including supported single-line quoted assignment forms used by JSON, configuration and shell-style text. GitHub detection covers documented classic/app prefixes, fine-grained `github_pat_` and stateless `ghs_APPID_JWT` shapes. Private-key blocks include matching standard, RSA, EC, DSA, OpenSSH, encrypted PKCS#8-style and PGP armor labels.
- Personal identifiers: checksum-valid Taiwan ID patterns with case-insensitive input, names from local dictionaries, Taiwan mobile numbers in local or `+886`/`886` international form, email and addresses.
- Enterprise identifiers: customer, supplier, employee, project, product and facility names. Bank-account context detection accepts controlled unquoted and single-line quoted English key/value assignments without treating a field name alone as a finding.
- Infrastructure: public/private IP, hostnames, account names, internal URLs and device IDs.
- Commercial information: quotations, exact costs, prices, margins, contract numbers and bank data.
- Technical know-how: source code secrets, equipment recipes, exact operating parameters and unpublished patent terms from enterprise dictionaries.
- Hidden content: Office comments, revision indicators, hidden worksheets/rows/columns, document properties and external links.
- Image text and metadata: OCR content, EXIF, GPS and device metadata when supported.

Detection uses deterministic rules, exact-data dictionaries and optional local-only assistance. AI classification is never the sole control.

Only immutable findings issued by the detector for the same source text, policy and dictionary snapshot can enter transformation. Callers cannot retype or clone a credential finding to weaken its forced-delete rule.

## Transformations

- `delete`: irreversibly remove content from the safe derivative.
- `tokenize`: replace with stable tokens such as `【CUSTOMER-A】`; keep the map in a separate encrypted local file.
- `generalize`: replace an exact value with an approved range or category.
- `keep`: retain with a controlled reason code and residual-risk status.

Only low/medium findings may remain in an exportable derivative. They carry residual risk and the product must not label the result completely safe. Public reports contain controlled reason codes only; free-form review details remain local and are not packaged. Token labels and generalization replacements come from controlled policy values and are scanned again.

Credentials and private keys cannot be kept or tokenized into the Safe Package; they must be deleted. P3 knowledge whose structure is itself sensitive must be handled locally and cannot be made cloud-safe by renaming entities.

For the Office core, comments, deleted revision text, hidden worksheets/rows/columns, hidden slides, speaker notes, formulas, external relationships and document-property indicators are reviewable locally but forced out of cloud derivatives. The public report records only controlled finding types and masked previews. XLSX export is blocked until the caller explicitly approves all visible worksheets selected for the current core run. Image OCR findings are delete-only in the MVP: every affected OCR bounding box is painted into new pixels and the output is re-encoded as PNG before the same local OCR model/dictionary scan runs again.

Classification and routes are fixed for the MVP:

- P0 Public: exportable only after complete verification and a passing second scan.
- P1 Internal: exportable after all sensitive findings are handled and verification passes.
- P2 Confidential: requires a sanitized derivative, explicit human confirmation bound to the reviewed project, sources, dictionary and derivative/report hashes, complete coverage and no unresolved high/critical finding.
- P3 Restricted: always local-only. Renaming, tokenization or generalization never changes this route.

An unresolved state includes a missing decision, a kept high/critical finding, a credential or private key not deleted, incomplete/unknown parser coverage, a failed transformation or second scan, a remaining high/critical second-scan finding, a P3 route violation, a changed source hash, or failed ZIP allowlist/entry verification. Source identity, byte length and SHA-256 remain live export conditions after verification: packaging rechecks them before and after artifact creation and removes call-created artifacts if they change.

## Outputs

### Uploadable Safe Package

`<project>-SAFE-PACKAGE.zip` contains only:

- `SAFE_SOURCE/` sanitized derivatives;
- `SAFE-MANIFEST.json`;
- `DLP-REPORT.json` without original sensitive values;
- `README-SAFE-UPLOAD.md`.

### Local-only artifacts

- `<project>.ewmap`: encrypted token rehydration map;
- local scan session and decision log;
- original source files, which remain untouched.
- `<project>-SAFE-PACKAGE.zip.sha256` and a local export receipt containing safe metadata, hashes, status and the output location.

The `.ewmap`, originals and raw findings never enter the Safe Package.

When tokenization is used, export remains blocked until the core receives an authentic proof issued while encrypting a local token map that covers every token used by the transformation. A boolean or forged/stale/tampered artifact cannot substitute for that proof. Safe Package basenames use a controlled ASCII format so checksum and receipt records cannot be injected through filenames.

The encrypted project token registry gives the same normalized original the same token within one project. Different projects use independent random scope secrets so their identifiers cannot be correlated. The project-scoped exact-data dictionary is also encrypted locally; manifests contain only its version and hash.

Each dictionary records its project UUID, and that UUID participates in the dictionary snapshot hash. A dictionary, token registry, finding set or transformation from another project cannot be substituted during verification.

## Content policy v0.4 limits

- The implemented core accepts TXT, Markdown, CSV, TSV, DOCX, XLSX, PPTX, text-only PDF, PNG, JPG and JPEG through dedicated content validation paths.
- Maximum 10 MiB per file, 100 files per session and 100 MiB total source bytes per session.
- Only explicitly supported Unicode encodings are accepted; unreliable decoding fails closed. Except for tab and line endings, C0/C1 control characters are rejected even when sparsely embedded in otherwise valid Unicode text.
- Extension is never the sole format signal. Binary content, unsupported formats and uncertain coverage block export.
- Dictionary matching uses Unicode NFKC, trimmed/collapsed whitespace and a configurable Latin case rule. Aliases are explicit and fuzzy matching is disabled.
- Exact-data dictionaries and per-file finding output have explicit resource ceilings; exceeding a ceiling fails closed instead of returning partial coverage.
- CSV uses a fixed comma delimiter and TSV uses a fixed tab delimiter. Quoting follows the supported double-quote grammar; unterminated quotes, quotes inside unquoted fields, characters after a closing quote, lone carriage returns and inconsistent column counts fail closed.
- Tabular scanning is cell-bounded so a detector cannot combine unrelated adjacent cells. Embedded delimiters and line endings are accepted only inside quoted fields.
- Tabular policy limits are 100,000 rows, 1,000 columns, 1,000,000 cells and 1,000,000 UTF-16 code units per decoded cell, subject to the stricter 10 MiB file limit.
- A non-empty cell whose first non-whitespace character is `=`, `+`, `-` or `@` is a controlled spreadsheet-formula finding. Export requires the `FORMULA_AS_LITERAL` transformation, which prefixes that character with an apostrophe in the derivative and records the event in the public finding counts.
- DOCX, XLSX and PPTX are accepted only as matching, non-macro OOXML ZIP packages. Extension, package structure and the main-part content type must agree.
- Office sources are limited to 25 MiB compressed, 2,048 ZIP entries, 16 MiB per expanded entry and 64 MiB aggregate expanded data. ZIP64, encryption, spanning, unsafe/duplicate paths, symbolic links, unsupported compression, noncanonical headers, DTD/entity declarations and malformed XML fail closed.
- DOCX derivatives are structured Markdown containing body/table/header/footer and supported note text. Deleted revisions and comments are removed.
- XLSX derivatives contain a controlled Markdown index plus one CSV per explicitly approved visible worksheet. Formulas and hidden sheet/row/column/comment content are removed.
- PPTX derivatives are structured Markdown by visible slide. Hidden slides, speaker notes and comments are removed.
- Embedded media, drawings, charts, diagrams, objects, ActiveX, custom XML and package signatures currently make Office coverage incomplete. Export remains blocked until their later parser/OCR coverage is implemented.
- PDF sources are limited to 25 MiB and 500 pages. Password/encryption/parser failures, image operations, image-only/empty pages or unknown coverage block export. Active-content indicators are forced-delete findings; layout fidelity and PDF raster OCR are not claimed.
- PNG/JPEG sources are limited to 25 MiB and 20 million decoded pixels. Signatures must match extensions. OCR uses one explicitly selected, pinned local English or Traditional Chinese model; model/WASM files are never fetched at runtime.
- Image derivatives are newly encoded flattened PNG pixels. PNG ancillary chunks and JPEG EXIF/GPS/device metadata are not copied. OCR is probabilistic, so complete pipeline coverage is not a claim of perfect recognition.

## MVP screens

1. Home and privacy boundary.
2. File queue and parser status.
3. Findings review with source context shown locally.
4. Transformation editor and classification decision.
5. Second-scan result and export readiness.
6. Export receipt with hashes and destination paths.

## Explicit exclusions

- Browser, clipboard, email or network interception.
- CASB, SIEM, SOC or centralized endpoint administration.
- Claims of perfect detection, anonymity, legal compliance or certification.
- Automatic upload to ChatGPT.
- Automatic publication of forged knowledge.
- Cloud OCR, cloud LLMs, analytics, advertising or telemetry.

## Success evidence

- Network-denied testing does not impair the core workflow.
- Original files remain byte-identical.
- Representative synthetic secrets and PII are detected.
- Unsupported or failed parsing blocks a safe claim.
- Unresolved high/critical findings block export.
- Safe Package contains no originals, raw values or token map.
- Re-scan passes before export.
- The repository schema validates the Safe Package manifest locally; EW Enterprise Secure Knowledge Forge cross-project acceptance remains pending integration.
