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
5. High- and critical-risk findings require resolution; keeping one requires an explicit reason.
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
| PDF | Extract text layer; flag attachments, forms, JavaScript and image-only pages when detectable | Structured Markdown; OCR text when selected |
| PNG, JPG, JPEG | Local OCR and flattened irreversible redaction | Sanitized PNG |

The MVP does not promise preservation of the original Office or PDF layout. Knowledge safety and semantic structure take priority over visual fidelity.

## Detection categories

- Credentials: passwords, API keys, access tokens, private keys and connection strings.
- Personal identifiers: Taiwan ID patterns, names from local dictionaries, phone, email and addresses.
- Enterprise identifiers: customer, supplier, employee, project, product and facility names.
- Infrastructure: public/private IP, hostnames, account names, internal URLs and device IDs.
- Commercial information: quotations, exact costs, prices, margins, contract numbers and bank data.
- Technical know-how: source code secrets, equipment recipes, exact operating parameters and unpublished patent terms from enterprise dictionaries.
- Hidden content: Office comments, revision indicators, hidden worksheets/rows/columns, document properties and external links.
- Image text and metadata: OCR content, EXIF, GPS and device metadata when supported.

Detection uses deterministic rules, exact-data dictionaries and optional local-only assistance. AI classification is never the sole control.

## Transformations

- `delete`: irreversibly remove content from the safe derivative.
- `tokenize`: replace with stable tokens such as `【CUSTOMER-A】`; keep the map in a separate encrypted local file.
- `generalize`: replace an exact value with an approved range or category.
- `keep`: retain with recorded reviewer reason and residual-risk status.

Credentials and private keys cannot be kept or tokenized into the Safe Package; they must be deleted. P3 knowledge whose structure is itself sensitive must be handled locally and cannot be made cloud-safe by renaming entities.

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

The `.ewmap`, originals and raw findings never enter the Safe Package.

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
- A Safe Package can be accepted by EW Enterprise Secure Knowledge Forge.

