# START_CODEX

Build EW Local Sanitizer v0.1.0.

Before editing, inspect the repository and read:

1. `PRODUCT.md`
2. `ARCHITECTURE.md`
3. `ACCEPTANCE.md`
4. `AGENTS.md`

In your first response, do not modify files. Report:

- the product and security boundary you understand;
- the proposed module and dependency structure;
- how original-file integrity and local-only operation will be verified;
- how each supported format will be parsed and what cannot be guaranteed;
- how Safe Package allowlisting and `.ewmap` isolation will be tested;
- the Windows packaging strategy;
- any conflict, missing dependency or acceptance item that cannot yet be satisfied.

After approval, implement in vertical slices:

1. plain text intake, detection, decisions, second scan and safe export;
2. encrypted token vault;
3. CSV/TSV;
4. DOCX/XLSX/PPTX with bounded OOXML ZIP/XML parsing and format-aware second scan;
5. PDF and image OCR;
6. Electron UI;
7. Windows installer and portable packaging.

Use only synthetic fixtures. Do not add cloud calls or weaken a block to make a test pass. Maintain `PROJECT_STATUS.md` with evidence and the earliest incomplete lifecycle stage.
