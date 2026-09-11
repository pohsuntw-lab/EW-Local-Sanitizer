# Windows unsigned test build UAT

Version: 0.1.0

Status: Pending real-machine execution

Scope: Windows 10/11 x64, named testers only

## Safety notice

The installer and portable executable are intentionally unsigned test artifacts. Windows SmartScreen may warn about an unknown publisher. Do not distribute them publicly, suppress the warning in product copy, or treat this checklist as Authenticode acceptance. Use synthetic documents only.

## Before testing

1. Copy the two `.exe` files, their sibling `.sha256` files and `WINDOWS-BUILD-RECEIPT.json` together.
2. In PowerShell, run `Get-FileHash -Algorithm SHA256 <artifact>` for each executable and compare the result with its sibling file and receipt.
3. Confirm both filenames contain `UNSIGNED-TEST-ONLY` and the receipt says `"signed": false`.
4. Disconnect the test machine from the network or apply an outbound-deny rule for the application before the workflow tests.
5. Prepare only repository-owned or newly created synthetic TXT, CSV, DOCX, XLSX, PPTX, text-only PDF and PNG/JPEG fixtures. Record their pre-test SHA-256 values.

## Installer and portable matrix

| ID | Test | Expected result | Result/evidence |
| --- | --- | --- | --- |
| W1 | Launch portable as a standard user | App opens without administrator rights; privacy boundary is visible | Pending |
| W2 | Run assisted installer as a standard user | Per-user location can be selected; no elevation is requested | Pending |
| W3 | Launch installed app | Same UI and local workflow as portable build | Pending |
| W4 | Uninstall from Windows Settings | Application files and shortcuts are removed; user documents are not touched | Pending |
| W5 | Re-run installer and portable after uninstall | Both remain usable and do not depend on prior session data | Pending |

## Security and workflow matrix

| ID | Test | Expected result | Result/evidence |
| --- | --- | --- | --- |
| W6 | Run while outbound network is denied | UI, parsing, local OCR, review, second scan and Safe Package creation continue without network access | Pending |
| W7 | Scan a synthetic P1 file, delete every finding and export | Native dialogs work; Safe Package, checksum and receipt are created locally; nothing uploads automatically | Pending |
| W8 | Scan synthetic credential/private-key values | Only `delete` is available and export remains blocked until deletion | Pending |
| W9 | Keep a synthetic high/critical finding | Local decision is visible, but Safe Package export remains blocked | Pending |
| W10 | Leave a finding undecided | Export remains disabled/blocked with an understandable reason | Pending |
| W11 | Select P2 without checking explicit confirmation | Export remains disabled; after explicit confirmation, the exact reviewed state can proceed to second scan | Pending |
| W12 | Select P3 | Route remains local-only and Safe Package export is disabled regardless of rename/token/generalization | Pending |
| W13 | Tokenize a supported synthetic value | A separate `.ewmap` location and 12+ character passphrase are required; `.ewmap` is absent from Safe Package | Pending |
| W14 | Use image-only PDF or unsupported Office embedded content | Coverage is incomplete and export remains blocked | Pending |
| W15 | OCR a supported synthetic PNG/JPEG | OCR runs locally, affected pixels are flattened into a new PNG and second OCR scan gates export | Pending |
| W16 | Inspect resulting ZIP | Only `SAFE_SOURCE/`, `SAFE-MANIFEST.json`, `DLP-REPORT.json` and `README-SAFE-UPLOAD.md` entries are present | Pending |
| W17 | Compare source hashes and timestamps after all tests | Every original SHA-256 remains unchanged and no original is overwritten | Pending |
| W18 | Close/replace the session and retry an old export state | Old session is rejected and temporary OCR/token state is no longer usable | Pending |

## Evidence handling

- Record Windows version, standard-user/admin status, artifact SHA-256, pass/fail and controlled error codes.
- Screenshots must show synthetic or masked values only and must not contain full local source paths.
- A failure keeps G1, G2, H1-H4 and J6 open. Do not weaken an export block to obtain a pass.
- Successful UAT still does not authorize signing, Release creation, website publication or distribution to unnamed users.
