# Release Readiness

Version: 0.1.0

Status: Blocked — preparation only

This document records the gates between the current unsigned review build and any public Windows release. It does not authorize signing, merging, uploading artifacts or creating a GitHub Release.

## Evidence available

- Draft review: [PR #1](https://github.com/pohsuntw-lab/EW-Local-Sanitizer/pull/1)
- Current development branch: `codex/plaintext-hardening-v0.1`
- Application/test baseline commit: `0510e953fb2b1862dc79645cd5aac9a133d7440b`
- Automated tests: 55 unit and 10 fixture tests passed
- Native Windows CI: packaging, portable launch, silent per-user install, installed-app launch and uninstall passed in [run 34599172096](https://github.com/pohsuntw-lab/EW-Local-Sanitizer/actions/runs/34599172096)
- Local unsigned setup and portable artifacts were produced with sibling SHA-256 files and a build receipt

## Open release gates

| Gate | Status | Required evidence or decision |
| --- | --- | --- |
| Code review | Open | Review and resolve Draft PR #1; do not merge while other release gates remain open |
| Windows 10/11 human UAT | Deferred, unverified | Execute `WINDOWS_UAT.md` on supported x64 systems or obtain an explicitly approved equivalent test environment |
| Network-denied end-to-end UI workflow | Unverified on Windows | Complete W6-W18 with synthetic fixtures and safe screenshots/log codes |
| Application identity | Open | Provide an approved Windows application icon and publisher identity |
| Source licensing | Open | Resolve the public repository's absent `LICENSE` file versus `package.json` declaring `Proprietary`; do not infer distribution rights |
| Authenticode | Not started | Select an approved certificate custody and timestamping process; purchasing or using a certificate requires separate authorization |
| Release metadata | Not started | Prepare version, file sizes, SHA-256 values, minimum OS, release notes and support/security contact route |
| Final release authorization | Not granted | Obtain explicit authorization only after all required evidence has been reviewed |

## Current artifact boundary

- Artifacts are named `UNSIGNED-TEST-ONLY` and may be shared only with named testers.
- CI does not upload executables or invoke publishing.
- Signing discovery and signing environment inputs remain disabled for the unsigned channel.
- No updater, telemetry, cloud API or automatic upload may be introduced as part of release preparation.
- A future signed artifact must be rebuilt from the exact authorized commit and verified again; an unsigned test artifact must not be renamed into a production artifact.

## Next authorized decision

The project owner must first resolve how Windows human UAT will be completed or explicitly accepted as a documented release risk by an authorized release approver. Separately, the owner must decide the intended source/distribution license and whether to begin an Authenticode certificate process. None of these decisions is implied by continuing development.
