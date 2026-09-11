# Security-sensitive dependencies

Versions are exact in `package.json` and `package-lock.json`.

| Dependency | Scope | Maintenance evidence checked | License | Security notes |
| --- | --- | --- | --- | --- |
| `ajv` 8.20.0 | Runtime JSON Schema validation | npm metadata showed an active upstream release in 2026 | MIT | Pure JavaScript; no network, telemetry or native executable. Ajv uses local code generation and has a `require-from-string` transitive dependency, so only the repository-owned static schema is compiled; untrusted schemas are never accepted. |
| `typescript` 5.9.3 | Development compiler | Maintained by Microsoft; npm metadata current in 2026 | Apache-2.0 | Development-only. A mature 5.9 release was selected instead of the newly released 7.x major. |
| `@types/node` 22.20.2 | Development types | Maintained in DefinitelyTyped; npm metadata current in 2026 | MIT | Types only; aligned with the minimum Node 22 runtime family. |

No Electron, OCR, cloud client, telemetry package, native addon or document parser is included in the plain-text hardening phase. Tests compile with `tsc` and run emitted JavaScript, so they do not depend on Node's direct TypeScript execution behavior.

Runtime transitives pinned by the lockfile are `fast-deep-equal` 3.1.3 (MIT), `fast-uri` 3.1.7 (BSD-3-Clause), `json-schema-traverse` 1.0.0 (MIT) and `require-from-string` 2.0.2 (MIT). Development transitive `undici-types` 6.21.0 is MIT and contains types only. A full `npm audit` reported zero known vulnerabilities when this baseline was created.

`npm run check:dependencies`, also included in `npm run lint`, runs without network access and rejects non-exact direct versions, manifest/lock mismatch, missing SHA-512 integrity or license metadata, undocumented packages, lifecycle install scripts and native-build flags. The installed dependency tree was also checked for native addon files and runtime network-module references. A fresh full `npm audit` on 2026-09-11 reported zero known vulnerabilities across production and development dependencies.
