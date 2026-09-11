import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const eulaLocales = ["zh-TW", "en-US"];

function parseFrontMatter(source, fileName) {
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/u);
  if (!match) throw new Error(`Invalid EULA front matter: ${fileName}`);
  const metadata = new Map();
  for (const line of match[1].split(/\r?\n/u)) {
    const separator = line.indexOf(":");
    if (separator < 1) throw new Error(`Invalid EULA metadata: ${fileName}`);
    metadata.set(line.slice(0, separator).trim(), line.slice(separator + 1).trim().replace(/^"|"$/gu, ""));
  }
  return { metadata: Object.fromEntries(metadata), body: match[2].trim() };
}

function markdownToPlainText(markdown) {
  return markdown
    .replace(/^#{1,6}\s+/gmu, "")
    .replace(/\*\*([^*]+)\*\*/gu, "$1")
    .replace(/_([^_]+)_/gu, "$1")
    .replace(/ {2}\n/gu, "\n")
    .replace(/\n{3,}/gu, "\n\n")
    .trim();
}

function nsisInclude(manifest) {
  const zhTw = manifest.agreements.find((item) => item.locale === "zh-TW");
  const enUs = manifest.agreements.find((item) => item.locale === "en-US");
  if (!zhTw || !enUs) throw new Error("Required EULA locale is missing");
  return `; Generated from eula/*.md by build/generate-eula-artifacts.mjs.
; Do not edit this derived file.

!include "FileFunc.nsh"
!include "LogicLib.nsh"

!define EWLS_EULA_VERSION "${manifest.agreementVersion}"
!define EWLS_EULA_HASH_zh_TW "${zhTw.sha256}"
!define EWLS_EULA_HASH_en_US "${enUs.sha256}"
!ifndef BUILD_UNINSTALLER
Var EwlsEulaAccepted
Var EwlsEulaLocale
Var EwlsEulaHash
!endif

!macro customHeader
  LangString EwlsEulaCheckbox \${LANG_TRADCHINESE} "我已閱讀、理解並同意《EW Local Sanitizer 最終使用者授權協議與使用規範》"
  LangString EwlsEulaAccept \${LANG_TRADCHINESE} "同意並安裝"
  LangString EwlsEulaCheckbox \${LANG_ENGLISH} "I have read, understood, and agree to the EW Local Sanitizer End User License Agreement and Acceptable Use Rules"
  LangString EwlsEulaAccept \${LANG_ENGLISH} "Agree and Install"
  !ifndef BUILD_UNINSTALLER
    !define MUI_LICENSEPAGE_CHECKBOX
    !define MUI_LICENSEPAGE_CHECKBOX_TEXT "$(EwlsEulaCheckbox)"
    !define MUI_LICENSEPAGE_BUTTON "$(EwlsEulaAccept)"
  !endif
!macroend

!ifndef BUILD_UNINSTALLER

!macro customPageAfterChangeDir
  Function EwlsUpdatedEulaPre
    \${IfNot} \${isUpdated}
      Abort
    \${EndIf}
  FunctionEnd
  !define MUI_LICENSEPAGE_CHECKBOX
  !define MUI_LICENSEPAGE_CHECKBOX_TEXT "$(EwlsEulaCheckbox)"
  !define MUI_LICENSEPAGE_BUTTON "$(EwlsEulaAccept)"
  !ifdef MUI_PAGE_CUSTOMFUNCTION_PRE
    !undef MUI_PAGE_CUSTOMFUNCTION_PRE
  !endif
  !define MUI_PAGE_CUSTOMFUNCTION_PRE EwlsUpdatedEulaPre
  !insertmacro MUI_PAGE_LICENSE "$(MUILicense)"
  !define MUI_PAGE_CUSTOMFUNCTION_PRE instFilesPre
!macroend

!macro customInit
  StrCpy $EwlsEulaAccepted "true"
  Call EwlsSelectEula
  \${If} \${Silent}
    StrCpy $EwlsEulaAccepted "false"
    \${GetParameters} $0
    \${GetOptions} $0 "/EWLSACCEPTEULA=" $1
    StrCpy $2 "${manifest.agreementVersion}:$EwlsEulaHash"
    \${If} $1 != $2
      SetErrorLevel 2
      Quit
    \${EndIf}
    StrCpy $EwlsEulaAccepted "true"
  \${EndIf}
!macroend

!macro customInstall
  \${If} $EwlsEulaAccepted != "true"
    Abort
  \${EndIf}
  CreateDirectory "$APPDATA\\EWLocalSanitizer"
  \${GetTime} "" "L" $0 $1 $2 $3 $4 $5 $6
  WriteINIStr "$APPDATA\\EWLocalSanitizer\\eula-acceptance.ini" "acceptance" "agreementVersion" "${manifest.agreementVersion}"
  WriteINIStr "$APPDATA\\EWLocalSanitizer\\eula-acceptance.ini" "acceptance" "softwareVersion" "\${VERSION}"
  WriteINIStr "$APPDATA\\EWLocalSanitizer\\eula-acceptance.ini" "acceptance" "installerVersion" "\${VERSION}"
  WriteINIStr "$APPDATA\\EWLocalSanitizer\\eula-acceptance.ini" "acceptance" "acceptedAt" "$2-$1-$0T$4:$5:$6"
  WriteINIStr "$APPDATA\\EWLocalSanitizer\\eula-acceptance.ini" "acceptance" "locale" "$EwlsEulaLocale"
  WriteINIStr "$APPDATA\\EWLocalSanitizer\\eula-acceptance.ini" "acceptance" "explicitAcceptance" "true"
  WriteINIStr "$APPDATA\\EWLocalSanitizer\\eula-acceptance.ini" "acceptance" "agreementSha256" "$EwlsEulaHash"
!macroend

Function EwlsSelectEula
  StrCmp $LANGUAGE 1033 EwlsSelectEnglish EwlsSelectTraditional
EwlsSelectEnglish:
  StrCpy $EwlsEulaLocale "en-US"
  StrCpy $EwlsEulaHash "${enUs.sha256}"
  Goto EwlsSelectDone
EwlsSelectTraditional:
  StrCpy $EwlsEulaLocale "zh-TW"
  StrCpy $EwlsEulaHash "${zhTw.sha256}"
EwlsSelectDone:
FunctionEnd

!endif
`;
}

export async function generateEulaArtifacts(root = projectRoot) {
  const outputDirectory = path.join(root, "build", "generated", "eula");
  await mkdir(outputDirectory, { recursive: true });
  const agreements = [];
  let commonVersion;
  for (const locale of eulaLocales) {
    const relativePath = `eula/${locale}.md`;
    const source = (await readFile(path.join(root, relativePath), "utf8")).replace(/\r\n?/gu, "\n");
    const { metadata, body } = parseFrontMatter(source, relativePath);
    if (metadata.format !== "ewls-eula" || metadata.formatVersion !== "1.0" || metadata.locale !== locale) throw new Error(`Unsupported EULA metadata: ${relativePath}`);
    if (!/^EWLS-EULA-[0-9]+\.[0-9]+$/u.test(metadata.agreementVersion ?? "")) throw new Error(`Invalid EULA version: ${relativePath}`);
    commonVersion ??= metadata.agreementVersion;
    if (metadata.agreementVersion !== commonVersion) throw new Error(`EULA versions differ: ${relativePath}`);
    if (metadata.rightsHolder !== "具象職人股份有限公司") throw new Error(`Unexpected rights holder: ${relativePath}`);
    const sha256 = createHash("sha256").update(source, "utf8").digest("hex");
    const plainText = `\uFEFF${markdownToPlainText(body)}\n`;
    await writeFile(path.join(outputDirectory, `${locale}.txt`), plainText, "utf8");
    const nativeNsisLocale = locale === "zh-TW" ? "zh_TW" : "en";
    await writeFile(path.join(root, "build", `eula_${nativeNsisLocale}.txt`), plainText, "utf8");
    agreements.push({ locale, agreementVersion: metadata.agreementVersion, effectiveDate: metadata.effectiveDate, rightsHolder: metadata.rightsHolder, title: metadata.title, sourcePath: relativePath, plainTextPath: `build/generated/eula/${locale}.txt`, sha256 });
  }
  const manifest = { format: "ewls-eula-manifest", formatVersion: "1.0", agreementVersion: commonVersion, generatedFrom: "eula/*.md", agreements };
  await writeFile(path.join(root, "build", "generated", "eula-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await writeFile(path.join(root, "build", "generated", "nsis-eula.nsh"), nsisInclude(manifest), "utf8");
  return manifest;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await generateEulaArtifacts();
