; Generated from eula/*.md by build/generate-eula-artifacts.mjs.
; Do not edit this derived file.

!include "FileFunc.nsh"
!include "LogicLib.nsh"

!define EWLS_EULA_VERSION "EWLS-EULA-1.0"
!define EWLS_EULA_HASH_zh_TW "2b41d85c64bea3118b46a010eb86e03d3d17a6838bd0cc5fc8dcb5b8fad03039"
!define EWLS_EULA_HASH_en_US "3dfec7d5dc91cb53036ee521147003e4f91bcaa181f26c6256903f1701fb264a"
!ifndef BUILD_UNINSTALLER
Var EwlsEulaAccepted
Var EwlsEulaLocale
Var EwlsEulaHash
!endif

!macro customHeader
  LangString EwlsEulaCheckbox ${LANG_TRADCHINESE} "我已閱讀、理解並同意《EW Local Sanitizer 最終使用者授權協議與使用規範》"
  LangString EwlsEulaAccept ${LANG_TRADCHINESE} "同意並安裝"
  LangString EwlsEulaCheckbox ${LANG_ENGLISH} "I have read, understood, and agree to the EW Local Sanitizer End User License Agreement and Acceptable Use Rules"
  LangString EwlsEulaAccept ${LANG_ENGLISH} "Agree and Install"
  !ifndef BUILD_UNINSTALLER
    !define MUI_LICENSEPAGE_CHECKBOX
    !define MUI_LICENSEPAGE_CHECKBOX_TEXT "$(EwlsEulaCheckbox)"
    !define MUI_LICENSEPAGE_BUTTON "$(EwlsEulaAccept)"
  !endif
!macroend

!ifndef BUILD_UNINSTALLER

!macro customPageAfterChangeDir
  Function EwlsUpdatedEulaPre
    ${IfNot} ${isUpdated}
      Abort
    ${EndIf}
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
  ${If} ${Silent}
    StrCpy $EwlsEulaAccepted "false"
    ${GetParameters} $0
    ${GetOptions} $0 "/EWLSACCEPTEULA=" $1
    StrCpy $2 "EWLS-EULA-1.0:$EwlsEulaHash"
    ${If} $1 != $2
      SetErrorLevel 2
      Quit
    ${EndIf}
    StrCpy $EwlsEulaAccepted "true"
  ${EndIf}
!macroend

!macro customInstall
  ${If} $EwlsEulaAccepted != "true"
    Abort
  ${EndIf}
  CreateDirectory "$APPDATA\EWLocalSanitizer"
  ${GetTime} "" "L" $0 $1 $2 $3 $4 $5 $6
  WriteINIStr "$APPDATA\EWLocalSanitizer\eula-acceptance.ini" "acceptance" "agreementVersion" "EWLS-EULA-1.0"
  WriteINIStr "$APPDATA\EWLocalSanitizer\eula-acceptance.ini" "acceptance" "softwareVersion" "${VERSION}"
  WriteINIStr "$APPDATA\EWLocalSanitizer\eula-acceptance.ini" "acceptance" "installerVersion" "${VERSION}"
  WriteINIStr "$APPDATA\EWLocalSanitizer\eula-acceptance.ini" "acceptance" "acceptedAt" "$2-$1-$0T$4:$5:$6"
  WriteINIStr "$APPDATA\EWLocalSanitizer\eula-acceptance.ini" "acceptance" "locale" "$EwlsEulaLocale"
  WriteINIStr "$APPDATA\EWLocalSanitizer\eula-acceptance.ini" "acceptance" "explicitAcceptance" "true"
  WriteINIStr "$APPDATA\EWLocalSanitizer\eula-acceptance.ini" "acceptance" "agreementSha256" "$EwlsEulaHash"
!macroend

Function EwlsSelectEula
  StrCmp $LANGUAGE 1033 EwlsSelectEnglish EwlsSelectTraditional
EwlsSelectEnglish:
  StrCpy $EwlsEulaLocale "en-US"
  StrCpy $EwlsEulaHash "3dfec7d5dc91cb53036ee521147003e4f91bcaa181f26c6256903f1701fb264a"
  Goto EwlsSelectDone
EwlsSelectTraditional:
  StrCpy $EwlsEulaLocale "zh-TW"
  StrCpy $EwlsEulaHash "2b41d85c64bea3118b46a010eb86e03d3d17a6838bd0cc5fc8dcb5b8fad03039"
EwlsSelectDone:
FunctionEnd

!endif
