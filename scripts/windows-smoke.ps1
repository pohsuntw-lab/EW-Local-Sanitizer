$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$outputDirectory = Join-Path $PSScriptRoot "..\release\windows-unsigned-test"
$portable = Join-Path $outputDirectory "EW-Local-Sanitizer-0.1.0-Windows-x64-Portable-UNSIGNED-TEST-ONLY.exe"
$setup = Join-Path $outputDirectory "EW-Local-Sanitizer-0.1.0-Windows-x64-Setup-UNSIGNED-TEST-ONLY.exe"
$receipt = Join-Path $outputDirectory "WINDOWS-BUILD-RECEIPT.json"
$eulaManifestPath = Join-Path $PSScriptRoot "..\build\generated\eula-manifest.json"
foreach ($path in @($portable, $setup, $receipt, $eulaManifestPath)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing Windows build output" }
}
$eulaManifest = Get-Content -LiteralPath $eulaManifestPath -Raw | ConvertFrom-Json
$englishAgreement = $eulaManifest.agreements | Where-Object { $_.locale -eq "en-US" } | Select-Object -First 1
if ($null -eq $englishAgreement -or $englishAgreement.sha256 -notmatch "^[0-9a-f]{64}$") { throw "Invalid English EULA manifest entry" }
$silentEulaToken = "$($eulaManifest.agreementVersion):$($englishAgreement.sha256)"

function Invoke-CheckedProcess {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [string[]]$ArgumentList = @(),
    [int]$TimeoutMilliseconds = 120000
  )
  $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru
  if (-not $process.WaitForExit($TimeoutMilliseconds)) {
    $process.Kill($true)
    throw "Windows smoke process timed out"
  }
  if ($process.ExitCode -ne 0) { throw "Windows smoke process failed with exit code $($process.ExitCode)" }
}

Invoke-CheckedProcess -FilePath $portable -ArgumentList @("--ew-packaged-smoke-test")

$installDirectory = Join-Path $env:RUNNER_TEMP "EWLocalSanitizerSmoke"
if (Test-Path -LiteralPath $installDirectory) { Remove-Item -LiteralPath $installDirectory -Recurse -Force }
Invoke-CheckedProcess -FilePath $setup -ArgumentList @("/S", "/LANG=1033", "/EWLSACCEPTEULA=$silentEulaToken", "/D=$installDirectory")

$installedExecutable = Join-Path $installDirectory "EW-Local-Sanitizer.exe"
if (-not (Test-Path -LiteralPath $installedExecutable -PathType Leaf)) { throw "Installed application executable is missing" }
Invoke-CheckedProcess -FilePath $installedExecutable -ArgumentList @("--ew-packaged-smoke-test")

$uninstaller = Get-ChildItem -LiteralPath $installDirectory -Filter "Uninstall*.exe" -File | Select-Object -First 1
if ($null -eq $uninstaller) { throw "Uninstaller is missing" }
Invoke-CheckedProcess -FilePath $uninstaller.FullName -ArgumentList @("/S")
Start-Sleep -Seconds 2
if (Test-Path -LiteralPath $installedExecutable) { throw "Installed executable remains after uninstall" }

Write-Host "Windows portable, installer, installed-app and uninstall smoke checks passed."
