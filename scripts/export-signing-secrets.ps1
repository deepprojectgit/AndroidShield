# Exports GPG material for GitHub Actions Maven Central publishing.
# NEVER paste the private key into chat, email, or Issues.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/export-signing-secrets.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/export-signing-secrets.ps1 -KeyId EDA4E3EE50102E96

param(
    [string]$KeyId = ""
)

$ErrorActionPreference = "Stop"

function Resolve-GpgExe {
    $cmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        return $cmd.Source
    }

    $candidates = @(
        "${env:ProgramFiles}\GnuPG\bin\gpg.exe",
        "${env:ProgramFiles(x86)}\GnuPG\bin\gpg.exe",
        "${env:ProgramFiles}\Git\usr\bin\gpg.exe",
        "${env:ProgramFiles(x86)}\Git\usr\bin\gpg.exe",
        "${env:LOCALAPPDATA}\Programs\GnuPG\bin\gpg.exe",
        "${env:ProgramFiles(x86)}\Gpg4win\bin\gpg.exe"
    )
    foreach ($path in $candidates) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            return $path
        }
    }
    return $null
}

$gpg = Resolve-GpgExe
if (-not $gpg) {
    throw @"
gpg.exe not found.

Install one of:
  - Gpg4win (https://gpg4win.org/)
  - Git for Windows (includes usr\bin\gpg.exe)

Or open Git Bash and run the same commands there.
"@
}

Write-Host "Using gpg: $gpg" -ForegroundColor DarkGray
Write-Host "Listing secret keys..." -ForegroundColor Cyan
& $gpg --list-secret-keys --keyid-format LONG
if ($LASTEXITCODE -ne 0) {
    throw "gpg failed while listing keys."
}

if ([string]::IsNullOrWhiteSpace($KeyId)) {
    Write-Host ""
    Write-Host "Enter SIGNING_KEY_ID from the sec line (e.g. EDA4E3EE50102E96):" -ForegroundColor Yellow
    $KeyId = (Read-Host).Trim()
}

if ($KeyId -notmatch '^(0x)?[0-9A-Fa-f]{8}([0-9A-Fa-f]{8})?$') {
    throw "Key id must be 8 or 16 hex characters. Got: $KeyId"
}

# Gradle PgpKeyId parses with signed Long — 16-char ids with high bit set fail.
# Prefer the last 8 hex chars for signingInMemoryKeyId.
$normalizedId = $KeyId
if ($normalizedId.StartsWith("0x") -or $normalizedId.StartsWith("0X")) {
    $normalizedId = $normalizedId.Substring(2)
}
if ($normalizedId.Length -eq 16) {
    $shortId = $normalizedId.Substring(8)
    Write-Host "Using short SIGNING_KEY_ID for Gradle: $shortId (from $normalizedId)" -ForegroundColor Yellow
    $KeyId = $shortId
}

$outDir = Join-Path $PSScriptRoot "..\build\signing-export"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$outDir = (Resolve-Path $outDir).Path

$keyFile = Join-Path $outDir "SIGNING_KEY.asc"
$idFile = Join-Path $outDir "SIGNING_KEY_ID.txt"
$checklist = Join-Path $outDir "UPLOAD_CHECKLIST.txt"

Write-Host "Exporting private key to $keyFile ..." -ForegroundColor Cyan
& $gpg --export-secret-keys --armor $KeyId | Set-Content -Path $keyFile -Encoding ascii
if (-not (Test-Path $keyFile) -or (Get-Item $keyFile).Length -lt 100) {
    throw "Export failed or empty. Check the key id / passphrase prompt."
}

$content = Get-Content -Raw $keyFile
if ($content -notmatch "BEGIN PGP PRIVATE KEY BLOCK") {
    throw "Export does not look like a private key block."
}

Set-Content -Path $idFile -Value $KeyId -Encoding ascii

@"
AndroidShield — upload these GitHub Actions repository secrets
Repo -> Settings -> Secrets and variables -> Actions

1) SIGNING_KEY
   - Open: $keyFile
   - Copy ALL text (including BEGIN/END lines)
   - Paste into secret SIGNING_KEY
   - Do NOT paste into chat / Issues / PRs

2) SIGNING_KEY_ID
   - Value: $KeyId
   - File: $idFile

3) SIGNING_PASSWORD
   - The passphrase you set when creating this GPG key
   - Leave empty only if the key has no passphrase

4) MAVEN_CENTRAL_USERNAME / MAVEN_CENTRAL_PASSWORD
   - From https://central.sonatype.com/account (Generate User Token)

Public key (already OK if keys.openpgp.org confirmed publish):
  `"$gpg`" --keyserver keys.openpgp.org --send-keys $KeyId

Then re-run the CI/CD workflow.
After uploading, delete this folder: $outDir
"@ | Set-Content -Path $checklist -Encoding utf8

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  SIGNING_KEY file : $keyFile"
Write-Host "  SIGNING_KEY_ID   : $KeyId"
Write-Host "  Checklist        : $checklist"
Write-Host ""
Write-Host "Open the checklist, upload secrets in GitHub, then DELETE $outDir" -ForegroundColor Yellow

try {
    Start-Process notepad $checklist
} catch {
    # Non-fatal if notepad cannot start.
}
