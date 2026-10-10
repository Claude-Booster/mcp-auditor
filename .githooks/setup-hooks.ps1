<#
  One-time per-clone activation (Windows). A fresh clone does NOT run these hooks
  until core.hooksPath points at .githooks AND a local .blocked exists — until
  then there is silently no protection. Run once after cloning:

      pwsh -File .githooks/setup-hooks.ps1

  Idempotent and safe to re-run.
#>
$ErrorActionPreference = 'Stop'

$root = (git rev-parse --show-toplevel 2>$null)
if (-not $root) { Write-Error 'Not inside a git repo.'; exit 1 }
Set-Location $root

# 1. Point git at the tracked hooks directory.
git config core.hooksPath .githooks
Write-Host 'core.hooksPath -> .githooks'

# 2. Seed the gitignored pattern file if absent.
$blocked = Join-Path $root '.githooks/.blocked'
$master  = Join-Path $env:USERPROFILE '.claude/.blocked'
if (Test-Path $blocked) {
    Write-Host '.githooks/.blocked already present — left as-is.'
} elseif (Test-Path $master) {
    Copy-Item $master $blocked -Force
    Write-Host "Seeded .githooks/.blocked from $master"
} else {
    Copy-Item (Join-Path $root '.githooks/.blocked.example') $blocked -Force
    Write-Host 'Seeded .githooks/.blocked from .blocked.example — EDIT IT (placeholders only).'
}

# 3. Optional annotated-tag guard alias (git has no native pre-tag hook).
git config alias.safetag '!sh .githooks/tag' 2>$null
Write-Host "Alias 'git safetag <name>' installed (early tag-identity check)."

# 4. Warn if the secret scanner is missing (pre-commit degrades to a warning).
if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Host 'NOTE: gitleaks not on PATH — secret scanning will be skipped by pre-commit.'
    Write-Host '  Install: winget install Gitleaks.Gitleaks'
}

Write-Host 'Hooks active.'
