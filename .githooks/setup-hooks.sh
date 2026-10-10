#!/usr/bin/env bash
# One-time per-clone activation. A fresh clone does NOT run these hooks until
# core.hooksPath is pointed at .githooks AND a local .blocked exists — until then
# there is silently no protection. Run this once after cloning:
#
#   bash .githooks/setup-hooks.sh
#
# It is idempotent and safe to re-run.
set -u

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "Not inside a git repo." >&2; exit 1; }
cd "$ROOT" || exit 1

# 1. Point git at the tracked hooks directory.
git config core.hooksPath .githooks
printf 'core.hooksPath -> .githooks\n'

# 2. Seed the gitignored pattern file if absent.
BLOCKED="$ROOT/.githooks/.blocked"
MASTER="${HOME}/.claude/.blocked"
if [ -f "$BLOCKED" ]; then
    printf '.githooks/.blocked already present — left as-is.\n'
elif [ -f "$MASTER" ]; then
    cp "$MASTER" "$BLOCKED"
    printf 'Seeded .githooks/.blocked from %s\n' "$MASTER"
else
    cp "$ROOT/.githooks/.blocked.example" "$BLOCKED"
    printf 'Seeded .githooks/.blocked from .blocked.example — EDIT IT (placeholders only).\n'
fi

# 3. Optional annotated-tag guard alias (git has no native pre-tag hook).
git config alias.safetag '!sh .githooks/tag' 2>/dev/null && \
    printf "Alias 'git safetag <name>' installed (early tag-identity check).\n"

# 4. Warn if the secret scanner is not installed (the hook degrades to a warning).
if ! command -v gitleaks >/dev/null 2>&1; then
    printf 'NOTE: gitleaks not on PATH — secret scanning will be skipped by pre-commit.\n'
    printf '  Install: winget install Gitleaks.Gitleaks\n'
fi

printf 'Hooks active.\n'
