#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
command -v gh >/dev/null || { echo 'Install GitHub CLI and authenticate before publishing.' >&2; exit 1; }
gh auth status
if gh repo view Dezocode/local-sandbox --json name >/dev/null 2>&1; then
  echo 'The target repository exists. Inspect it and configure the remote explicitly before pushing.' >&2
  exit 1
fi
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git init -b main
  git add .
  git commit -m 'Create Local Sandbox implementation preview'
fi
gh repo create Dezocode/local-sandbox --private --source=. --remote=github --push --description 'iOS agent control room, scoped sandbox, bounded Shortcuts workflows, and Oracle guidance'
