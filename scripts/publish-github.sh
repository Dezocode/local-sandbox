#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
exec python3 "$project_root/scripts/release/github_release.py" "$@"
