#!/usr/bin/env bash
# One-time setup: points this clone at scripts/hooks/ for git hooks.
# Run once after cloning: ./scripts/hooks/install.sh

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

chmod +x scripts/hooks/pre-push
git config core.hooksPath scripts/hooks

echo "✓ git hooks installed (core.hooksPath = scripts/hooks)"
echo "  Active: pre-push (blocks direct push to master/main)"
