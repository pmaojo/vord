#!/usr/bin/env bash
# Publishes the workspace to crates.io in dependency order.
#
#   scripts/publish-crates.sh --dry-run     # verify every crate packages cleanly
#   scripts/publish-crates.sh               # publish for real
#
# Deliberately NOT wired into the release workflow. crates.io versions are
# immutable and cannot be re-published: a 50-crate run that dies at crate 30
# leaves half a version on the registry permanently, and the only way out is
# a version bump. That is a decision to take at a terminal with the output in
# front of you, not something to discover in a failed CI job.
#
# Run the dry run first. It catches the two failures that actually happen:
# a missing `description`, and a path dependency without a `version`.

set -euo pipefail
cd "$(dirname "$0")/.."

DRY=""
[ "${1:-}" = "--dry-run" ] && DRY="--dry-run"

# Topological order: a crate may only be published after everything it depends
# on is already on the registry. Leaves first, composition roots last.
CRATES=(
  vord-ast
  vord-profiles
  vord-treesitter-tokens
  vord-symbols
  vord-import-graph
  vord-cpd
  vord-agent-policy
  vord-rules-engine
  vord-taint
  vord-remediation

  vord-parser-typescript vord-parser-rust vord-parser-python vord-parser-go
  vord-parser-java vord-parser-c vord-parser-cpp vord-parser-php
  vord-parser-dockerfile vord-parser-csharp vord-parser-ruby vord-parser-kotlin
  vord-parser-swift vord-parser-scala vord-parser-html vord-parser-css
  vord-parser-xml vord-parser-json vord-parser-yaml vord-parser-hcl
  vord-parser-bash vord-parser-groovy vord-parser-lua vord-parser-elixir

  vord-rules-owasp vord-rules-smells vord-rules-iac vord-rules-a11y
  vord-rules-react vord-rules-secrets vord-rules-rust vord-rules-python
  vord-rules-architecture vord-rules-reactive vord-rules-typescript
  vord-rules-php vord-rules-go vord-rules-ai-agent

  vord-infra-memory vord-infra-fs vord-infra-github vord-infra-gitlab
  vord-infra-bitbucket vord-infra-azure vord-infra-pdf vord-infra-llm

  vord-cli
  vord-lsp
)

echo "Publishing ${#CRATES[@]} crates${DRY:+ (dry run)}"

for crate in "${CRATES[@]}"; do
  echo "==> $crate"
  if cargo publish -p "$crate" --locked $DRY; then
    # The registry index is eventually consistent; the next crate's
    # dependency resolution fails if it queries before this one lands.
    [ -z "$DRY" ] && sleep 20
  else
    status=$?
    # Re-running after a partial failure must be safe, so an already-published
    # version is a skip, not an abort.
    if cargo search "$crate" --limit 1 2>/dev/null | grep -q "^$crate = "; then
      echo "    (already on the registry at this version — skipping)"
      continue
    fi
    echo "!! $crate failed (exit $status). Fix, then re-run — published crates are skipped." >&2
    exit $status
  fi
done

echo "Done."
