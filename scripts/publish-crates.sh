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
  yunq-ast
  yunq-profiles
  yunq-treesitter-tokens
  yunq-symbols
  yunq-import-graph
  yunq-cpd
  yunq-agent-policy
  yunq-rules-engine
  yunq-taint
  yunq-remediation

  yunq-parser-typescript yunq-parser-rust yunq-parser-python yunq-parser-go
  yunq-parser-java yunq-parser-c yunq-parser-cpp yunq-parser-php
  yunq-parser-dockerfile yunq-parser-csharp yunq-parser-ruby yunq-parser-kotlin
  yunq-parser-swift yunq-parser-scala yunq-parser-html yunq-parser-css
  yunq-parser-xml yunq-parser-json yunq-parser-yaml yunq-parser-hcl
  yunq-parser-bash yunq-parser-groovy yunq-parser-lua yunq-parser-elixir

  yunq-rules-owasp yunq-rules-smells yunq-rules-iac yunq-rules-a11y
  yunq-rules-react yunq-rules-secrets yunq-rules-rust yunq-rules-python
  yunq-rules-architecture yunq-rules-reactive yunq-rules-typescript
  yunq-rules-php yunq-rules-go yunq-rules-ai-agent

  yunq-infra-memory yunq-infra-fs yunq-infra-github yunq-infra-gitlab
  yunq-infra-bitbucket yunq-infra-azure yunq-infra-pdf yunq-infra-llm

  yunq-cli
  yunq-lsp
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
