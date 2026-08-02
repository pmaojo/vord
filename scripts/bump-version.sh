#!/usr/bin/env bash
# Bumps the version everywhere it is declared, atomically.
#
#   scripts/bump-version.sh 0.2.0
#
# The version lives in more places than it looks: Cargo does not allow
# `version.workspace = true` inside a `[workspace.dependencies]` entry, so
# every one of the ~57 internal dependencies carries the number literally
# alongside its path — and a path dependency without a version cannot be
# published at all, so dropping them is not an option.
#
# Bumping `[workspace.package]` alone therefore yields crates at the new
# version that declare dependencies on the old one: `cargo publish` either
# fails outright or silently resolves against the previously published
# release. This script exists so that is never a manual step.

set -euo pipefail
cd "$(dirname "$0")/.."

NEW="${1:-}"
[ -n "$NEW" ] || { echo "usage: bump-version.sh <x.y.z>" >&2; exit 1; }
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
  || { echo "not a semver version: $NEW" >&2; exit 1; }

OLD="$(grep -m1 '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')"
[ -n "$OLD" ] || { echo "cannot read the current version from Cargo.toml" >&2; exit 1; }

if [ "$OLD" = "$NEW" ]; then
  echo "already at $NEW — nothing to do"
  exit 0
fi

echo "$OLD -> $NEW"

# Count first, so a silent no-op is impossible: an unexpected count means the
# manifest shape changed and this script no longer knows where the version is.
expected="$(grep -c "version = \"$OLD\"" Cargo.toml)"
echo "  Cargo.toml: $expected occurrences (1 workspace.package + internal deps)"
[ "$expected" -ge 2 ] || { echo "!! expected the workspace version plus internal deps" >&2; exit 1; }

sed -i.bak "s/version = \"$OLD\"/version = \"$NEW\"/g" Cargo.toml && rm -f Cargo.toml.bak
sed -i.bak "s/^version = \"$OLD\"/version = \"$NEW\"/" vord.toml && rm -f vord.toml.bak
sed -i.bak "s/\"version\": \"$OLD\"/\"version\": \"$NEW\"/" .claude-plugin/plugin.json \
  && rm -f .claude-plugin/plugin.json.bak

remaining="$(grep -c "version = \"$OLD\"" Cargo.toml || true)"
[ "$remaining" -eq 0 ] || { echo "!! $remaining occurrences of $OLD left in Cargo.toml" >&2; exit 1; }

# Rewrites the workspace members' versions in Cargo.lock, leaving every
# external dependency pinned where it is. `cargo metadata --no-deps` does NOT
# do this — it reads the manifests without resolving — and the release builds
# with `--locked`, so a lock left at the old version fails every target
# before it compiles a line.
cargo update --workspace --quiet

# Count real workspace entries, not raw version lines: an unrelated external
# crate that happens to sit at this version would make a bare grep pass while
# the lock is still stale.
locked="$(awk -v v="$NEW" '
  /^name = "vord-/ { pending = 1; next }
  pending && $0 == "version = \"" v "\"" { n++ }
  { pending = 0 }
  END { print n + 0 }
' Cargo.lock)"
members="$(cargo metadata --no-deps --format-version 1 | grep -o '"name":"vord-[^"]*"' | sort -u | wc -l)"
[ "$locked" -eq "$members" ] || {
  echo "!! Cargo.lock has $locked/$members workspace crates at $NEW — the lock is stale" >&2
  exit 1
}

echo
echo "Updated:"
grep -n "version = \"$NEW\"" vord.toml
grep -n "\"version\": \"$NEW\"" .claude-plugin/plugin.json
echo "  Cargo.toml: $(grep -c "version = \"$NEW\"" Cargo.toml) occurrences"
echo "  Cargo.lock: $locked/$members workspace crates"
echo
echo "npm/package.json stays at 0.0.0 by design — the release job sets it from the tag."
echo
echo "Next:  git commit -am \"Release v$NEW\" && git tag v$NEW && git push origin main v$NEW"
