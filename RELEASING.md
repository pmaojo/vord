# Releasing vord

Every distribution channel resolves binaries from the GitHub release assets,
so a tag is the only thing that has to happen by hand.

```
tag v0.1.1
   └── .github/workflows/release.yml
         ├── binaries  → 5 targets + .sha256 → GitHub Release
         ├── docker    → ghcr.io/pmaojo/vord:0.1.1, :0.1, :latest
         ├── npm       → npm publish (needs NPM_TOKEN)
         └── homebrew  → pmaojo/homebrew-tap (needs HOMEBREW_TAP_TOKEN)

install.sh · action.yml · ci-templates/ · npm/install.js · the Homebrew
formula  →  all read releases/<tag>/download/vord-<target>
```

**Renaming a release asset breaks every one of those at once.** The asset
names are the public contract, more so than any API in the codebase.

## Cutting a release

1. Bump the version — **never by hand**:
   ```sh
   scripts/bump-version.sh 0.2.0
   ```
   The number lives in 60 places, not one. Cargo does not allow
   `version.workspace = true` inside a `[workspace.dependencies]` entry, so
   each of the ~57 internal dependencies carries it literally beside its path
   — and a path dependency with no version cannot be published at all, so
   they cannot simply be dropped. Editing `[workspace.package]` alone
   produces crates at the new version declaring dependencies on the old one.
   The script also rewrites `Cargo.lock`, `vord.toml` and
   `.claude-plugin/plugin.json`, and refuses to finish if any of them is left
   behind. `npm/package.json` stays at `0.0.0` by design — the release job
   sets it from the tag.
2. `cargo test --workspace` and `cargo clippy --workspace --all-targets`.
3. Commit, then tag and push:
   ```sh
   git tag v0.1.1 && git push origin v0.1.1
   ```
4. Watch the run. `fail-fast` is off, so a single broken target still yields a
   release with the other four — re-run that job rather than re-tagging.
5. Verify the result actually installs, from a clean machine or container:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/pmaojo/vord/main/scripts/install.sh | sh
   vord --version
   ```

`workflow_dispatch` builds an existing tag and publishes nothing — use it to
prove a matrix change before tagging.

## Required secrets

| Secret | Channel | Absent |
|---|---|---|
| `GITHUB_TOKEN` | Releases, GHCR | provided automatically |
| `NPM_TOKEN` | npm | job warns and skips |
| `HOMEBREW_TAP_TOKEN` | Homebrew tap | formula is rendered and uploaded as an artifact, not pushed |

A missing optional secret must never fail the release — a red X on a run that
produced good binaries teaches people to ignore red Xs.

The Homebrew channel also needs a `pmaojo/homebrew-tap` repository to exist,
containing a `Formula/` directory. The workflow commits `Formula/vord.rb` into
it on every tag.

## crates.io

Run by hand, not from CI:

```sh
scripts/publish-crates.sh --dry-run   # always first
scripts/publish-crates.sh
```

crates.io versions are immutable. A 50-crate run that dies at crate 30 leaves
half a version on the registry permanently, and the only remedy is a version
bump — a decision to take at a terminal with the output in front of you, not
one to discover in a failed CI job. Re-running is safe: crates already on the
registry at that version are skipped.

Two failures account for nearly all dry-run breakage: a crate missing
`description`, and an internal dependency missing `version` alongside its
`path` (a path-only dependency cannot be published).

## After the first release

These stay broken until a release exists, then start working with no further
change — they are already written and pointed at the right URLs:

- `ci-templates/github-actions.yml` (curls the musl binary)
- `action.yml` / `uses: pmaojo/vord@v0`
- `scripts/install.sh`
- `npm/install.js`

For `uses: pmaojo/vord@v0` to resolve, push a moving major tag after the
release:

```sh
git tag -f v0 v0.1.1 && git push -f origin v0
```
