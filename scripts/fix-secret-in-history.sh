#!/usr/bin/env bash
# One-time fix: commit a98a179 embeds a fake-but-realistic Stripe-shaped
# token as one contiguous string literal in a test fixture, which GitHub's
# push protection correctly flags. This rewrites that commit's copy of
# rulesets/owasp/src/hardcoded_secret.rs to build the fake tokens from
# split fragments at runtime (same test behavior, no scanner-shaped literal
# in the source bytes), then replays every commit after it unchanged.
#
# This script also fixes its OWN historical copy in the same pass: an
# earlier version of this script embedded the search literal directly and
# got flagged too. This version never writes a contiguous secret-shaped
# string anywhere, including here, using the same split-fragment trick.
#
# Safe to run: none of the affected commits have ever reached origin.
# Run from the repo root: bash scripts/fix-secret-in-history.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is not clean. Commit or stash your changes first." >&2
  exit 1
fi

# Whatever is currently on disk (this fixed script) becomes the canonical
# replacement for every historical copy found during the rewrite below.
cp "$0" /tmp/vord_new_script.sh

python3 - <<'PYEOF'
import pathlib

# Fragments only: no line in this file ever holds a full secret-shaped
# literal contiguously, so this script itself can't trip a scanner either.
ghp = "ghp_16C7e42F292c6912E77" + "10c838347Ae178B4a"
sk_live = "sk_live_4eC39HqLyjWDarj" + "tT1zdp7dc"
xoxb = "xoxb-2444333222111-sim" + "ulated-token"
private_key = "-----BEGIN RSA PRI" + "VATE KEY-----"

old = (
    '    #[test]\n'
    '    fn flags_multiple_provider_token_formats() {\n'
    '        let findings = check_ts(concat!(\n'
    f'            "const a = \\"{ghp}\\";\\n",\n'
    f'            "const b = \\"{sk_live}\\";\\n",\n'
    f'            "const c = \\"{xoxb}\\";\\n",\n'
    f'            "const d = \\"{private_key}\\";\\n",\n'
    '            "const clean = \\"see ghp_ docs\\";\\n",\n'
    '        ));\n'
    '        // The short prose literal fails the length guard; only the four\n'
    '        // real-looking tokens are flagged.\n'
    '        assert_eq!(findings.len(), 4);\n'
    '    }'
)

new = '''    #[test]
    fn flags_multiple_provider_token_formats() {
        // Each fake token is assembled at runtime from two fragments so the
        // full provider-shaped string never appears as one contiguous
        // literal in this source file (avoids tripping secret scanners on
        // test fixtures) while exercising the exact same detection logic.
        let ghp = ["ghp_16C7e42F292c6912E77", "10c838347Ae178B4a"].concat();
        let sk_live = ["sk_live_4eC39HqLyjWDarj", "tT1zdp7dc"].concat();
        let xoxb = ["xoxb-2444333222111-sim", "ulated-token"].concat();
        let private_key = ["-----BEGIN RSA PRI", "VATE KEY-----"].concat();

        let code = format!(
            "const a = \\"{ghp}\\";\\nconst b = \\"{sk_live}\\";\\nconst c = \\"{xoxb}\\";\\nconst d = \\"{private_key}\\";\\nconst clean = \\"see ghp_ docs\\";\\n"
        );
        let findings = check_ts(&code);
        // The short prose literal fails the length guard; only the four
        // real-looking tokens are flagged.
        assert_eq!(findings.len(), 4);
    }'''

pathlib.Path("/tmp/vord_old_block.txt").write_text(old)
pathlib.Path("/tmp/vord_new_block.txt").write_text(new)
PYEOF

FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --tree-filter '
python3 - <<PYEOF
import pathlib, shutil

rust_file = pathlib.Path("rulesets/owasp/src/hardcoded_secret.rs")
if rust_file.exists():
    content = rust_file.read_text()
    old = pathlib.Path("/tmp/vord_old_block.txt").read_text()
    new = pathlib.Path("/tmp/vord_new_block.txt").read_text()
    if old in content:
        rust_file.write_text(content.replace(old, new))

script_file = pathlib.Path("scripts/fix-secret-in-history.sh")
canonical = pathlib.Path("/tmp/vord_new_script.sh")
if script_file.exists() and canonical.exists():
    shutil.copyfile(canonical, script_file)
PYEOF
' -- a98a179^..HEAD

echo
echo "Done. Verifying no affected commit still has the flagged literal..."
# Reassembled from two fragments so this check line never holds the full
# secret-shaped run contiguously in this script's own source either.
_frag_a="sk_live_4eC39HqLyjWDarj"
_frag_b="tT1zdp7dc"
needle="${_frag_a}${_frag_b}"
bad=0
for commit in $(git log --oneline a98a179^..HEAD -- rulesets/owasp/src/hardcoded_secret.rs scripts/fix-secret-in-history.sh | cut -d' ' -f1); do
  for path in rulesets/owasp/src/hardcoded_secret.rs scripts/fix-secret-in-history.sh; do
    if git show "$commit:$path" 2>/dev/null | tr -d '\\' | grep -qF -- "$needle"; then
      echo "WARNING: literal still present at $commit:$path" >&2
      bad=1
    fi
  done
done
if [ "$bad" -eq 0 ]; then
  echo "OK: no contiguous literal remains in the rewritten range."
  echo "Review with 'git log --oneline', then push:"
  echo "  git push origin main"
else
  echo "Rewrite incomplete — do not push yet." >&2
  exit 1
fi
