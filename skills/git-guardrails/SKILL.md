---
name: git-guardrails
description: "Safety rules for git operations in this repository — no direct commits/pushes to main, no unreviewed force-push, prefer reversible steps. Use whenever a session is about to run git commit, git push, git reset, git rebase, or any history-rewriting command in this repo."
---

# Git Guardrails

vord ships as a public Action other repositories depend on directly
(`uses: pmaojo/vord@vX.Y.Z`). A bad push here doesn't just break this
repo's CI — it can break every downstream repo pinned to a moving ref.
Treat git operations on this repository with the same care the
write-time guardrail applies to source edits.

## Rules, in order of how hard they are to undo

1. **Never commit or push directly to `main`.** Work on a branch, open a
   pull request, let `ci.yml` and review gate it in. `hooks/pre-push`
   enforces this mechanically — a direct push to `main`/`master` is
   rejected unless the caller explicitly adds `--no-verify`, which is
   itself a signal to stop and ask a human first.
2. **Never force-push a branch other agents or humans may have pulled.**
   `hooks/pre-push` rejects non-fast-forward pushes on the same terms.
   If a rebase is genuinely needed, use `--force-with-lease`, never bare
   `--force`, and only on a branch you are certain is yours alone.
3. **Never rewrite history that isn't yours.** No `rebase -i`, `commit
   --amend`, or `reset --hard` on a branch you didn't create in this
   session. If a pre-commit hook fails, fix and create a new commit —
   amending after a failed hook risks amending the *previous* commit,
   since the failed one never landed.
4. **Never bypass the gate to make a red build look green.**
   `hooks/pre-commit` and CI enforce `min_health_score` from
   `vord.toml`. `--no-verify` exists for legitimate exceptions a human
   chooses, not for a session working around its own failing scan.
5. **Treat `vord-policy.toml`, `vord.toml`, and `.github/workflows/*` as
   protected**, per `skills/agent-dev-loop/SKILL.md` — these decide what
   the guardrail enforces on everyone else. An agent that can loosen its
   own referee isn't governed by one.

## Before a destructive command

`git checkout -- .`, `git clean -f`, `git reset --hard`, and restoring
from a snapshot all discard uncommitted work. Run `git status` first;
stash (`git stash -u`) or commit anything found before proceeding. If
you find unfamiliar files or branches, investigate before deleting —
they may be someone else's in-progress work.

## Installing the hooks locally

```sh
git config core.hooksPath hooks
```

This wires both `hooks/pre-commit` (quality gate) and `hooks/pre-push`
(branch/force-push protection) for anyone who clones the repo — set it
once per clone; it isn't a server-side setting GitHub enforces on its
own, so a clone that skips this step still relies on PR review and CI.
