//! `vord swarm` — multi-agent orchestration (roadmap B).
//!
//! Adapted from Uncle Bob's swarm-forge: the protocol, not the
//! implementation. Worktree-per-agent isolation and durable file-based
//! handoffs are the load-bearing ideas; swarm-forge coordinates them through
//! tmux and a shared `scripts/` directory, which is a shell-level answer to a
//! problem vord can solve in-process and in-binary.
//!
//! Pure by construction, like every other `core/` crate: no filesystem, no
//! process spawning, no clock. [`worktree::plan_worktree`] only computes
//! *where* a role's worktree and branch belong; [`handoff::parse_handoff`]
//! only validates one handoff's bytes. Both are deliberately silent about how
//! a caller gets those bytes onto disk — that I/O lives in `infra/fs`, the
//! same split every other `core`/`infra` pair in this workspace follows.
//! Per-role policy scoping (roadmap B3) lives in `core/agent-policy` itself
//! (`AgentPolicy::with_role_scope`) rather than here, since it needs direct
//! access to that crate's compiled `GlobSet`. [`topology::resolve_topology`]
//! (roadmap B4) is the last pure decision a pipeline run needs: which roles,
//! in what order — driving them (creating worktrees, running `vord agent`,
//! moving handoffs) is I/O and lives in `bin/cli::swarm`.

pub mod handoff;
pub mod topology;
pub mod worktree;

pub use handoff::{Handoff, HandoffError, parse_handoff};
pub use topology::{FOUR_PACK, TRIAGE_PACK, TWO_PACK, TopologyError, next_role, resolve_topology};
pub use worktree::{DEFAULT_WORKTREE_ROOT, RoleWorktreeConfig, WorktreePlan, plan_worktree};
