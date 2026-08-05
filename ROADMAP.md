# Roadmap

## Upcoming Focus

Future releases of `vord` will focus on:
- Advanced cross-language call graph resolution and cross-crate inter-procedural taint analysis.
- Expanding architectural rulesets and continuous precision tuning against real-world open source projects.
- Issue Triage Factory (roadmap C): reproduce → diagnose → fix incoming GitHub issues autonomously, gated by exit codes and an agent session's own regression-free completion rather than a model's self-assessment. `vord triage advance` drives all three stages end-to-end today; opening a PR from a verified fix is the remaining piece. See [`docs/design/issue-triage-factory.md`](docs/design/issue-triage-factory.md).
