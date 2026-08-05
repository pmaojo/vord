# Roadmap

## Upcoming Focus

Future releases of `vord` will focus on:
- Advanced cross-language call graph resolution and cross-crate inter-procedural taint analysis.
- Expanding architectural rulesets and continuous precision tuning against real-world open source projects.
- Issue Triage Factory (roadmap C): reproduce → diagnose → fix incoming GitHub issues autonomously, gated by re-scans and test runs rather than a model's self-assessment. `vord triage advance` drives the Reproduce stage end-to-end today; Diagnose and Fix still need a live agent session wired in. See [`docs/design/issue-triage-factory.md`](docs/design/issue-triage-factory.md).
