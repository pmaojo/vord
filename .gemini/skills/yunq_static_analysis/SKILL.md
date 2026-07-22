---
name: yunq-static-analysis
description: "Native ultraperformant SAST static analysis, code quality, and AI remediation skill for yunq"
---

# `yunq` Static Analysis AI Skill

This skill equips AI coding assistants (Antigravity, Cursor, Claude Code, GitHub Copilot) with native static analysis and code quality diagnostics powered by **yunq**.

## Capabilities

1. **Run Local SAST Analysis**:
   ```bash
   yunq scan .
   ```

2. **Automated AI Remediation**:
   ```bash
   yunq fix --path <file_path> --issue <rule_id>
   ```

3. **Check Quality Gate Status**:
   ```bash
   yunq scan . --enforce-gate
   ```

## Rules & Guidance
- Always inspect `yunq scan .` output when auditing code for vulnerabilities or code smells.
- Re-run `yunq scan .` after making code modifications to ensure 0 blocker/critical issues and 100/100 Health Score.
