#!/usr/bin/env python3
"""Correlate yunq's instant AST mutation gap findings with the output of a
traditional mutation-testing engine (StrykerJS/Stryker.NET/Infection, or PIT
converted to the same "Mutation Testing Elements" JSON schema).

The point (research gap #2): yunq's mutation rules are static O(N) gap
analysis — they say *where* a mutant would exist, not whether it survives.
Correlating them with a real engine's verdicts tells you how often a yunq
flagged site is a genuinely surviving mutant (high-value, test gap) versus a
killed one (already covered, low value).

Usage:
  yunq scan . --format json --no-cache > yunq.json
  stryker run  # produces reports/mutation-report.json (Stryker JSON schema)
  python3 scripts/correlate-mutation.py --yunq yunq.json --mutation reports/mutation-report.json
  python3 scripts/correlate-mutation.py --yunq yunq.json --mutation pit.json --out overlap.csv

Output: per-rule and per-file tables:
  * sites          — yunq mutation-rule findings
  * mutants        — total mutants the engine generated
  * matched        — yunq sites whose line range contains >= 1 mutant
  * killed / survived / no_coverage — engine verdicts at matched sites
  * survival_rate  — survived / (killed + survived + no_coverage)
"""

import argparse
import csv
import json
import sys
from collections import defaultdict


def load_yunq_findings(path: str):
    """yunq scan --format json -> list of (rule, file, line)."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    issues = data.get("issues", data if isinstance(data, list) else [])
    findings = []
    for issue in issues:
        rule = issue.get("rule_id") or issue.get("rule") or ""
        if not rule.startswith("mutation:"):
            continue
        file = issue.get("file") or issue.get("path") or ""
        line = issue.get("line") or (issue.get("span") or {}).get("start_line")
        findings.append({"rule": rule, "file": file, "line": int(line or 0)})
    return findings


def load_mutation_report(path: str):
    """Stryker 'Mutation Testing Elements' JSON: {schemaVersion, thresholds,
    files: {path: {language, mutants: [{id, mutatorName, replacement,
    location: {start:{line,column}, end:{line,column}}, status, ...}]}}}"""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    mutants = []
    files = data.get("files", {})
    if isinstance(files, list):
        # Some exports nest differently; try the common object form.
        files = {f.get("name", str(i)): f for i, f in enumerate(files)}
    for file, payload in files.items():
        file_mutants = payload.get("mutants", []) if isinstance(payload, dict) else []
        for m in file_mutants:
            loc = m.get("location", {})
            start = loc.get("start", {})
            end = loc.get("end", {})
            mutants.append(
                {
                    "file": file,
                    "mutator": m.get("mutatorName", "unknown"),
                    "status": (m.get("status") or "unknown").lower(),
                    "start_line": (start.get("line") or 1),
                    "end_line": (end.get("line") or start.get("line") or 1),
                }
            )
    return mutants


def line_overlap(a_start, a_end, b_start, b_end) -> bool:
    return not (a_end < b_start or b_end < a_start)


def correlate(sites, mutants, tolerance: int):
    """For each yunq site, does any mutant land on its line (within
    `tolerance` lines)? Returns per-rule and per-file stats."""
    by_file_mutants = defaultdict(list)
    for m in mutants:
        by_file_mutants[m["file"]].append(m)

    rule_stats = defaultdict(lambda: {"sites": 0, "matched": 0,
                                      "killed": 0, "survived": 0,
                                      "no_coverage": 0, "other": 0})
    file_stats = defaultdict(lambda: {"sites": 0, "matched": 0})
    matched_sites = []

    for site in sites:
        rule_stats[site["rule"]]["sites"] += 1
        file_stats[site["file"]]["sites"] += 1
        lo = site["line"] - tolerance
        hi = site["line"] + tolerance
        found = False
        for m in by_file_mutants.get(site["file"], []):
            if line_overlap(lo, hi, m["start_line"], m["end_line"]):
                found = True
                stats = rule_stats[site["rule"]]
                if m["status"] in ("killed", "timeout"):
                    stats["killed"] += 1
                elif m["status"] == "survived":
                    stats["survived"] += 1
                elif m["status"] == "no-coverage":
                    stats["no_coverage"] += 1
                else:
                    stats["other"] += 1
        if found:
            rule_stats[site["rule"]]["matched"] += 1
            file_stats[site["file"]]["matched"] += 1
            matched_sites.append(site)
    return rule_stats, file_stats, matched_sites


def render(rule_stats, file_stats, matched_sites, out_csv):
    total_sites = sum(s["sites"] for s in rule_stats.values())
    total_matched = sum(s["matched"] for s in rule_stats.values())
    total_killed = sum(s["killed"] for s in rule_stats.values())
    total_survived = sum(s["survived"] for s in rule_stats.values())
    total_nocov = sum(s["no_coverage"] for s in rule_stats.values())
    print("=" * 78)
    print("yunq mutation findings vs. mutation-engine verdicts")
    print("=" * 78)
    print(f"  yunq mutation sites:        {total_sites}")
    print(f"  sites with >= 1 real mutant:{total_matched}  ({100.0 * total_matched / max(total_sites, 1):.1f}% coverage)")
    print(f"  mutants at matched sites:   killed={total_killed} survived={total_survived} no_coverage={total_nocov}")
    survival = total_survived / max(total_killed + total_survived + total_nocov, 1)
    print(f"  survival rate at sites:     {100.0 * survival:.1f}%  "
          f"(share of yunq sites where the mutant actually survives -> real test gap)")
    print()
    print("  per rule:")
    print(f"  {'rule':<45} {'sites':>6} {'matched':>8} {'killed':>7} {'survived':>9} {'noCov':>6}")
    for rule, s in sorted(rule_stats.items()):
        print(f"  {rule:<45} {s['sites']:>6} {s['matched']:>8} {s['killed']:>7} {s['survived']:>9} {s['no_coverage']:>6}")

    if out_csv:
        with open(out_csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["rule", "sites", "matched", "killed", "survived", "no_coverage", "survival_rate"])
            for rule, s in sorted(rule_stats.items()):
                denom = max(s["killed"] + s["survived"] + s["no_coverage"], 1)
                writer.writerow([rule, s["sites"], s["matched"], s["killed"],
                                 s["survived"], s["no_coverage"],
                                 round(100.0 * s["survived"] / denom, 1)])
        print(f"\n  wrote CSV -> {out_csv}")
    print()
    print("  interpretation: a site with killed mutants is already covered;")
    print("  one with only survived/no_coverage mutants is a live test gap —")
    print("  the exact set to prioritize for `yunq fix` / new tests.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--yunq", required=True, help="yunq scan --format json output")
    ap.add_argument("--mutation", required=True, help="Stryker/PIT mutation report JSON")
    ap.add_argument("--out", default=None, help="optional CSV output")
    ap.add_argument("--tolerance", type=int, default=0,
                    help="line tolerance when matching a site to a mutant (default 0)")
    args = ap.parse_args()

    sites = load_yunq_findings(args.yunq)
    mutants = load_mutation_report(args.mutation)
    if not sites:
        print("no mutation:* findings in the yunq output — did the scan run the mutation ruleset?", file=sys.stderr)
    if not mutants:
        print("no mutants parsed from the mutation report — is it the Stryker Mutation Testing Elements schema?", file=sys.stderr)
    rule_stats, file_stats, matched = correlate(sites, mutants, args.tolerance)
    render(rule_stats, file_stats, matched, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
