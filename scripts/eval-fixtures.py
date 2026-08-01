#!/usr/bin/env python3
"""
yunq Multi-Language Precision Benchmark
========================================
Runs yunq against the fixtures/ directory and evaluates precision/recall
against `fixtures/ground-truth.json`. Reports per-language metrics and
a global summary.

Unlike the OWASP Benchmark eval which uses file-level labels, this script
uses *rule-level expected findings*: each fixture file declares which
specific yunq rule IDs SHOULD fire on it. This gives us:
  - File-level Precision/Recall (any finding = flagged)
  - Rule-level Precision/Recall (expected rule matched exactly)

Output:
  .benchmark-results/fixtures-<timestamp>.json
  .benchmark-results/fixtures-<timestamp>.md
"""

import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
YUNQ_BIN = PROJECT_ROOT / "target" / "debug" / "yunq"
FIXTURES_DIR = PROJECT_ROOT / "fixtures"
GT_PATH = FIXTURES_DIR / ".ground-truth.json"
RESULTS_DIR = PROJECT_ROOT / ".benchmark-results"


def load_ground_truth() -> dict:
    with open(GT_PATH) as f:
        return json.load(f)


def run_yunq() -> tuple[list, float]:
    cmd = [str(YUNQ_BIN), "scan", str(FIXTURES_DIR), "--format", "json", "--no-cache"]
    start = time.time()
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    duration = time.time() - start
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        data = {}
    issues = data.get("issues", [])
    hotspots = data.get("hotspots", [])
    return issues + hotspots, duration


def lang_from_path(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return {
        ".ts": "typescript", ".tsx": "typescript", ".js": "typescript",
        ".py": "python",
        ".rs": "rust",
        ".html": "html",
        ".tf": "hcl", ".hcl": "hcl",
        ".yaml": "yaml", ".yml": "yaml",
        ".json": "json",
    }.get(ext, "other")


def evaluate(ground_truth: dict, findings: list[dict]) -> dict:
    """Compute per-language and global precision/recall."""
    files = ground_truth["files"]

    # Group findings by file basename
    issues_by_file: Dict[str, List[dict]] = defaultdict(list)
    for finding in findings:
        file_path = finding.get("file", "")
        base = Path(file_path).name
        issues_by_file[base].append(finding)

    # Per-language accumulators
    lang_stats: Dict[str, dict] = defaultdict(
        lambda: {"TP_file": 0, "FP_file": 0, "TN_file": 0, "FN_file": 0,
                 "TP_rule": 0, "FP_rule": 0, "FN_rule": 0,
                 "total": 0, "expected_rules_count": 0}
    )

    per_file_details = []
    rule_level_hits: Dict[str, dict] = defaultdict(
        lambda: {"expected": 0, "matched": 0}
    )

    for filename, label in files.items():
        lang = lang_from_path(filename)
        stats = lang_stats[lang]
        stats["total"] += 1

        is_vuln = label.get("is_vulnerable", False)
        expected_rules = label.get("expected_rules", [])
        stats["expected_rules_count"] += len(expected_rules)

        # Track expected rules for rule-level precision
        for rule_id in expected_rules:
            rule_level_hits[rule_id]["expected"] += 1

        # Get findings for this file
        file_issues = issues_by_file.get(filename, [])
        file_rules_fired = set(
            i.get("rule", i.get("rule_id", "unknown")) for i in file_issues
        )

        # File-level classification
        is_flagged = len(file_issues) > 0
        if is_vuln and is_flagged:
            stats["TP_file"] += 1
        elif not is_vuln and is_flagged:
            stats["FP_file"] += 1
        elif not is_vuln and not is_flagged:
            stats["TN_file"] += 1
        elif is_vuln and not is_flagged:
            stats["FN_file"] += 1

        # Rule-level: which expected rules fired?
        for rule_id in expected_rules:
            if rule_id in file_rules_fired:
                stats["TP_rule"] += 1
                rule_level_hits[rule_id]["matched"] += 1
            else:
                stats["FN_rule"] += 1

        # Rule-level FP: rules that fired but weren't expected
        for rule_id in file_rules_fired:
            if rule_id not in expected_rules:
                stats["FP_rule"] += 1

        per_file_details.append({
            "file": filename,
            "lang": lang,
            "is_vulnerable": is_vuln,
            "is_flagged": is_flagged,
            "expected_rules": expected_rules,
            "rules_fired": sorted(file_rules_fired),
            "missed_rules": sorted(set(expected_rules) - file_rules_fired),
            "extra_rules": sorted(file_rules_fired - set(expected_rules)),
        })

    # Compute per-language metrics
    per_lang = {}
    global_tp_file = global_fp_file = global_tn_file = global_fn_file = 0
    global_tp_rule = global_fp_rule = global_fn_rule = 0
    global_expected_rules = 0

    for lang, s in sorted(lang_stats.items()):
        if s["total"] == 0:
            continue
        global_tp_file += s["TP_file"]
        global_fp_file += s["FP_file"]
        global_tn_file += s["TN_file"]
        global_fn_file += s["FN_file"]
        global_tp_rule += s["TP_rule"]
        global_fp_rule += s["FP_rule"]
        global_fn_rule += s["FN_rule"]
        global_expected_rules += s["expected_rules_count"]

        def ratios(tp, fp, tn, fn):
            p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
            return round(p * 100, 1), round(r * 100, 1), round(f1 * 100, 1)

        fp, fr, ff1 = ratios(s["TP_file"], s["FP_file"], s["TN_file"], s["FN_file"])
        rp, rr, rf1 = ratios(s["TP_rule"], s["FP_rule"], 0, s["FN_rule"])

        per_lang[lang] = {
            "fixture_count": s["total"],
            "file_level": {
                "TP": s["TP_file"], "FP": s["FP_file"],
                "TN": s["TN_file"], "FN": s["FN_file"],
                "precision_pct": fp, "recall_pct": fr, "f1_pct": ff1,
            },
            "rule_level": {
                "TP": s["TP_rule"], "FP": s["FP_rule"], "FN": s["FN_rule"],
                "expected_rules": s["expected_rules_count"],
                "precision_pct": rp, "recall_pct": rr, "f1_pct": rf1,
            },
        }

    total_files = global_tp_file + global_fp_file + global_tn_file + global_fn_file
    fp, fr, ff1 = (
        global_tp_file / (global_tp_file + global_fp_file) * 100 if (global_tp_file + global_fp_file) > 0 else 0,
        global_tp_file / (global_tp_file + global_fn_file) * 100 if (global_tp_file + global_fn_file) > 0 else 0,
        0,
    )
    if (fp + fr) > 0:
        ff1 = 2 * fp * fr / (fp + fr)

    rp = global_tp_rule / (global_tp_rule + global_fp_rule) * 100 if (global_tp_rule + global_fp_rule) > 0 else 0
    rr = global_tp_rule / (global_tp_rule + global_fn_rule) * 100 if (global_tp_rule + global_fn_rule) > 0 else 0
    rf1 = 2 * rp * rr / (rp + rr) if (rp + rr) > 0 else 0

    # Rule-level report
    rule_details = {}
    for rule_id, counts in sorted(rule_level_hits.items()):
        matched = counts["matched"]
        expected = counts["expected"]
        rule_details[rule_id] = {
            "expected": expected,
            "matched": matched,
            "recall_pct": round(matched / expected * 100, 1) if expected > 0 else None,
        }

    return {
        "global": {
            "total_fixtures": total_files,
            "file_level": {
                "TP": global_tp_file, "FP": global_fp_file,
                "TN": global_tn_file, "FN": global_fn_file,
                "precision_pct": round(fp, 1),
                "recall_pct": round(fr, 1),
                "f1_pct": round(ff1, 1),
            },
            "rule_level": {
                "TP": global_tp_rule, "FP": global_fp_rule, "FN": global_fn_rule,
                "expected_rules": global_expected_rules,
                "precision_pct": round(rp, 1),
                "recall_pct": round(rr, 1),
                "f1_pct": round(rf1, 1),
            },
        },
        "by_language": per_lang,
        "by_rule": rule_details,
        "per_file": per_file_details,
    }


def generate_markdown(results: dict, duration: float) -> str:
    g = results["global"]
    lines = [
        "# yunq Multi-Language Precision Benchmark",
        "",
        f"**Scan duration:** {duration:.1f}s | **Corpus:** fixtures/ ({g['total_fixtures']} files)",
        "",
        "## Global Results",
        "",
        "### File-Level (any finding = flagged)",
        "| Metric | Value |",
        "|---|---|",
        f"| Precision | **{g['file_level']['precision_pct']}%** |",
        f"| Recall | **{g['file_level']['recall_pct']}%** |",
        f"| F1 | **{g['file_level']['f1_pct']}%** |",
        f"| TP={g['file_level']['TP']} FP={g['file_level']['FP']} TN={g['file_level']['TN']} FN={g['file_level']['FN']} | |",
        "",
        "### Rule-Level (expected rule exactly matched)",
        "| Metric | Value |",
        "|---|---|",
        f"| Precision | **{g['rule_level']['precision_pct']}%** |",
        f"| Recall | **{g['rule_level']['recall_pct']}%** |",
        f"| F1 | **{g['rule_level']['f1_pct']}%** |",
        f"| TP={g['rule_level']['TP']} FP={g['rule_level']['FP']} FN={g['rule_level']['FN']} (of {g['rule_level']['expected_rules']} expected) | |",
        "",
        "## Per Language",
        "",
        "| Language | Files | File P% | File R% | File F1% | Rule P% | Rule R% | Rule F1% |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for lang, s in results.get("by_language", {}).items():
        f = s["file_level"]
        r = s["rule_level"]
        lines.append(
            f"| {lang} | {s['fixture_count']} | {f['precision_pct']}% | {f['recall_pct']}% "
            f"| {f['f1_pct']}% | {r['precision_pct']}% | {r['recall_pct']}% | {r['f1_pct']}% |"
        )

    lines += [
        "",
        "## Per-Rule Recall",
        "",
        "| Rule | Expected | Matched | Recall |",
        "|---|---|---|---|",
    ]
    for rule_id, info in sorted(results.get("by_rule", {}).items(), key=lambda x: -(x[1].get("recall_pct") or 0)):
        r = info["recall_pct"]
        r_str = f"{r}%" if r is not None else "N/A"
        lines.append(f"| `{rule_id}` | {info['expected']} | {info['matched']} | {r_str} |")

    lines += ["", "## Per-File Details", ""]
    for fd in results.get("per_file", []):
        status = "✅" if fd["is_flagged"] == fd["is_vulnerable"] else "❌"
        lines.append(
            f"- {status} **{fd['file']}** ({fd['lang']}): "
            f"expected={fd['expected_rules']}, "
            f"fired={fd['rules_fired']}"
        )
        if fd["missed_rules"]:
            lines.append(f"  - Missed: {fd['missed_rules']}")
        if fd["extra_rules"]:
            lines.append(f"  - Extra: {fd['extra_rules']}")

    return "\n".join(lines) + "\n"


def main():
    print("=" * 60)
    print("yunq Multi-Language Precision Benchmark")
    print("=" * 60)

    gt = load_ground_truth()
    print(f"Ground truth: {len(gt['files'])} fixtures loaded")

    if not YUNQ_BIN.exists():
        print(f"Building yunq debug binary...")
        subprocess.run(["cargo", "build", "--bin", "yunq"], cwd=PROJECT_ROOT, check=True)

    print(f"\nRunning yunq scan on {FIXTURES_DIR} ...")
    all_findings, duration = run_yunq()
    print(f"Scan complete: {len(all_findings)} findings (issues + hotspots) in {duration:.1f}s")

    results = evaluate(gt, all_findings)

    # Print summary
    g = results["global"]
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"File-Level:  P={g['file_level']['precision_pct']}%  R={g['file_level']['recall_pct']}%  F1={g['file_level']['f1_pct']}%")
    print(f"Rule-Level:  P={g['rule_level']['precision_pct']}%  R={g['rule_level']['recall_pct']}%  F1={g['rule_level']['f1_pct']}%")
    print()
    for lang, s in results.get("by_language", {}).items():
        r = s["rule_level"]
        print(f"  {lang:12s}  Rule P={r['precision_pct']:5.1f}%  R={r['recall_pct']:5.1f}%  F1={r['f1_pct']:5.1f}%  ({s['fixture_count']} files)")

    # Save
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    json_path = RESULTS_DIR / f"fixtures-precision-{ts}.json"
    md_path = RESULTS_DIR / f"fixtures-precision-{ts}.md"
    json_path.write_text(json.dumps({
        "timestamp": ts,
        "duration_seconds": round(duration, 1),
        **results,
    }, indent=2))
    md_path.write_text(generate_markdown(results, duration))
    print(f"\n→ {md_path}")


if __name__ == "__main__":
    main()
