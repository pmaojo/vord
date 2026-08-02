#!/usr/bin/env python3
"""
vord SAST Precision Evaluation: OWASP Benchmark v1.2
=====================================================
Runs vord against the OWASP Benchmark v1.2 (2,740 labeled Java test cases)
and computes per-category Confusion Matrices (TP/FP/TN/FN) plus aggregate
Precision, Recall, F1, and False Positive Rate.

Ground truth is parsed from `expectedresults-1.2.csv`, which ships with the
benchmark and maps each test case number to the expected result for every
tool that has been run against it.  vord findings are mapped back to test
cases by parsing `BenchmarkTestXXXXX.java` from the finding's file path.

Output:
  .benchmark-results/owasp-precision-<timestamp>.json  — full metrics
  .benchmark-results/owasp-precision-<timestamp>.md    — human-readable report
  .benchmark-results/latest_owasp_precision.md          — symlink for README badge
"""

import csv
import json
import os
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VORD_BIN = PROJECT_ROOT / "target" / "debug" / "vord"
CORPORA_DIR = PROJECT_ROOT / ".benchmark-corpora"
RESULTS_DIR = PROJECT_ROOT / ".benchmark-results"
OWASP_DIR = CORPORA_DIR / "owasp"
TESTCODE_DIR = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
EXPECTED_CSV = OWASP_DIR / "expectedresults-1.2beta.csv"


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def parse_expected_results(csv_path: Path) -> dict:
    """
    Parse the OWASP expectedresults CSV into a dict:
        {test_case_number: {"category": str, "cwe": int, "is_vulnerable": bool}}
    A test case is "vulnerable" if the majority of tools in the CSV report
    it as a true positive (the ` real vulnerability` column is "true").
    """
    gt = {}
    if not csv_path.exists():
        print(f"✗ Expected results not found: {csv_path}")
        print("  Download the OWASP Benchmark v1.2 first:")
        print(f"  scripts/benchmark-corpora.sh --corpus owasp")
        return gt

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # The "# test name" column loses its leading # when parsed
            # by DictReader, becoming " test name" or just "test name"
            tc_name = row.get("# test name", "").strip() or row.get("test name", "").strip()
            if not tc_name or not tc_name.startswith("BenchmarkTest"):
                continue
            try:
                tc = int(tc_name.replace("BenchmarkTest", ""))
            except ValueError:
                continue
            category = row.get(" category", "").strip() or row.get("category", "").strip()
            cwe = int(row.get(" cwe", "0").strip() or row.get("cwe", "0").strip() or "0")
            is_vuln = row.get(" real vulnerability", "").strip().lower() == "true" or \
                      row.get("real vulnerability", "").strip().lower() == "true"
            gt[tc] = {"category": category, "cwe": cwe, "is_vulnerable": is_vuln}
    return gt


# ---------------------------------------------------------------------------
# vord scan
# ---------------------------------------------------------------------------

def ensure_vord():
    if not VORD_BIN.exists():
        print(f"==> Building vord release binary at {VORD_BIN} ...")
        subprocess.run(["cargo", "build", "--release", "--bin", "vord"],
                       cwd=PROJECT_ROOT, check=True)


def run_vord_scan(target_dir: Path) -> tuple[dict, float]:
    """Run vord scan --format json on target_dir. Returns (parsed JSON, duration_seconds)."""
    cmd = [str(VORD_BIN), "scan", str(target_dir), "--format", "json", "--no-cache"]
    start = time.time()
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    duration = time.time() - start
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        print(f"Error parsing vord JSON. Stderr: {res.stderr[:500]}")
        data = {"issues": []}
    return data, duration


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------

# Regex to extract test case number from OWASP Benchmark filenames
TC_RE = re.compile(r"BenchmarkTest(\d{5})\.java")


def extract_test_case(file_path: str) -> Optional[int]:
    m = TC_RE.search(file_path)
    return int(m.group(1)) if m else None


def map_findings_to_test_cases(issues: list) -> dict:
    """Group vord findings by OWASP test case number."""
    by_tc: dict[int, list[dict]] = defaultdict(list)
    for issue in issues:
        tc = extract_test_case(issue.get("file", ""))
        if tc is not None:
            by_tc[tc].append(issue)
    return by_tc


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(ground_truth: dict, vord_findings: dict[int, list[dict]]):
    """
    Compute confusion matrix per category and globally.
    Returns a dict suitable for JSON serialization.
    """
    # Per-category accumulators
    cat_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "total": 0}
    )
    # Track which rules fired on which test cases (for gap analysis)
    rule_hits: dict[str, list[int]] = defaultdict(list)  # rule_id -> [tc, ...]
    unmatched_findings: list[dict] = []  # findings that couldn't be mapped

    for tc, label in ground_truth.items():
        category = label["category"] or "unknown"
        is_vuln = label["is_vulnerable"]
        is_flagged = tc in vord_findings

        stats = cat_stats[category]
        stats["total"] += 1

        if is_vuln and is_flagged:
            stats["TP"] += 1
            for finding in vord_findings[tc]:
                rule_hits[finding.get("rule", "unknown")].append(tc)
        elif not is_vuln and is_flagged:
            stats["FP"] += 1
            for finding in vord_findings[tc]:
                rule_hits[finding.get("rule", "unknown")].append(tc)
        elif not is_vuln and not is_flagged:
            stats["TN"] += 1
        elif is_vuln and not is_flagged:
            stats["FN"] += 1

    # Findings that couldn't be mapped to any test case
    all_tcs_in_findings = set()
    for tc in vord_findings:
        all_tcs_in_findings.add(tc)
    for tc in all_tcs_in_findings:
        if tc not in ground_truth:
            for finding in vord_findings[tc]:
                unmatched_findings.append(finding)

    # Compute metrics per category
    categories = {}
    global_tp = global_fp = global_tn = global_fn = 0
    for cat, s in sorted(cat_stats.items()):
        tp, fp, tn, fn = s["TP"], s["FP"], s["TN"], s["FN"]
        global_tp += tp
        global_fp += fp
        global_tn += tn
        global_fn += fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        categories[cat] = {
            "total": s["total"],
            "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
            "precision_pct": round(precision * 100, 2),
            "recall_pct": round(recall * 100, 2),
            "f1_pct": round(f1 * 100, 2),
            "fpr_pct": round(fpr * 100, 2),
        }

    total = global_tp + global_fp + global_tn + global_fn
    precision = global_tp / (global_tp + global_fp) if (global_tp + global_fp) > 0 else 0.0
    recall = global_tp / (global_tp + global_fn) if (global_tp + global_fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    fpr = global_fp / (global_fp + global_tn) if (global_fp + global_tn) > 0 else 0.0

    # Rule analysis
    rule_summary = {}
    for rule_id, tcs in sorted(rule_hits.items(), key=lambda x: -len(x[1])):
        rule_summary[rule_id] = {
            "test_cases_flagged": len(set(tcs)),
            "example_tcs": sorted(set(tcs))[:5],
        }

    return {
        "global": {
            "total_test_cases": total,
            "confusion_matrix": {"TP": global_tp, "FP": global_fp, "TN": global_tn, "FN": global_fn},
            "precision_pct": round(precision * 100, 2),
            "recall_pct": round(recall * 100, 2),
            "f1_pct": round(f1 * 100, 2),
            "fpr_pct": round(fpr * 100, 2),
        },
        "by_category": categories,
        "rules": rule_summary,
        "unmatched_findings_count": len(unmatched_findings),
        "test_cases_in_ground_truth": len(ground_truth),
        "test_cases_found_by_vord": len(vord_findings),
    }


# ---------------------------------------------------------------------------
# Hardware metadata
# ---------------------------------------------------------------------------

def capture_hardware() -> dict:
    import platform
    info = {"os": platform.system(), "python": platform.python_version()}
    try:
        if platform.system() == "Darwin":
            import subprocess
            cpu = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"],
                                          text=True).strip()
            cores = subprocess.check_output(["sysctl", "-n", "hw.ncpu"], text=True).strip()
            mem = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip()
            info["cpu"] = cpu
            info["cores"] = int(cores)
            info["ram_gb"] = round(int(mem) / (1024**3), 1)
        elif platform.system() == "Linux":
            info["cpu"] = subprocess.check_output(
                ["grep", "-m1", "model name", "/proc/cpuinfo"], text=True
            ).split(":")[1].strip()
            info["cores"] = int(subprocess.check_output(["nproc"], text=True).strip())
            mem_kb = int(subprocess.check_output(
                ["grep", "MemTotal", "/proc/meminfo"], text=True
            ).split()[1])
            info["ram_gb"] = round(mem_kb / (1024**2), 1)
    except Exception:
        pass
    try:
        info["vord_version"] = subprocess.check_output(
            [str(VORD_BIN), "--version"], text=True
        ).strip()
    except Exception:
        info["vord_version"] = "unknown"
    return info


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_markdown(results: dict, hardware: dict, duration: float, loc: int) -> str:
    g = results["global"]
    cm = g["confusion_matrix"]

    lines = [
        "# vord Precision Evaluation: OWASP Benchmark v1.2",
        "",
        "## Environment",
        "```",
        f"OS:       {hardware.get('os', 'unknown')}",
        f"CPU:      {hardware.get('cpu', 'unknown')}",
        f"Cores:    {hardware.get('cores', 'unknown')}",
        f"RAM:      {hardware.get('ram_gb', 'unknown')} GB",
        f"vord:     {hardware.get('vord_version', 'unknown')}",
        "```",
        "",
        "## Corpus",
        f"- **Test cases**: {g['total_test_cases']}",
        f"- **LOC scanned**: {loc:,}",
        f"- **Scan duration**: {duration:.1f}s",
        "",
        "## Global Results",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| True Positives (TP) | {cm['TP']} |",
        f"| False Positives (FP) | {cm['FP']} |",
        f"| True Negatives (TN) | {cm['TN']} |",
        f"| False Negatives (FN) | {cm['FN']} |",
        f"| **Precision** | **{g['precision_pct']}%** |",
        f"| **Recall** | **{g['recall_pct']}%** |",
        f"| **F1 Score** | **{g['f1_pct']}%** |",
        f"| False Positive Rate | {g['fpr_pct']}% |",
        "",
        "## Per-Category Results",
        "",
        "| Category | Total | TP | FP | TN | FN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for cat, s in results.get("by_category", {}).items():
        c = s["confusion_matrix"]
        lines.append(
            f"| {cat} | {s['total']} | {c['TP']} | {c['FP']} | {c['TN']} | {c['FN']} "
            f"| {s['precision_pct']}% | {s['recall_pct']}% | {s['f1_pct']}% |"
        )

    lines += [
        "",
        "## Rules Fired",
        "",
        "| Rule | Test Cases Flagged | Examples |",
        "|---|---|---|",
    ]
    for rule_id, info in sorted(results.get("rules", {}).items(),
                                 key=lambda x: -x[1]["test_cases_flagged"]):
        examples = ", ".join(str(tc) for tc in info["example_tcs"])
        lines.append(f"| `{rule_id}` | {info['test_cases_flagged']} | {examples} |")

    if results.get("unmatched_findings_count", 0) > 0:
        lines += [
            "",
            f"⚠ {results['unmatched_findings_count']} findings could not be mapped to any test case.",
        ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("vord SAST Precision Evaluation: OWASP Benchmark v1.2")
    print("=" * 70)

    ensure_vord()

    if not TESTCODE_DIR.exists():
        print(f"\n✗ OWASP Benchmark not found at {TESTCODE_DIR}")
        print("  Download it first:")
        print(f"  scripts/benchmark-corpora.sh --corpus owasp")
        sys.exit(1)

    # Count LOC
    loc = 0
    for java_file in TESTCODE_DIR.rglob("*.java"):
        try:
            loc += len(java_file.read_text().splitlines())
        except Exception:
            pass
    print(f"\nCorpus: {loc:,} LOC across {TESTCODE_DIR}")

    # Parse ground truth
    ground_truth = parse_expected_results(EXPECTED_CSV)
    print(f"Ground truth: {len(ground_truth)} test cases loaded")

    if not ground_truth:
        print("✗ No ground truth found. Check expectedresults-1.2.csv")
        sys.exit(1)

    # Run vord
    print(f"\nRunning vord scan on {TESTCODE_DIR} ...")
    vord_output, duration = run_vord_scan(TESTCODE_DIR)
    issues = vord_output.get("issues", [])
    print(f"Scan complete: {len(issues)} findings in {duration:.1f}s")

    # Map findings to test cases
    vord_findings = map_findings_to_test_cases(issues)
    print(f"Mapped to {len(vord_findings)} test cases")

    # Evaluate
    results = evaluate(ground_truth, vord_findings)
    hardware = capture_hardware()

    # Print summary
    g = results["global"]
    cm = g["confusion_matrix"]
    print(f"\n{'='*70}")
    print(f"RESULTS")
    print(f"{'='*70}")
    print(f"  Test cases:     {g['total_test_cases']}")
    print(f"  TP={cm['TP']}  FP={cm['FP']}  TN={cm['TN']}  FN={cm['FN']}")
    print(f"  Precision:      {g['precision_pct']}%")
    print(f"  Recall:         {g['recall_pct']}%")
    print(f"  F1 Score:       {g['f1_pct']}%")
    print(f"  False Pos Rate: {g['fpr_pct']}%")
    print(f"  Duration:       {duration:.1f}s")

    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")

    json_path = RESULTS_DIR / f"owasp-precision-{ts}.json"
    json_path.write_text(json.dumps({
        "benchmark": "OWASP Benchmark v1.2",
        "timestamp": ts,
        "hardware": hardware,
        "duration_seconds": round(duration, 1),
        "loc_scanned": loc,
        **results,
    }, indent=2))

    md_path = RESULTS_DIR / f"owasp-precision-{ts}.md"
    md_path.write_text(generate_markdown(results, hardware, duration, loc))

    # Symlink latest
    latest_json = RESULTS_DIR / "latest_owasp_precision.json"
    latest_md = RESULTS_DIR / "latest_owasp_precision.md"
    for src, dst in [(json_path, latest_json), (md_path, latest_md)]:
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        dst.symlink_to(src.name)

    print(f"\n→ JSON: {json_path}")
    print(f"→ Markdown: {md_path}")
    print(f"→ Latest: {latest_md}")


if __name__ == "__main__":
    main()
