#!/usr/bin/env python3
"""
vord SAST Precision & False Positive Automated Evaluation Suite

Runs vord against labeled benchmark suites (OWASP Benchmark, Juliet, PythonSecurityEval,
or labeled JSON test cases) to compute exact Confusion Matrices:
  - True Positives (TP): Real security vulnerabilities correctly flagged
  - False Positives (FP): Clean code incorrectly flagged as vulnerable
  - True Negatives (TN): Clean code correctly ignored
  - False Negatives (FN): Real vulnerabilities missed by the scanner

Outputs Precision, Recall, F1 Score, and False Positive Rate (FPR).
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VORD_BIN = PROJECT_ROOT / "target" / "release" / "vord"


def ensure_vord_binary():
    if not VORD_BIN.exists():
        print(f"==> Building vord release binary at {VORD_BIN}...")
        subprocess.run(["cargo", "build", "--release", "--bin", "vord"], cwd=PROJECT_ROOT, check=True)


def run_vord_scan(target_dir):
    """Executes vord scan --format json over target_dir and returns parsed JSON output."""
    cmd = [str(VORD_BIN), "scan", str(target_dir), "--format", "json", "--no-cache"]
    start_time = time.time()
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    duration = time.time() - start_time
    
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        print(f"Error parsing vord JSON output. Stderr: {res.stderr}")
        data = {"issues": [], "files_scanned": 0}
        
    return data, duration


def evaluate_labeled_suite(suite_dir, expected_labels):
    """
    Compares vord scan findings against ground truth labels.
    expected_labels format:
    {
       "file_path.py": {"is_vulnerable": True/False, "cwe": "CWE-89"},
       ...
    }
    """
    ensure_vord_binary()
    scan_results, duration = run_vord_scan(suite_dir)
    
    flagged_files = set()
    for issue in scan_results.get("issues", []):
        file_path = issue.get("file", "")
        flagged_files.add(file_path)
        
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    
    for file, label in expected_labels.items():
        is_vuln = label.get("is_vulnerable", False)
        is_flagged = file in flagged_files
        
        if is_vuln and is_flagged:
            tp += 1
        elif not is_vuln and is_flagged:
            fp += 1
        elif not is_vuln and not is_flagged:
            tn += 1
        elif is_vuln and not is_flagged:
            fn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    report = {
        "suite": str(suite_dir),
        "duration_seconds": round(duration, 3),
        "total_test_cases": total,
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "metrics": {
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "false_positive_rate": round(fpr * 100, 2),
        }
    }
    return report


def main():
    print("=" * 70)
    print("vord Automated SAST Precision & False Positive Evaluation Runner")
    print("=" * 70)
    
    fixtures_dir = PROJECT_ROOT / "fixtures"
    
    # Synthetic ground truth for fixtures directory evaluation
    mock_labels = {
        "dirty.py": {"is_vulnerable": True},
        "caller.ts": {"is_vulnerable": True},
        "smelly_owasp_nosql.ts": {"is_vulnerable": True},
        "lookup_table.py": {"is_vulnerable": False},
        "lookup_table.ts": {"is_vulnerable": False},
    }
    
    report = evaluate_labeled_suite(fixtures_dir, mock_labels)
    
    print("\nEvaluation Summary:")
    print(f"  Target Suite: {report['suite']}")
    print(f"  Duration: {report['duration_seconds']}s")
    print(f"  Confusion Matrix: TP={report['confusion_matrix']['TP']}, FP={report['confusion_matrix']['FP']}, TN={report['confusion_matrix']['TN']}, FN={report['confusion_matrix']['FN']}")
    print(f"  Precision: {report['metrics']['precision']}%")
    print(f"  Recall: {report['metrics']['recall']}%")
    print(f"  F1 Score: {report['metrics']['f1_score']}%")
    print(f"  False Positive Rate (FPR): {report['metrics']['false_positive_rate']}%")
    print("=" * 70)


if __name__ == "__main__":
    main()
