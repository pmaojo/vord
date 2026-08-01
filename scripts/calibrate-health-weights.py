#!/usr/bin/env python3
"""Empirically calibrate the yunq Health Score penalty weights (research
gap #3: "the Health Score weights are heuristic, not derived from data").

The engine currently uses (core/rules-engine/src/domain/report.rs,
`AnalysisReport::health_score`):

    health = 100 - (w_blk * blocker/kloc + w_crit * critical/kloc
                    + w_maj * major/kloc + w_hot * hotspots/kloc
                    + w_dup * duplicated_lines_density)

with weights w_blk=10.0, w_crit=5.0, w_maj=1.0, w_hot=2.0, w_dup=0.5.

This script fits those weights to a labeled dataset instead of trusting the
heuristic values. The dataset is a CSV of projects with their feature
counts and a human/expert-labeled health score (0-100, or a label column you
can map to 0-100):

    lines_of_code,blocker,critical,major,hotspots,dup_density,health
    60000,0,0,44,12,8.4,93
    5000,1,3,120,40,25.0,10

Fitting:
  * without numpy: grid search over a bounded weight space (slow but stdlib-only)
  * with numpy: least-squares solve (exact, fast)

Output: recommended weights, plus per-project residual error so you can
eyeball which projects the model misjudges. Use `--print-current` to see the
weights the engine ships today.
"""

import argparse
import csv
import math
import sys

CURRENT_WEIGHTS = {"w_blk": 10.0, "w_crit": 5.0, "w_maj": 1.0,
                   "w_hot": 2.0, "w_dup": 0.5}

FEATURES = ("blocker", "critical", "major", "hotspots", "dup_density")
# Feature name -> engine weight key (the engine uses short keys w_blk/w_crit/...).
WEIGHT_KEY = {"blocker": "w_blk", "critical": "w_crit", "major": "w_maj",
              "hotspots": "w_hot", "dup_density": "w_dup"}


def features_vector(row):
    kloc = max(float(row["lines_of_code"]), 1.0) / 1000.0
    return [
        float(row["blocker"]) / kloc,
        float(row["critical"]) / kloc,
        float(row["major"]) / kloc,
        float(row["hotspots"]) / kloc,
        float(row["dup_density"]),
    ]


def predict(row, weights):
    penalty = sum(w * f for w, f in zip(weights, features_vector(row)))
    return max(0.0, 100.0 - penalty)


def load_dataset(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if "health" not in row:
                raise SystemExit(
                    'dataset must have a "health" column (0-100 label); '
                    "you can also name it 'score' and pass --label score"
                )
            rows.append(row)
    if not rows:
        raise SystemExit("empty dataset")
    return rows


def solve_least_squares(rows):
    """Minimize sum (target - (100 - sum w_i f_i))^2  ==  fit (sum w_i f_i) ~ (100 - target)."""
    try:
        import numpy as np
    except ImportError:
        return None
    A = np.array([features_vector(r) for r in rows], dtype=float)
    y = np.array([100.0 - float(r["health"]) for r in rows], dtype=float)
    weights, *_ = np.linalg.lstsq(A, y, rcond=None)
    return [float(w) for w in weights]


def grid_search(rows, steps=12):
    """Stdlib fallback: coarse grid around the current weights."""
    ranges = {
        "w_blk": (0.0, 20.0),
        "w_crit": (0.0, 12.0),
        "w_maj": (0.0, 6.0),
        "w_hot": (0.0, 8.0),
        "w_dup": (0.0, 2.0),
    }
    names = list(ranges)
    best = None
    best_err = float("inf")

    def sweep(idx, current):
        nonlocal best, best_err
        if idx == len(names):
            err = 0.0
            for r in rows:
                d = float(r["health"]) - predict(r, current)
                err += d * d
            if err < best_err:
                best_err = err
                best = current[:]
            return
        lo, hi = ranges[names[idx]]
        for i in range(steps + 1):
            current.append(lo + (hi - lo) * i / steps)
            sweep(idx + 1, current)
            current.pop()

    sweep(0, [])
    return best, math.sqrt(best_err / max(len(rows), 1))


def report(rows, weights, label):
    print(f"== fitted weights ({label}) ==")
    for name, w in zip(FEATURES, weights):
        print(f"  {name:<12} {w:8.3f}   (current: {CURRENT_WEIGHTS.get(WEIGHT_KEY[name], 0.0):.3f})")
    print()
    print("  per-project residual (predicted - labeled):")
    for r in rows:
        pred = predict(r, weights)
        target = float(r["health"])
        print(f"    {r.get('project', r.get('file', '?')):<40} pred={pred:6.1f} label={target:6.1f} "
              f"resid={pred - target:+6.1f}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dataset", help="CSV with lines_of_code, blocker, critical, major, hotspots, dup_density, health")
    ap.add_argument("--print-current", action="store_true", help="print the weights the engine ships today")
    args = ap.parse_args()

    if args.print_current:
        print("current engine weights (core/rules-engine/src/domain/report.rs):")
        for k, v in CURRENT_WEIGHTS.items():
            print(f"  {k:<8} {v}")
        return 0

    rows = load_dataset(args.dataset)
    weights = solve_least_squares(rows)
    if weights is not None:
        report(rows, weights, "numpy least squares")
    else:
        weights, rmse = grid_search(rows)
        print(f"numpy not available — grid search fit (RMSE {rmse:.2f}):")
        report(rows, weights, "grid search")
    return 0


if __name__ == "__main__":
    sys.exit(main())
