# yunq Precision Evaluation: OWASP Benchmark v1.2

## Environment
```
OS:       Darwin
CPU:      Apple M2 Pro
Cores:    10
RAM:      16.0 GB
yunq:     yunq 0.2.1
```

## Corpus
- **Test cases**: 2740
- **LOC scanned**: 252,966
- **Scan duration**: 95.1s

## Global Results

| Metric | Value |
|---|---|
| True Positives (TP) | 992 |
| False Positives (FP) | 887 |
| True Negatives (TN) | 438 |
| False Negatives (FN) | 423 |
| **Precision** | **52.79%** |
| **Recall** | **70.11%** |
| **F1 Score** | **60.23%** |
| False Positive Rate | 66.94% |

## Per-Category Results

| Category | Total | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 251 | 22 | 18 | 107 | 104 | 55.0% | 17.46% | 26.51% |
| crypto | 246 | 130 | 116 | 0 | 0 | 52.85% | 100.0% | 69.15% |
| hash | 236 | 86 | 77 | 30 | 43 | 52.76% | 66.67% | 58.9% |
| ldapi | 59 | 27 | 32 | 0 | 0 | 45.76% | 100.0% | 62.79% |
| pathtraver | 268 | 88 | 79 | 56 | 45 | 52.69% | 66.17% | 58.67% |
| securecookie | 67 | 28 | 19 | 12 | 8 | 59.57% | 77.78% | 67.47% |
| sqli | 504 | 224 | 184 | 48 | 48 | 54.9% | 82.35% | 65.88% |
| trustbound | 126 | 44 | 27 | 16 | 39 | 61.97% | 53.01% | 57.14% |
| weakrand | 493 | 218 | 275 | 0 | 0 | 44.22% | 100.0% | 61.32% |
| xpathi | 35 | 13 | 11 | 9 | 2 | 54.17% | 86.67% | 66.67% |
| xss | 455 | 112 | 49 | 160 | 134 | 69.57% | 45.53% | 55.04% |

## Rules Fired

| Rule | Test Cases Flagged | Examples |
|---|---|---|
| `owasp:xss-java` | 1519 | 1, 2, 3, 4, 5 |
| `smells:long-function` | 878 | 3, 5, 9, 10, 19 |
| `owasp:path-traversal-java` | 362 | 1, 2, 3, 5, 9 |
| `smells:cognitive-complexity` | 361 | 9, 10, 35, 38, 53 |
| `smells:high-complexity` | 311 | 5, 9, 10, 20, 35 |
| `smells:select-star` | 310 | 24, 26, 32, 33, 34 |
| `owasp:weak-crypto` | 183 | 5, 19, 20, 35, 50 |
| `secrets:high-entropy-string` | 59 | 12, 21, 44, 138, 139 |
