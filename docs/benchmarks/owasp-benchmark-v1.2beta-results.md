# vord Precision Evaluation: OWASP Benchmark v1.2

## Environment
```
OS:       Darwin
CPU:      Apple M2 Pro
Cores:    10
RAM:      16.0 GB
vord:     vord 0.2.1
```

## Corpus
- **Test cases**: 2740
- **LOC scanned**: 252,966
- **Scan duration**: 94.1s

## Global Results

| Metric | Value |
|---|---|
| True Positives (TP) | 566 |
| False Positives (FP) | 674 |
| True Negatives (TN) | 651 |
| False Negatives (FN) | 849 |
| **Precision** | **45.65%** |
| **Recall** | **40.0%** |
| **F1 Score** | **42.64%** |
| False Positive Rate | 50.87% |

## Per-Category Results

| Category | Total | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cmdi | 251 | 12 | 11 | 114 | 114 | 52.17% | 9.52% | 16.11% |
| crypto | 246 | 130 | 116 | 0 | 0 | 52.85% | 100.0% | 69.15% |
| hash | 236 | 65 | 59 | 48 | 64 | 52.42% | 50.39% | 51.38% |
| ldapi | 59 | 27 | 32 | 0 | 0 | 45.76% | 100.0% | 62.79% |
| pathtraver | 268 | 18 | 24 | 111 | 115 | 42.86% | 13.53% | 20.57% |
| securecookie | 67 | 7 | 3 | 28 | 29 | 70.0% | 19.44% | 30.43% |
| sqli | 504 | 169 | 149 | 83 | 103 | 53.14% | 62.13% | 57.29% |
| trustbound | 126 | 0 | 0 | 43 | 83 | 0.0% | 0.0% | 0.0% |
| weakrand | 493 | 137 | 275 | 0 | 81 | 33.25% | 62.84% | 43.49% |
| xpathi | 35 | 1 | 5 | 15 | 14 | 16.67% | 6.67% | 9.52% |
| xss | 455 | 0 | 0 | 209 | 246 | 0.0% | 0.0% | 0.0% |

## Rules Fired

| Rule | Test Cases Flagged | Examples |
|---|---|---|
| `smells:long-function` | 878 | 3, 5, 9, 10, 19 |
| `smells:cognitive-complexity` | 361 | 9, 10, 35, 38, 53 |
| `smells:high-complexity` | 311 | 5, 9, 10, 20, 35 |
| `smells:select-star` | 310 | 24, 26, 32, 33, 34 |
| `owasp:weak-crypto` | 183 | 5, 19, 20, 35, 50 |
| `secrets:high-entropy-string` | 59 | 12, 21, 44, 138, 139 |
