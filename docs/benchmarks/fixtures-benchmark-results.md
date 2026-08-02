# vord Multi-Language Precision Benchmark

**Scan duration:** 0.1s | **Corpus:** fixtures/ (16 files)

## Global Results

### File-Level (any finding = flagged)
| Metric | Value |
|---|---|
| Precision | **75.0%** |
| Recall | **100.0%** |
| F1 | **85.7%** |
| TP=9 FP=3 TN=4 FN=0 | |

### Rule-Level (expected rule exactly matched)
| Metric | Value |
|---|---|
| Precision | **45.0%** |
| Recall | **100.0%** |
| F1 | **62.1%** |
| TP=18 FP=22 FN=0 (of 18 expected) | |

## Per Language

| Language | Files | File P% | File R% | File F1% | Rule P% | Rule R% | Rule F1% |
|---|---|---|---|---|---|---|---|
| hcl | 1 | 100.0% | 100.0% | 100.0% | 50.0% | 100.0% | 66.7% |
| html | 1 | 100.0% | 100.0% | 100.0% | 50.0% | 100.0% | 66.7% |
| python | 2 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| rust | 2 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| typescript | 10 | 62.5% | 100.0% | 76.9% | 28.6% | 100.0% | 44.4% |

## Per-Rule Recall

| Rule | Expected | Matched | Recall |
|---|---|---|---|
| `a11y:img-missing-alt` | 1 | 1 | 100.0% |
| `iac:open-ingress-cidr` | 1 | 1 | 100.0% |
| `owasp:command-execution` | 3 | 3 | 100.0% |
| `owasp:cross-file-injection` | 1 | 1 | 100.0% |
| `owasp:eval-usage` | 2 | 2 | 100.0% |
| `owasp:hardcoded-secret` | 2 | 2 | 100.0% |
| `react:rules-of-hooks-naming` | 1 | 1 | 100.0% |
| `secrets:aws-access-key-id` | 1 | 1 | 100.0% |
| `smells:long-function` | 2 | 2 | 100.0% |
| `smells:todo-comment` | 3 | 3 | 100.0% |
| `smells:unwrap-usage` | 1 | 1 | 100.0% |

## Per-File Details

- ✅ **vulnerable.ts** (typescript): expected=['owasp:hardcoded-secret', 'owasp:eval-usage', 'secrets:aws-access-key-id', 'smells:todo-comment'], fired=['owasp:eval-usage', 'owasp:hardcoded-secret', 'owasp:injection', 'secrets:aws-access-key-id', 'secrets:high-entropy-string', 'smells:todo-comment']
  - Extra: ['owasp:injection', 'secrets:high-entropy-string']
- ✅ **caller.ts** (typescript): expected=['owasp:cross-file-injection'], fired=['owasp:cross-file-injection']
- ✅ **lib_exec.ts** (typescript): expected=['owasp:command-execution'], fired=['owasp:command-execution']
- ❌ **smelly_owasp_nosql.ts** (typescript): expected=[], fired=['typescript:loose-equality']
  - Extra: ['typescript:loose-equality']
- ❌ **smelly_react.tsx** (typescript): expected=[], fired=['react:array-index-key', 'react:dangerously-set-inner-html', 'react:direct-state-mutation', 'react:hook-missing-deps-array', 'react:inline-prop-function-in-component', 'react:jsx-img-missing-alt', 'react:rules-of-hooks-conditional', 'react:unsafe-target-blank', 'typescript:leftover-debug-statement']
  - Extra: ['react:array-index-key', 'react:dangerously-set-inner-html', 'react:direct-state-mutation', 'react:hook-missing-deps-array', 'react:inline-prop-function-in-component', 'react:jsx-img-missing-alt', 'react:rules-of-hooks-conditional', 'react:unsafe-target-blank', 'typescript:leftover-debug-statement']
- ✅ **smelly_react_bulletproof.tsx** (typescript): expected=['react:rules-of-hooks-naming'], fired=['react:rules-of-hooks-naming', 'typescript:leftover-debug-statement', 'typescript:promise-then-without-catch']
  - Extra: ['typescript:leftover-debug-statement', 'typescript:promise-then-without-catch']
- ✅ **long_function.ts** (typescript): expected=['smells:long-function'], fired=['smells:cognitive-complexity', 'smells:high-complexity', 'smells:long-function']
  - Extra: ['smells:cognitive-complexity', 'smells:high-complexity']
- ✅ **inaccessible.html** (html): expected=['a11y:img-missing-alt'], fired=['a11y:img-missing-alt', 'a11y:missing-lang-attribute']
  - Extra: ['a11y:missing-lang-attribute']
- ✅ **insecure.tf** (hcl): expected=['iac:open-ingress-cidr'], fired=['iac:iam-wildcard-permission', 'iac:open-ingress-cidr']
  - Extra: ['iac:iam-wildcard-permission']
- ❌ **clean_react.tsx** (typescript): expected=[], fired=['react:hook-missing-deps-array', 'smells:cognitive-complexity', 'smells:high-complexity', 'typescript:leftover-debug-statement']
  - Extra: ['react:hook-missing-deps-array', 'smells:cognitive-complexity', 'smells:high-complexity', 'typescript:leftover-debug-statement']
- ✅ **clean_react_bulletproof.tsx** (typescript): expected=[], fired=[]
- ✅ **lookup_table.ts** (typescript): expected=[], fired=[]
- ✅ **dirty.py** (python): expected=['owasp:hardcoded-secret', 'owasp:eval-usage', 'owasp:command-execution', 'smells:todo-comment'], fired=['owasp:command-execution', 'owasp:eval-usage', 'owasp:hardcoded-secret', 'smells:todo-comment']
- ✅ **lookup_table.py** (python): expected=[], fired=[]
- ✅ **smelly.rs** (rust): expected=['smells:unwrap-usage', 'owasp:command-execution', 'smells:long-function', 'smells:todo-comment'], fired=['owasp:command-execution', 'smells:long-function', 'smells:todo-comment', 'smells:unwrap-usage']
- ✅ **duplication_edge.rs** (rust): expected=[], fired=[]
