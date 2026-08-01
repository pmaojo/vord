#!/usr/bin/env bash
# ==============================================================================
# yunq SAST & Performance Benchmark Suite
# ==============================================================================
# Clones, runs, and evaluates yunq against standard SAST benchmark targets,
# vulnerable applications, and clean production repositories.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${PROJECT_ROOT}/.benchmark-targets"
RESULTS_DIR="${PROJECT_ROOT}/.benchmark-results"
YUNQ_BIN="${PROJECT_ROOT}/target/release/yunq"

# Target definitions: "NAME|URL|CATEGORY|DESCRIPTION"
ALL_TARGETS=(
  "pygoat|https://github.com/adeyosemanputra/pygoat.git|Target App (Python)|Deliberately vulnerable Django app"
  "flask|https://github.com/pallets/flask.git|Clean Prod (Python)|WSGI web application framework"
  "express|https://github.com/expressjs/express.git|Clean Prod (Node.js)|Fast, unopinionated web framework"
  "juice-shop|https://github.com/OWASP/juice-shop.git|Target App (Node.js)|OWASP Juice Shop vulnerable app"
  "curl|https://github.com/curl/curl.git|Clean Prod (C)|Command line tool for transferring data with URLs"
  "sast-benchmark|https://github.com/Perdiga/sast-benchmark.git|Precision (Multi)|Labeled SAST vulnerability benchmark"
)

QUICK_TARGETS=("pygoat" "flask")

# Command line option defaults
DO_BUILD=true
SKIP_CLONE=false
QUICK_MODE=false
SELECTED_TARGET=""

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --target <name>   Run benchmark for a specific target (pygoat, flask, express, juice-shop, curl, sast-benchmark)
  --quick           Run benchmark on lightweight subset (pygoat, flask)
  --no-build        Skip cargo release build step
  --skip-clone      Use existing cloned repositories without pulling/cloning
  --help, -h        Show this help message
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      SELECTED_TARGET="$2"
      shift 2
      ;;
    --quick)
      QUICK_MODE=true
      shift
      ;;
    --no-build)
      DO_BUILD=false
      shift
      ;;
    --skip-clone)
      SKIP_CLONE=true
      shift
      ;;
    --help|-h)
      usage
      ;;
    *)
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

mkdir -p "${TARGET_DIR}" "${RESULTS_DIR}"

# 1. Build yunq release binary
if [[ "${DO_BUILD}" == true ]]; then
  echo "==> Building yunq release binary (cargo build --release --bin yunq)..."
  cargo build --manifest-path "${PROJECT_ROOT}/Cargo.toml" --release --bin yunq
elif [[ ! -f "${YUNQ_BIN}" ]]; then
  echo "Error: ${YUNQ_BIN} does not exist. Please run without --no-build first."
  exit 1
fi

TIMESTAMP="$(date +'%Y-%m-%d_%H-%M-%S')"
REPORT_FILE="${RESULTS_DIR}/benchmark_${TIMESTAMP}.md"
LATEST_REPORT="${RESULTS_DIR}/latest_report.md"

cat <<EOF > "${REPORT_FILE}"
# yunq Benchmark Results (${TIMESTAMP})

| Target | Category | Files | Duration (s) | Throughput (files/s) | Total Issues | Blocker | Critical | Major | Minor | Info |
|---|---|---|---|---|---|---|---|---|---|---|
EOF

echo ""
echo "======================================================================"
echo "                   yunq BENCHMARK RUNNER                              "
echo "======================================================================"
echo "Binary: ${YUNQ_BIN}"
echo "Targets Directory: ${TARGET_DIR}"
echo "Results Directory: ${RESULTS_DIR}"
echo "======================================================================"
echo ""

# Filter target list
RUN_TARGETS=()
for entry in "${ALL_TARGETS[@]}"; do
  IFS='|' read -r name url cat desc <<< "${entry}"
  
  if [[ -n "${SELECTED_TARGET}" ]]; then
    if [[ "${name}" == "${SELECTED_TARGET}" ]]; then
      RUN_TARGETS+=("${entry}")
    fi
  elif [[ "${QUICK_MODE}" == true ]]; then
    for q in "${QUICK_TARGETS[@]}"; do
      if [[ "${name}" == "${q}" ]]; then
        RUN_TARGETS+=("${entry}")
      fi
    done
  else
    RUN_TARGETS+=("${entry}")
  fi
done

if [[ ${#RUN_TARGETS[@]} -eq 0 ]]; then
  echo "Error: No targets selected or target '${SELECTED_TARGET}' not found."
  exit 1
fi

for entry in "${RUN_TARGETS[@]}"; do
  IFS='|' read -r name url cat desc <<< "${entry}"
  repo_path="${TARGET_DIR}/${name}"

  echo "----------------------------------------------------------------------"
  echo "► Target: ${name} (${cat})"
  echo "  Description: ${desc}"

  # Clone or pull target repo
  if [[ "${SKIP_CLONE}" == false ]]; then
    if [[ -d "${repo_path}" ]]; then
      echo "  Updating existing clone in ${repo_path}..."
      (cd "${repo_path}" && git fetch --depth 1 origin || true)
    else
      echo "  Cloning ${url} (shallow)..."
      git clone --depth 1 "${url}" "${repo_path}"
    fi
  fi

  # Count total files in target directory (excluding hidden files/dirs like .git)
  file_count=$(cd "${repo_path}" && find . -type f -not -path '*/.*' | wc -l | tr -d ' ')

  # Clear cache to ensure fresh scan with current binary rules
  rm -f "${PROJECT_ROOT}/.yunq-cache.json" "${repo_path}/.yunq-cache.json"

  echo "  Scanning ${file_count} files with yunq..."
  raw_json_output="${RESULTS_DIR}/${name}_${TIMESTAMP}.json"

  start_time=$(python3 -c 'import time; print(time.time())')
  set +e
  "${YUNQ_BIN}" scan "${repo_path}" --format json > "${raw_json_output}" 2>/dev/null
  scan_status=$?
  set -e
  end_time=$(python3 -c 'import time; print(time.time())')

  duration=$(python3 -c "print(round(${end_time} - ${start_time}, 3))")
  fps=$(python3 -c "print(round(${file_count} / max(${duration}, 0.001), 1))")

  # Parse metrics using embedded python script
  python3 - <<PYSCRIPT
import json, sys

json_path = "${raw_json_output}"
name = "${name}"
cat = "${cat}"
file_count = "${file_count}"
duration = "${duration}"
fps = "${fps}"
report_file = "${REPORT_FILE}"

try:
    with open(json_path, 'r') as f:
        data = json.load(f)
except Exception as e:
    data = {}

# Analyze findings
issues = data.get("issues", [])
total_issues = len(issues)

severities = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
rule_counts = {}

for issue in issues:
    sev = issue.get("severity", "INFO").upper()
    severities[sev] = severities.get(sev, 0) + 1
    rule_id = issue.get("rule_id") or issue.get("rule") or "unknown"
    rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
top_rules_str = ", ".join([f"{r}: {c}" for r, c in top_rules]) if top_rules else "None"

print(f"  ✓ Scan completed in {duration}s ({fps} files/sec)")
print(f"  Total Findings: {total_issues}")
print(f"  Severities: Blocker: {severities['BLOCKER']} | Critical: {severities['CRITICAL']} | Major: {severities['MAJOR']} | Minor: {severities['MINOR']} | Info: {severities['INFO']}")
print(f"  Top Rules Triggered: {top_rules_str}")

# Append line to markdown report
row = f"| {name} | {cat} | {file_count} | {duration} | {fps} | {total_issues} | {severities['BLOCKER']} | {severities['CRITICAL']} | {severities['MAJOR']} | {severities['MINOR']} | {severities['INFO']} |\n"
with open(report_file, 'a') as f:
    f.write(row)
PYSCRIPT

done

cp "${REPORT_FILE}" "${LATEST_REPORT}"

echo ""
echo "======================================================================"
echo "                  BENCHMARK SUMMARY REPORT                            "
echo "======================================================================"
cat "${REPORT_FILE}"
echo ""
echo "Report written to: ${REPORT_FILE}"
echo "Latest symlink/copy: ${LATEST_REPORT}"
echo "======================================================================"
