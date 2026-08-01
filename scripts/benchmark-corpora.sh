#!/usr/bin/env bash
# ==============================================================================
# yunq Standard-Corpus Benchmark Harness
# ==============================================================================
# Runs yunq against standardized SAST corpora and publishes reproducible
# precision + performance numbers:
#
#   * OWASP Benchmark v1.2beta   (~2,740 labeled Java test cases)
#   * NIST Juliet Test Suite — Java  (112 CWEs, ~25k cases, Maven/Gradle)
#   * NIST Juliet Test Suite — C/C++ (~64k cases, CMake build)
#
# For each corpus it:
#   * captures hardware/OS metadata (CPU model, cores, RAM) in the report,
#   * warms up the scanner, then runs N *clean* measured repetitions,
#   * reports median/min/max wall time and LOC/s,
#   * saves the scan's JSON and SARIF artifacts for publishing.
#
# Usage:
#   scripts/benchmark-corpora.sh --corpus owasp --repetitions 5
#   scripts/benchmark-corpora.sh --corpus juliet-java --repetitions 3
#   scripts/benchmark-corpora.sh --corpus juliet-cpp --repetitions 3
#   scripts/benchmark-corpora.sh --corpus all --no-build
#   scripts/benchmark-corpora.sh --sample /path/to/repo --repetitions 3
#
# NOTES:
#   * Juliet Java is ~15 MB; Juliet C/C++ is ~700 MB.
#   * The Microsoft SCA Java dataset (microsoft/vulnerability-dataset) that
#     was listed here originally has been deleted from GitHub. Use
#     `--corpus owasp` for labeled Java security benchmarks instead.
#   * Start with --corpus owasp for quick validation first.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORPORA_DIR="${PROJECT_ROOT}/.benchmark-corpora"
RESULTS_DIR="${PROJECT_ROOT}/.benchmark-results"
YUNQ_BIN="${PROJECT_ROOT}/target/release/yunq"

# --- defaults ----------------------------------------------------------------
CORPUS="all"
REPETITIONS=3
WARMUP=1
DO_FETCH=true
DO_BUILD=true
SAMPLE_PATH=""

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --corpus <name>      owasp | juliet-java | juliet-cpp | all   (default: all)
  --repetitions <n>    measured runs per corpus      (default: 3)
  --warmup <n>         warm-up runs before measuring (default: 1)
  --sample <path>      run against any local directory instead of a corpus
  --no-fetch           skip downloads (use existing corpus trees)
  --no-build           skip the release build (binary must already exist)
  --help, -h           show this help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --corpus) CORPUS="$2"; shift 2 ;;
    --repetitions) REPETITIONS="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --sample) SAMPLE_PATH="$2"; shift 2 ;;
    --no-fetch) DO_FETCH=false; shift ;;
    --no-build) DO_BUILD=false; shift ;;
    --help|-h) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

mkdir -p "${CORPORA_DIR}" "${RESULTS_DIR}"

# --- hardware metadata --------------------------------------------------------
capture_hardware() {
  local os
  os="$(uname -s)"
  local cpu="unknown" cores="unknown" ram="unknown"
  if [[ "${os}" == "Darwin" ]]; then
    cpu="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
    cores="$(sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
    ram="$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 )) GB"
  elif [[ "${os}" == "Linux" ]]; then
    cpu="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo unknown)"
    cores="$(nproc 2>/dev/null || echo unknown)"
    ram="$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{printf "%.0f GB", $2/1024/1024}' || echo unknown)"
  fi
  echo "OS: ${os}"
  echo "CPU: ${cpu}"
  echo "Cores: ${cores}"
  echo "RAM: ${ram}"
  echo "yunq version: $("${YUNQ_BIN}" --version 2>/dev/null || echo unknown)"
}

# --- corpus definitions -------------------------------------------------------
corpus_source() {
  case "$1" in
    owasp)
      echo "https://github.com/OWASP-Benchmark/BenchmarkJava/archive/refs/tags/1.2beta.tar.gz" ;;
    juliet-java)
      echo "https://github.com/find-sec-bugs/juliet-test-suite/archive/refs/heads/master.tar.gz" ;;
    juliet-cpp)
      echo "https://github.com/arichardson/juliet-test-suite-c/archive/refs/heads/master.tar.gz" ;;
  esac
}

corpus_repo() {
  case "$1" in
    juliet-java) echo "https://github.com/find-sec-bugs/juliet-test-suite.git" ;;
    juliet-cpp)  echo "https://github.com/arichardson/juliet-test-suite-c.git" ;;
  esac
}

# For corpora hosted on GitHub, prefer git clone (faster, resume-friendly).
# For tarball-hosted corpora (OWASP), use curl + tar.
fetch_corpus() {
  local name="$1"
  local dir="${CORPORA_DIR}/${name}"
  if [[ -d "${dir}" && -n "$(ls -A "${dir}" 2>/dev/null)" ]]; then
    echo "  corpus '${name}' already present in ${dir}"
    return
  fi
  case "${name}" in
    owasp)
      echo "  downloading ${name} from $(corpus_source "${name}") ..."
      local tarball="${CORPORA_DIR}/${name}.tar.gz"
      curl -fL --retry 3 -o "${tarball}" "$(corpus_source "${name}")"
      mkdir -p "${dir}"
      tar -xzf "${tarball}" -C "${dir}" --strip-components=1
      rm -f "${tarball}"
      ;;
    juliet-java|juliet-cpp)
      echo "  cloning ${name} from $(corpus_repo "${name}") ..."
      git clone --depth 1 "$(corpus_repo "${name}")" "${dir}" 2>&1 | tail -1
      ;;
  esac
}

count_loc() {
  local dir="$1"
  find "${dir}" -type f \( -name '*.java' -o -name '*.c' -o -name '*.cpp' -o -name '*.h' -o -name '*.ts' -o -name '*.js' -o -name '*.py' -o -name '*.go' -o -name '*.rs' \) -print0 \
    | xargs -0 cat 2>/dev/null | wc -l | tr -d ' '
}

# --- one measured run ---------------------------------------------------------
run_corpus() {
  local name="$1" dir="$2"
  local ts
  ts="$(date +'%Y-%m-%d_%H-%M-%S')"
  local report="${RESULTS_DIR}/${name}_${ts}.md"
  local files loc

  echo ""
  echo "======================================================================"
  echo "  CORPUS: ${name}  (${dir})"
  echo "======================================================================"

  files="$(find "${dir}" -type f -not -path '*/.*' | wc -l | tr -d ' ')"
  loc="$(count_loc "${dir}")"

  # Warmup (cold caches, first parse of the tree).
  for _ in $(seq 1 "${WARMUP}"); do
    "${YUNQ_BIN}" scan "${dir}" --format json --no-cache > /dev/null 2>&1 || true
  done

  local times=() locs=()
  for i in $(seq 1 "${REPETITIONS}"); do
    # Clear yunq's own caches so every run is a clean, cold scan.
    rm -f "${PROJECT_ROOT}/.yunq-cache.json" "${dir}/.yunq-cache.json"
    local start end dur
    start="$(python3 -c 'import time; print(time.time())')"
    "${YUNQ_BIN}" scan "${dir}" --format json --no-cache > "${RESULTS_DIR}/${name}_run${i}_${ts}.json" 2>/dev/null
    end="$(python3 -c 'import time; print(time.time())')"
    dur="$(python3 -c "print(${end} - ${start})")"
    times+=("${dur}")
    locs+=("$(python3 -c "print(int(${loc} / max(${dur}, 0.000001)))")")
    # bash 3.2 (macOS default) has no negative array subscripts.
    local last_index=$(( ${#times[@]} - 1 ))
    echo "  run ${i}: ${dur}s  (~${locs[${last_index}]} LOC/s)"
  done

  "${YUNQ_BIN}" scan "${dir}" --format sarif --no-cache > "${RESULTS_DIR}/${name}_${ts}.sarif" 2>/dev/null || true

  # Aggregate: median/min/max of durations and throughput.
  local median min max locrate
  median="$(python3 -c "import statistics; print(round(statistics.median([${times[*]}]), 3))")"
  min="$(python3 -c "print(round(min([${times[*]}]), 3))")"
  max="$(python3 -c "print(round(max([${times[*]}]), 3))")"
  locrate="$(python3 -c "import statistics; print(round(statistics.median([${locs[*]}])))")"

  {
    echo "# yunq Benchmark: ${name} (${ts})"
    echo ""
    echo "## Environment"
    echo '```'
    capture_hardware
    echo '```'
    echo ""
    echo "## Corpus"
    echo "- Source: \`${dir}\`"
    echo "- Files: ${files}"
    echo "- LOC: ${loc}"
    echo "- Repetitions: ${REPETITIONS} (after ${WARMUP} warm-up run(s)), caches cleared between runs"
    echo ""
    echo "## Results"
    echo "| metric | value |"
    echo "|---|---|"
    echo "| wall time median (s) | ${median} |"
    echo "| wall time min (s) | ${min} |"
    echo "| wall time max (s) | ${max} |"
    echo "| throughput median (LOC/s) | ${locrate} |"
    echo ""
    echo "## Artifacts"
    echo "- JSON: \`${RESULTS_DIR}/${name}_run{1..${REPETITIONS}}_${ts}.json\`"
    echo "- SARIF: \`${RESULTS_DIR}/${name}_${ts}.sarif\`"
  } > "${report}"
  echo ""
  echo "  → ${report}"
  cp "${report}" "${RESULTS_DIR}/latest_${name}.md"
}

# --- build --------------------------------------------------------------------
if [[ "${DO_BUILD}" == true ]]; then
  echo "==> Building yunq release binary ..."
  cargo build --manifest-path "${PROJECT_ROOT}/Cargo.toml" --release --bin yunq
elif [[ ! -f "${YUNQ_BIN}" ]]; then
  echo "Error: ${YUNQ_BIN} missing; run without --no-build first." >&2
  exit 1
fi

# --- dispatch -----------------------------------------------------------------
if [[ -n "${SAMPLE_PATH}" ]]; then
  run_corpus "sample" "${SAMPLE_PATH}"
  exit 0
fi

case "${CORPUS}" in
  owasp|juliet-java|juliet-cpp)
    if [[ "${DO_FETCH}" == true ]] && ! fetch_corpus "${CORPUS}"; then
      echo "  download failed for '${CORPUS}' — rerun with --no-fetch once you have the tree"
      exit 1
    fi
    run_corpus "${CORPUS}" "${CORPORA_DIR}/${CORPUS}"
    ;;
  all)
    for c in owasp juliet-java juliet-cpp; do
      if [[ "${DO_FETCH}" == true ]] && ! fetch_corpus "${c}"; then
        echo "  download failed for '${c}' — skipping (corpora are independent)"
        continue
      fi
      run_corpus "${c}" "${CORPORA_DIR}/${c}"
    done
    ;;
  *) echo "Unknown corpus: ${CORPUS} (owasp|juliet-java|juliet-cpp|all)"; exit 1 ;;
esac

echo ""
echo "Done. Results in ${RESULTS_DIR}"
