#!/usr/bin/env bash
# ==============================================================================
# vord coverage auto-detection (research gap #5)
# ==============================================================================
# Instead of requiring the user to locate and pass LCOV/Cobertura/JaCoCo/
# llvm-cov/Istanbul reports by hand, detect the project's coverage tooling and
# existing report files, and print the exact `vord scan` invocation that
# ingests them.
#
# Usage:
#   scripts/detect-coverage.sh [path]          # print detected reports
#   scripts/detect-coverage.sh [path] --scan   # run vord with the detected report
#   VORD_BIN=./target/release/vord scripts/detect-coverage.sh --scan
# ==============================================================================

set -uo pipefail

ROOT="${1:-.}"
SCAN="${2:-}"
if [[ "${1}" == "--scan" ]]; then
  ROOT="."
  SCAN="--scan"
elif [[ "${2}" == "--scan" ]]; then
  SCAN="--scan"
fi
ROOT="$(cd "${ROOT}" && pwd)"
VORD_BIN="${VORD_BIN:-vord}"

declare -A REPORT_FORMAT
found=()

# Rust: llvm-cov (lcov.info), tarpaulin (cobertura.xml), grcov (lcov.info)
for f in lcov.info target/llvm-cov/lcov.info cobertura.xml target/tarpaulin/cobertura.xml; do
  if [[ -f "${ROOT}/${f}" ]]; then REPORT_FORMAT["${ROOT}/${f}"]="lcov"; found+=("${ROOT}/${f}"); fi
done

# JS/TS: jest/vitest (coverage/lcov.info or coverage-final.json), nyc/istanbul
for f in coverage/lcov.info coverage/coverage-final.json .nyc_output/coverage-final.json; do
  if [[ -f "${ROOT}/${f}" ]]; then
    case "${f}" in
      *.info) REPORT_FORMAT["${ROOT}/${f}"]="lcov" ;;
      *.json) REPORT_FORMAT["${ROOT}/${f}"]="istanbul" ;;
    esac
    found+=("${ROOT}/${f}")
  fi
done

# Python: coverage.py (coverage.xml) or its .coverage converted to lcov
for f in coverage.xml htmlcov/coverage.xml; do
  if [[ -f "${ROOT}/${f}" ]]; then REPORT_FORMAT["${ROOT}/${f}"]="cobertura"; found+=("${ROOT}/${f}"); fi
done
if [[ -f "${ROOT}/.coverage" ]]; then
  echo "# .coverage (coverage.py) found — convert with: coverage lcov -o lcov.info" >&2
fi

# Java: JaCoCo (jacoco.xml — the CSV export is not parseable by vord's
# XML importer; point users at the report goal instead), Cobertura
for f in target/site/jacoco/jacoco.xml build/reports/jacoco/test/jacocoTestReport.xml; do
  if [[ -f "${ROOT}/${f}" ]]; then
    REPORT_FORMAT["${ROOT}/${f}"]="jacoco"
    found+=("${ROOT}/${f}")
  fi
done
if [[ -f "${ROOT}/target/site/jacoco/jacoco.csv" ]]; then
  echo "# jacoco.csv found — vord's JaCoCo importer reads XML; regenerate with 'mvn jacoco:report'" >&2
fi
for f in target/site/cobertura/coverage.xml build/reports/cobertura/coverage.xml; do
  if [[ -f "${ROOT}/${f}" ]]; then REPORT_FORMAT["${ROOT}/${f}"]="cobertura"; found+=("${ROOT}/${f}"); fi
done

# Go: go test -coverprofile=coverage.out (convert with gcov2lcov)
for f in coverage.out coverage/lcov.info; do
  if [[ -f "${ROOT}/${f}" ]]; then
    case "${f}" in
      *.out) echo "# go coverage.out found — convert with: gcov2lcov -infile coverage.out -outfile lcov.info" >&2 ;;
      *.info) REPORT_FORMAT["${ROOT}/${f}"]="lcov"; found+=("${ROOT}/${f}") ;;
    esac
  fi
done

# Toolchain hint if nothing was found.
if [[ ${#found[@]} -eq 0 ]]; then
  echo "# no coverage report found under ${ROOT}"
  echo "# generate one first, e.g.:"
  echo "#   Rust:  cargo llvm-cov --workspace --lcov --output-path lcov.info"
  echo "#   JS/TS: npx jest --coverage  (writes coverage/lcov.info)"
  echo "#   Py:    coverage run -m pytest && coverage xml"
  echo "#   Java:  mvn jacoco:report     (writes target/site/jacoco/jacoco.xml)"
  exit 1
fi

if [[ "${SCAN}" == "--scan" ]]; then
  for report in "${found[@]}"; do
    fmt="${REPORT_FORMAT["${report}"]}"
    echo "==> vord scan ${ROOT} --coverage-report ${report} --coverage-format ${fmt}"
    "${VORD_BIN}" scan "${ROOT}" --coverage-report "${report}" --coverage-format "${fmt}"
  done
else
  echo "# detected coverage report(s):"
  for report in "${found[@]}"; do
    echo "  ${report}  (${REPORT_FORMAT["${report}"]})"
  done
  echo ""
  echo "# run vord with them:"
  for report in "${found[@]}"; do
    echo "  vord scan ${ROOT} --coverage-report ${report} --coverage-format ${REPORT_FORMAT["${report}"]}"
  done
fi
