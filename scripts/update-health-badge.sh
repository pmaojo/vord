#!/usr/bin/env bash
# Regenerates .vord-health.json from a vord scan so the README badge
# stays current. Run this in CI after every scan, or locally after
# significant changes to watch the score trend.
#
# The output is a shields.io endpoint JSON:
#   { "schemaVersion": 1, "label": "health", "message": "96/100", "color": "brightgreen" }
#
# shields.io renders it as a badge via the dynamic JSON endpoint:
#   https://img.shields.io/badge/dynamic/json?url=<raw-github-url>/.vord-health.json&query=$.message&label=health

set -euo pipefail

VORD="${1:-./target/debug/vord}"
SCAN_PATH="${2:-.}"

if [ ! -x "$VORD" ] && ! command -v "$VORD" &>/dev/null; then
  echo "vord binary not found at $VORD and not on PATH" >&2
  exit 1
fi

JSON=$("$VORD" scan "$SCAN_PATH" --format json 2>/dev/null || true)

if [ -z "$JSON" ]; then
  echo "vord scan produced no output — writing unknown badge" >&2
  cat > .vord-health.json <<'JSONEOF'
{"schemaVersion":1,"label":"health","message":"unknown","color":"lightgrey"}
JSONEOF
  exit 0
fi

SCORE=$(echo "$JSON" | python3 -c "
import json, sys
d = json.load(sys.stdin)
score = d.get('health_score')
# Only trust the real health_score from the engine — no crude approximation.
if score is None:
    print('unknown')
else:
    print(int(score))
" 2>/dev/null || echo "unknown")

if [ "$SCORE" = "unknown" ]; then
  COLOR="lightgrey"
  MESSAGE="unknown"
else
  MESSAGE="$SCORE/100"
  if   [ "$SCORE" -ge 90 ]; then COLOR=brightgreen
  elif [ "$SCORE" -ge 75 ]; then COLOR=green
  elif [ "$SCORE" -ge 60 ]; then COLOR=yellow
  else COLOR=red
  fi
fi

cat > .vord-health.json <<JSONEOF
{"schemaVersion":1,"label":"health","message":"$MESSAGE","color":"$COLOR"}
JSONEOF

echo "vord health badge: $MESSAGE ($COLOR)"
