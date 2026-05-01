#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_FILE="$ROOT_DIR/docs/benchmark-results.md"

mkdir -p "$ROOT_DIR/docs"

echo "# Benchmark Results" > "$OUT_FILE"
echo "" >> "$OUT_FILE"
echo "Generated at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$OUT_FILE"
echo "" >> "$OUT_FILE"

echo "## nginx-defender" >> "$OUT_FILE"
NGINX_TIME=$( { time go test ./cmd/nginx-defender >/dev/null; } 2>&1 | awk '/real/ {print $2}' )
echo "- baseline processing test runtime: ${NGINX_TIME}" >> "$OUT_FILE"

echo "" >> "$OUT_FILE"
echo "## Fail2Ban" >> "$OUT_FILE"
if command -v fail2ban-client >/dev/null 2>&1; then
  F2B_STATUS=$(fail2ban-client ping 2>/dev/null || true)
  echo "- fail2ban status: ${F2B_STATUS:-unknown}" >> "$OUT_FILE"
else
  echo "- fail2ban not installed in this environment" >> "$OUT_FILE"
fi

echo "" >> "$OUT_FILE"
echo "## Notes" >> "$OUT_FILE"
echo "- Run this script in a controlled environment with representative log replay for meaningful numbers." >> "$OUT_FILE"

echo "Benchmark report written to $OUT_FILE"
