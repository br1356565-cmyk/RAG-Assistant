#!/usr/bin/env bash
# Writes ~40 storefront log lines (normal traffic, 502s from a slow payment provider, one
# stack trace) to the demo log group, timestamped over the last hour. Re-run any time: log
# queries only look back a limited window (logs_tool_max_hours).
#   bash local/seed_demo_logs.sh [log-group] [region]
set -euo pipefail
GROUP=${1:-/demo/storefront}
REGION=${2:-${AWS_REGION:-ap-southeast-2}}
STREAM="storefront-$(date -u +%Y%m%d%H%M%S)"
now=$(date +%s%3N)
aws logs create-log-stream --log-group-name "$GROUP" --log-stream-name "$STREAM" --region "$REGION"

lines=()
for i in $(seq 1 40); do
  case $((i % 8)) in
    0) msg="ERROR payment provider timeout after 30000ms (order=$((4000 + i)))" ;;
    1) msg="GET /checkout 502 upstream timeout 30012ms" ;;
    2) msg="GET /preview?url=http://169.254.169.254/latest/meta-data/ 200 41ms" ;;
    3) msg="POST /carts/$((100 + i)) 200 12ms" ;;
    4) msg="GET /banner?tpl=Hello 200 3ms" ;;
    *) msg="GET /health 200 1ms" ;;
  esac
  ts=$((now - (40 - i) * 90000))
  lines+=("$(printf '{"timestamp":%d,"message":"%s"}' "$ts" "$msg")")
done
lines+=("$(printf '{"timestamp":%d,"message":"%s"}' "$now" 'TypeError: Cannot read properties of undefined (reading \"total\") at renderBanner (src/banner.js:6)')")

events=$(IFS=,; echo "[${lines[*]}]")
aws logs put-log-events --log-group-name "$GROUP" --log-stream-name "$STREAM" \
  --log-events "$events" --region "$REGION" >/dev/null
echo "Wrote ${#lines[@]} lines to $GROUP/$STREAM"
