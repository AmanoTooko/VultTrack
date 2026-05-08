#!/bin/bash
# Full fetcher bootstrap - saves results to JSON
export PATH="/opt/homebrew/bin:$PATH"
export FETCHER_MAX_RECORDS=
export FETCHER_TIMEOUT_MS=600000

LOGDIR=/Volumes/NekoMac/Dev/VulTrack/data/logs
mkdir -p "$LOGDIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SUMMARY="$LOGDIR/fetch-summary-${TIMESTAMP}.json"

SOURCES=(osv cve-list-v5 nvd-cve nvd-cpe)

echo "[" > "$SUMMARY"
FIRST=true

for src in "${SOURCES[@]}"; do
  LOG="$LOGDIR/fetch-${src}-${TIMESTAMP}.log"
  echo "[$(date '+%H:%M:%S')] START $src" | tee "$LOG"
  node /Volumes/NekoMac/Dev/VulTrack/plugins/fetchers/run-fetcher.mjs --source "$src" >> "$LOG" 2>&1
  RC=$?
  echo "[$(date '+%H:%M:%S')] END $src (exit=$RC)" | tee -a "$LOG"
  $FIRST || echo "," >> "$SUMMARY"
  echo "  {\"source\":\"$src\",\"exit\":$RC,\"log\":\"$LOG\"}" >> "$SUMMARY"
  FIRST=false
done

echo "]" >> "$SUMMARY"
echo "[$(date '+%H:%M:%S')] ALL DONE" | tee -a "$LOGDIR/fetch-all-${TIMESTAMP}.log"
echo "Summary: $SUMMARY"
