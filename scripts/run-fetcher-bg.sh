#!/bin/bash
# Background fetcher runner with logging
SOURCE=$1
LOGFILE=/Volumes/NekoMac/Dev/VulTrack/data/logs/fetcher-${SOURCE}-$(date +%H%M%S).log
mkdir -p "$(dirname "$LOGFILE")"
export PATH="/opt/homebrew/bin:$PATH"
echo "[$(date '+%H:%M:%S')] Starting $SOURCE..." | tee "$LOGFILE"
node /Volumes/NekoMac/Dev/VulTrack/plugins/fetchers/run-fetcher.mjs --source "$SOURCE" >> "$LOGFILE" 2>&1
echo "[$(date '+%H:%M:%S')] $SOURCE done (exit=$?)" | tee -a "$LOGFILE"
