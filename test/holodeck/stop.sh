#!/bin/sh
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="$ROOT/holodeck.pid"
if [ -f "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE")
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    # Holodeck's startServer may spawn children; kill by port if needed
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
    echo "Stopped Holodeck (pid $pid)."
  else
    echo "Stale pid file (not running)."
  fi
  rm -f "$PIDFILE"
else
  # fallback: anything on 8080 that looks like holodeck
  pids=$(lsof -tiTCP:8080 -sTCP:LISTEN 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "Killing listener(s) on :8080: $pids"
    kill $pids 2>/dev/null || true
  else
    echo "Holodeck not running."
  fi
fi
