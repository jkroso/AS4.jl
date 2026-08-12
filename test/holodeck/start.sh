#!/bin/sh
# Start Holodeck B2B (AS4 peer for AS4.jl tests).
set -e
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk}"
export PATH="$JAVA_HOME/bin:/opt/homebrew/bin:$PATH"
ROOT="$(cd "$(dirname "$0")" && pwd)"
HB2B="$ROOT/hb2b"
PIDFILE="$ROOT/holodeck.pid"
LOG="$ROOT/holodeck.log"

if [ ! -x "$JAVA_HOME/bin/java" ]; then
  echo "JAVA_HOME=$JAVA_HOME has no java; install OpenJDK (brew install openjdk)." >&2
  exit 1
fi
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "Holodeck already running (pid $(cat "$PIDFILE"))."
  exit 0
fi

cd "$HB2B"
# background; write pid
nohup "$HB2B/bin/startServer.sh" >"$LOG" 2>&1 &
echo $! >"$PIDFILE"
echo "Starting Holodeck (pid $(cat "$PIDFILE")), log: $LOG"
# wait for HTTP
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if curl -sf -o /dev/null "http://127.0.0.1:8080/holodeckb2b/as4" 2>/dev/null \
     || curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/" 2>/dev/null | grep -qE '200|302|404|405|500'; then
    # AS4 endpoint may 405/500 on GET — any HTTP response means listener is up
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/holodeckb2b/as4" || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      echo "Holodeck listening on :8080 (AS4 endpoint HTTP $code)"
      exit 0
    fi
  fi
  sleep 1
done
echo "Timed out waiting for Holodeck on :8080 — see $LOG" >&2
exit 1
