#!/bin/sh
# restart_until_stall.sh -- restart the leaf ircd in a loop until the hub logs
# a TLS handshake timeout, to catch the intermittent inbound-'*' stall with the
# TLSDBG identity/FIONREAD lines in place.
#
# Run this on the LEAF host.  It (re)starts the leaf, waits out the autoconnect
# (~1 s after launch) plus the 5 s handshake deadline, then scans the HUB log
# for a new timeout.  Point HUBLOG at the hub's log; if the hub is another host,
# set HUBLOG to something like: ssh hub 'tail -n 0 -F /path/ircd.log' via a
# side pipe, or just run the loop and watch the hub log yourself.
#
# Adjust the five variables below for your setup, then: sh restart_until_stall.sh

# --- configure -------------------------------------------------------------
LEAF_START='./ircd'                          # command to start the leaf (it daemonizes)
LEAF_PIDFILE="${HOME}/lib/ircd.pid"          # leaf pid file (from PPATH), or ''
LEAF_MATCH='ircd'                            # pkill -f fallback if no pidfile
HUBLOG='/home/ircd/lib/ircd.log'             # hub log to scan
PATTERN='TLS handshake timed out'            # what a stall looks like in the log
MAXTRIES=300
WAIT=9                                       # 1 s autoconnect + 5 s deadline + slack
# ---------------------------------------------------------------------------

stop_leaf() {
  if [ -n "$LEAF_PIDFILE" ] && [ -f "$LEAF_PIDFILE" ]; then
    kill "$(cat "$LEAF_PIDFILE")" 2>/dev/null
  else
    pkill -f "$LEAF_MATCH" 2>/dev/null
  fi
  sleep 1
}

i=1
while [ "$i" -le "$MAXTRIES" ]; do
  stop_leaf
  # remember where the hub log ends so we only look at new lines
  if [ -f "$HUBLOG" ]; then
    mark=$(wc -l < "$HUBLOG")
  else
    mark=0
    echo "warning: HUBLOG '$HUBLOG' not found -- scan will be skipped" >&2
  fi

  $LEAF_START
  printf 'try %d: leaf restarted, waiting %ds for the handshake window...\n' "$i" "$WAIT"
  sleep "$WAIT"

  if [ -f "$HUBLOG" ] && tail -n "+$((mark + 1))" "$HUBLOG" | grep -q "$PATTERN"; then
    echo "=== STALL REPRODUCED on try $i ==="
    # dump the relevant hub lines: TLSDBG identity + the timeout snapshot/notice
    tail -n "+$((mark + 1))" "$HUBLOG" | grep -E 'TLSDBG|handshake TIMEOUT|handshake timed out'
    echo "--- match the rport above against the leaf's own TLSDBG log ---"
    exit 0
  fi
  i=$((i + 1))
done

echo "no stall reproduced in $MAXTRIES tries"
exit 1
