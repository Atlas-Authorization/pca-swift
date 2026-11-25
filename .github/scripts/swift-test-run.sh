#!/usr/bin/env bash
# swift-test-run.sh <filter-regex> [limit-minutes]
# `swift test --filter <regex>` with live output and a watchdog, so a hang names itself instead of burning the job timeout:
#  * output is line-buffered (a pty through script(1) on macOS, stdbuf on Linux, NSUnbufferedIO for Foundation's own writes), so the log always shows the
#    test that is running;
#  * when one test case has been running longer than <limit-minutes> (default 25: the slowest corpus replay measured 10 minutes in a debug build) the
#    watchdog prints that test, the last output lines and every thread's stack of the test process, kills the run and exits 1.
set -uo pipefail
FILTER="${1:?filter regex}"
LIMIT=$(( ${2:-25} * 60 ))
LOG="$(mktemp)"
export NSUnbufferedIO=YES
# The default is the one debug build the job already made. A shard whose tests are big-integer or statistics loops (the VDF replay, the intent-stats replay) passes
# SWIFT_TEST_FLAGS="-Xswiftc -O": it rebuilds those modules (BigInt included, a dependency whose flags only the command line reaches) optimised, without the
# whole-module release build that cost 25 minutes in round 25. `-enable-testing` stays on (debug), so `@testable import` keeps working.
FLAGS="${SWIFT_TEST_FLAGS:-}"
if [ -n "$FLAGS" ]; then
  # build first, then prove from SwiftPM's build manifest that -O reached the BigInt dependency (the last optimisation flag of its compile command wins)
  swift build --build-tests $FLAGS || exit 1
  python3 - <<'PY'
import glob, re, sys
files = glob.glob(".build/*/debug.yaml") + glob.glob(".build/debug.yaml")
if not files:
    print("::warning::-O proof: no .build debug.yaml manifest found"); sys.exit(0)
opt = re.compile(r"-O(none|size|unchecked)?$")
shown = False
for f in files:
    t = open(f, errors="ignore").read()
    for mod in ("BigInt", "AtlasPCAVDF"):
        m = re.search(r'"-module-name",\s*"' + mod + '"', t)
        if not m:
            continue
        a = t.rfind("[", 0, m.start()); b = t.find("]", m.end())
        toks = re.findall(r'"((?:[^"\\]|\\.)*)"', t[a:b])
        flags = [x for x in toks if opt.match(x)]
        shown = True
        print(f"-O proof: {mod} compiled with optimisation flags {flags}, effective {flags[-1] if flags else '(none)'}")
        if flags and flags[-1] == "-Onone":
            print(f"::error::-O did not reach {mod}: the last optimisation flag is -Onone"); sys.exit(1)
if not shown:
    print("::warning::-O proof: no BigInt compile command found in the build manifest")
PY
  [ $? -eq 0 ] || exit 1
fi
if [ "$(uname -s)" = "Darwin" ]; then
  script -q /dev/null swift test $FLAGS --filter "$FILTER" > "$LOG" 2>&1 &
elif command -v stdbuf >/dev/null 2>&1; then
  stdbuf -oL -eL swift test $FLAGS --filter "$FILTER" > "$LOG" 2>&1 &
else
  swift test $FLAGS --filter "$FILTER" > "$LOG" 2>&1 &
fi
RUN=$!
tail -n +1 -f "$LOG" &
TAIL=$!
cleanup() { kill "$TAIL" 2>/dev/null; }
trap cleanup EXIT

running_test() { # the last case that started and has no later pass/fail line
  tr -d '\r' < "$LOG" | awk '
    /Test Case .* started/ { cur = $0; next }
    /Test Case .* (passed|failed)/ { cur = "" }
    END { print cur }'
}

dump_stacks() {
  for pid in $(pgrep -f 'xctest' 2>/dev/null); do
    echo "---- threads of pid $pid ($(ps -o command= -p "$pid" 2>/dev/null | cut -c1-120))"
    if [ "$(uname -s)" = "Darwin" ]; then
      sample "$pid" 3 -file /dev/stdout 2>&1 | head -400
    elif command -v gdb >/dev/null 2>&1; then
      gdb -p "$pid" -batch -ex 'thread apply all bt 30' 2>&1 | head -400
    else
      for t in /proc/"$pid"/task/*; do echo "thread ${t##*/}: $(cut -d' ' -f2,3 "$t/stat" 2>/dev/null) wchan=$(cat "$t/wchan" 2>/dev/null)"; done
    fi
  done
}

last="" ; since=$(date +%s)
while kill -0 "$RUN" 2>/dev/null; do
  sleep 15
  now=$(date +%s); cur="$(running_test)"
  if [ "$cur" != "$last" ]; then last="$cur"; since=$now; fi
  if [ -n "$cur" ] && [ $(( now - since )) -gt "$LIMIT" ]; then
    echo "::error::watchdog: this test case has run for more than $(( LIMIT / 60 )) minutes: $cur"
    echo "---- last output"; tr -d '\r' < "$LOG" | tail -n 25
    dump_stacks
    pkill -9 -f 'xctest' 2>/dev/null; kill -9 "$RUN" 2>/dev/null
    exit 1
  fi
done
wait "$RUN"; rc=$?
sleep 2 # let the tail drain the last lines
exit "$rc"
