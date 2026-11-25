#!/usr/bin/env bash
# c-mutate.sh <name> <source file> <swift test filter regexp>: hand-mutation gate for one C/C++ source of ours (swift-mutate mutates only
# Swift). Each mutant of c-mutants/<name>.mutants.json (a literal substring replacement in one line; "nth" picks the n-th identical line,
# default: the line must occur exactly once) is applied to the source in place, the package is rebuilt (incrementally: only the C target
# and what links it) and the filtered test classes run; the original is restored after every mutant. killed = a test failed; survived
# fails the gate unless c-mutants/<name>.ledger.json lists it (a proven equivalent); build-failed, crash and timeout always fail; a
# ledger entry for a killed or unknown mutant is stale and fails too. "applicable": false (needs a reason) lists a mutant of a branch
# this platform never compiles. The unmutated baseline must pass first and run tests. Run in the package root, with the module's native
# libraries and ATLAS_PCA_* switch already in the environment.
# Env: SKIP_FILTER (a swift test --skip regexp: tests that compare the mutated file with a canonical copy would kill every mutant), SLICE_OF/SLICE_OFF (run every OF-th mutant from OFF, the matrix split), MUTANT_TIMEOUT (seconds, build included, default 1200).
set -euo pipefail
# macOS has no timeout(1): the same call (-k <grace> <seconds> <cmd...>; 124 on expiry) through python3, which every runner has
if ! command -v timeout > /dev/null; then
  timeout() {
    python3 -c 'import os, signal, subprocess, sys
g, t = int(sys.argv[2]), int(sys.argv[3])
p = subprocess.Popen(sys.argv[4:], start_new_session=True)
try:
    rc = p.wait(timeout=t)
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGTERM)
    try: p.wait(g)
    except subprocess.TimeoutExpired: os.killpg(p.pid, signal.SIGKILL); p.wait()
    sys.exit(124)
sys.exit(rc if rc >= 0 else 128 - rc)' "$@"
  }
fi
NAME="${1:?name}"; SRC="${2:?source}"; FILTER="${3:?filter}"
LIST="c-mutants/$NAME.mutants.json"; LEDGER="c-mutants/$NAME.ledger.json"
OF="${SLICE_OF:-1}"; OFF="${SLICE_OFF:-0}"; TMO="${MUTANT_TIMEOUT:-1200}"
OUT="$(mktemp -d)"; ORIG="$OUT/original"; cp "$SRC" "$ORIG"
trap 'cp "$ORIG" "$SRC"; rm -rf "$OUT"' EXIT
export LIST SRC

python3 - "$LIST" "$LEDGER" "$SRC" "$OF" "$OFF" > "$OUT/plan.txt" <<'PY'
import json, sys
muts, led = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
of, off = int(sys.argv[4]), int(sys.argv[5])
src = open(sys.argv[3]).read().split("\n")
bad, ids = [], [m.get("id") for m in muts]
if len(set(ids)) != len(ids): bad.append("duplicate mutant ids")
for m in muts:
    i = m.get("id")
    # "to" may be empty: a deletion of the matched text is a mutant
    if any(not isinstance(m.get(k), str) or (k != "to" and not m[k]) for k in ("id", "line", "from", "to", "what")): bad.append(f"{i}: needs id, line, from, to, what"); continue
    n, c = m.get("nth", 0), src.count(m["line"])
    if (n == 0 and c != 1) or (n > 0 and c < n): bad.append(f"{i}: line occurs {c} times (nth {n or 'unset: must be unique'})")
    if m["line"].count(m["from"]) != 1: bad.append(f"{i}: 'from' occurs {m['line'].count(m['from'])} times in the line (want 1)")
    if m["from"] == m["to"]: bad.append(f"{i}: from == to")
    if m.get("applicable", True) is not True and not m.get("reason"): bad.append(f"{i}: not applicable without a reason")
lids = [e.get("id") for e in led]
if len(set(lids)) != len(lids): bad.append("duplicate ledger ids")
na = {m["id"] for m in muts if m.get("applicable", True) is not True}
for e in led:
    if set(e) != {"id", "reason"} or not e["reason"]: bad.append(f"ledger {e.get('id')}: needs exactly id and a reason")
    if e.get("id") not in ids: bad.append(f"ledger {e.get('id')}: stale (no such mutant)")
    if e.get("id") in na: bad.append(f"ledger {e.get('id')}: stale (not applicable, never run)")
if bad:
    for b in bad: print("::error::" + b, file=sys.stderr)
    sys.exit(1)
for k, m in enumerate(muts): print(m["id"], "na" if m["id"] in na else ("run" if k % of == off else "other"))
PY

# apply <id>: replace in the n-th occurrence of the line
apply_mutant() {
  python3 - "$LIST" "$1" "$SRC" <<'PY'
import json, sys
m = next(x for x in json.load(open(sys.argv[1])) if x["id"] == sys.argv[2])
lines = open(sys.argv[3]).read().split("\n")
at = [i for i, l in enumerate(lines) if l == m["line"]][(m.get("nth", 1)) - 1]
lines[at] = lines[at].replace(m["from"], m["to"])
open(sys.argv[3], "w").write("\n".join(lines))
PY
}

# run_one <id|baseline> -> $OUT/<id>.status
run_one() {
  local id="$1" log="$OUT/$1.log" rc=0 st
  cp "$ORIG" "$SRC"
  if [ "$id" != baseline ]; then
    apply_mutant "$id" >"$log" 2>&1 || { echo apply-failed >"$OUT/$id.status"; return 0; }
    if cmp -s "$ORIG" "$SRC"; then echo apply-failed >"$OUT/$id.status"; return 0; fi
  fi
  timeout -k 10 "$TMO" swift test --filter "$FILTER" ${SKIP_FILTER:+--skip "$SKIP_FILTER"} >>"$log" 2>&1 || rc=$?
  cp "$ORIG" "$SRC"
  if [ "$rc" = 0 ]; then st=survived
  elif grep -Eq "Test Case .* failed|error: -\[|✘ Test|with [1-9][0-9]* failure" "$log"; then st=killed
  elif [ "$rc" = 124 ] || [ "$rc" = 137 ]; then st=timeout
  elif grep -Eq "error: .*\.(c|cpp|h):[0-9]+:[0-9]+|error: fatalError|error: build had [0-9]+ command failures|error: compilation" "$log"; then st=build-failed
  else st=crash; fi
  echo "$st" >"$OUT/$id.status"; echo "$NAME $id: $st"
}

echo "baseline (unmutated)"
run_one baseline >/dev/null
if [ "$(cat "$OUT/baseline.status")" != survived ] || ! grep -Eq "Executed [1-9][0-9]* tests?, with 0 failures" "$OUT/baseline.log"; then
  tail -60 "$OUT/baseline.log"; echo "::error::the unmutated baseline must pass and execute tests"; exit 1
fi
# a mutant that survives with every test skipped is no oracle: the filter must run at least one test and none may be skipped for a missing library
if grep -aEq "skipped|XCTSkip" "$OUT/baseline.log"; then echo "::warning::the baseline skipped tests (missing native library or corpus?)"; grep -aE "skipped|XCTSkip" "$OUT/baseline.log" | head -5 || true; fi

for id in $(awk '$2 == "run" { print $1 }' "$OUT/plan.txt"); do run_one "$id"; done

python3 - "$LIST" "$LEDGER" "$OUT" "$OF" "$OFF" <<'PY'
import json, os, sys
muts, led = json.load(open(sys.argv[1])), {e["id"]: e for e in json.load(open(sys.argv[2]))}
out, of, off = sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
counts, fail = {}, []
for k, m in enumerate(muts):
    i = m["id"]
    if k % of != off and m.get("applicable", True) is True: continue  # another slice's mutant (and its ledger entry)
    if m.get("applicable", True) is not True: st = "not-applicable"
    else:
        p = os.path.join(out, i + ".status"); st = open(p).read().strip() if os.path.exists(p) else "not-run"
    counts[st] = counts.get(st, 0) + 1
    if st in ("killed", "not-applicable"):
        if i in led: fail.append(f"{i}: stale ledger entry ({st})")
    elif i in led and st != "survived": fail.append(f"{i}: ledgered as equivalent but {st} (an equivalent runs clean)")
    elif i not in led:
        fail.append(f"{i}: {st}, not in the ledger ({m['what']})")
        log = os.path.join(out, i + ".log")
        if st != "survived" and os.path.exists(log): print(f"--- {i} log tail:\n" + "".join(open(log).readlines()[-25:]))
print(f"c mutants {sys.argv[1]}: slice {off + 1}/{of}; " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + f"; ledgered {len(led)}")
for f in fail: print("::error::" + f)
sys.exit(1 if fail else 0)
PY
