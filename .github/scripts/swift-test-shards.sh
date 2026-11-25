#!/usr/bin/env bash
# swift-test-shards.sh regex <shard> | guard | names
#   regex <shard>  prints the `swift test --filter` regex of one shard (the filter matches "Target.Class/test" ids from the start).
#   guard          reads `swift test list` on stdin and fails unless every listed test id matches exactly one shard.
#   names          prints the shard names (the CI matrix legs).
# One table below is the single source of the split: the workflow matrix, the filters and the guard all read it, so a new test class can never
# fall outside every shard (the guard fails) or into two (it fails too). Measured on run 45156615643 (debug build, per-class seconds):
# RefIntentCoreTests 585, VdfReplayTests (its own shard: CPU-bound big-integer loops), RefAnalyzerResidualTests 402, RefAnalyzerCoverageTests 391, the FROST and remaining analyzer classes ~640 together,
# the other Ref classes ~500, A-F ~380, the rest ~170 plus the other targets.
set -euo pipefail
V='AtlasPCAVerifyTests\.'
NAMES="core vdf residual coverage heavy ref ab rest"
# a function, not an associative array: the macOS runners' bash is 3.2
rx() {
  case "$1" in
    core) echo "^${V}RefIntentCoreTests/" ;;
    vdf|vdf-[0-9]*of[0-9]*) echo "^AtlasPCAVDFTests\\.VdfReplayTests/" ;; # the VDF replay is split by CASE (ATLAS_VDF_SHARD=i/N), a leg per slice
    residual) echo "^${V}RefAnalyzerResidualTests/" ;;
    coverage) echo "^${V}RefAnalyzerCoverageTests/" ;;
    heavy) echo "^${V}(RefFrost|RefAnalyzer(?!ResidualTests/|CoverageTests/))" ;;
    ref) echo "^${V}Ref(?!Frost|Analyzer|IntentCoreTests/)" ;;
    ab) echo "^${V}[A-F]" ;;
    rest) echo "^(?!${V}(Ref|[A-F])|AtlasPCAVDFTests\\.VdfReplayTests/)" ;;
    *) echo "unknown shard $1" >&2; return 2 ;;
  esac
}
case "${1:-}" in
  names) for n in $NAMES; do echo "$n"; done ;;
  # `env <shard>`: the environment a leg runs under (the VDF slices replay the FULL set of their cases, nothing skipped)
  env) case "${2:?shard}" in
         vdf-*of*) sh="${2#vdf-}"; echo "ATLAS_VDF_SHARD=${sh%of*}/${sh#*of} ATLAS_VDF_FULL=1" ;;
         *) echo "" ;;
       esac ;;
  # `matrix-guard <ci.yml> <corpus.json.gz>`: every `vdf-IofN` group in the workflow matrices is complete (0..N-1 once each) and its slices together cover every case
  # index of the corpus (counted from the corpus itself), so N and the matrix cannot drift apart
  matrix-guard)
    python3 - "${2:?ci.yml}" "${3:?corpus}" <<'PY'
import gzip, re, sys, collections
wf, corpus = sys.argv[1], sys.argv[2]
total = sum(1 for l in gzip.open(corpus, "rt", encoding="utf-8") if l.startswith('{"fn":"'))
if total == 0:
    sys.exit("::error::the VDF corpus holds no cases")
groups = collections.defaultdict(list)   # (line of the matrix list, N) -> slices
for m in re.finditer(r"^\s*shard:\s*\[([^\]]*)\]", open(wf).read(), re.M):
    for name in (x.strip() for x in m.group(1).split(",")):
        v = re.fullmatch(r"vdf-(\d+)of(\d+)", name)
        if v:
            groups[(m.start(), int(v.group(2)))].append(int(v.group(1)))
if not groups:
    sys.exit("::error::no vdf-IofN slices in the workflow matrix")
bad = 0
for (_, n), slices in groups.items():
    if sorted(slices) != list(range(n)):
        bad += 1
        print(f"::error::the vdf slices of N={n} are {sorted(slices)}, want 0..{n - 1} once each")
        continue
    covered = sum(len(range(i, total, n)) for i in slices)
    if covered != total:
        bad += 1
        print(f"::error::N={n}: the slices cover {covered} of {total} cases")
    else:
        print(f"vdf N={n}: {n} slices cover all {total} cases")
sys.exit(1 if bad else 0)
PY
    ;;
  regex) rx "${2:?shard}" ;;
  guard)
    for n in $NAMES; do printf '%s\t%s\n' "$n" "$(rx "$n")"; done > "${TMPDIR:-/tmp}/shards.tsv"
    # the program goes in a file: a heredoc on python3's stdin would replace the piped test list
    cat > "${TMPDIR:-/tmp}/shard-guard.py" <<'PY'
import re, sys
shards = [l.rstrip("\n").split("\t") for l in open(sys.argv[1])]
ids = [l.strip() for l in sys.stdin if "/" in l and "." in l.split("/")[0]]
if not ids:
    sys.exit("::error::swift test list printed no test ids")
bad = 0
for i in ids:
    hit = [n for n, rx in shards if re.search(rx, i)]
    if len(hit) != 1:
        bad += 1
        print(f"::error::{i} matches {len(hit)} shards {hit}")
print(f"{len(ids)} tests, {bad} not in exactly one shard")
sys.exit(1 if bad else 0)
PY
    python3 "${TMPDIR:-/tmp}/shard-guard.py" "${TMPDIR:-/tmp}/shards.tsv"
    ;;
  *) echo "usage: $0 names | regex <shard> | guard" >&2; exit 2 ;;
esac
