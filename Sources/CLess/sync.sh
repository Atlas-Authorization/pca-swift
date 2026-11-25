#!/usr/bin/env bash
# Sources/CLess is a copy of the canonical LESS C (sdks/pca-less-c) laid out for SwiftPM: atlas_less.c, include/atlas_less.h (public), ref/*.h (the
# reference headers, kept out of the public include directory), lib/*.c. The copy keeps the package buildable on its own. `./sync.sh` refreshes it;
# `./sync.sh --check` reports drift (exit 1).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/../../../pca-less-c"
pairs=("atlas_less.c:atlas_less.c" "atlas_less.h:include/atlas_less.h" "LICENSE:LICENSE")
for f in "$src"/include/*.h; do pairs+=("include/$(basename "$f"):ref/$(basename "$f")"); done
for f in "$src"/lib/*.c; do pairs+=("lib/$(basename "$f"):lib/$(basename "$f")"); done
drift=0
for p in "${pairs[@]}"; do
  from="$src/${p%%:*}"; to="$here/${p##*:}"
  if [ "${1:-}" = --check ]; then cmp -s "$from" "$to" || { echo "drift: ${p##*:}"; drift=1; }
  else mkdir -p "$(dirname "$to")"; cp "$from" "$to"; fi
done
exit $drift
