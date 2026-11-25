#!/usr/bin/env bash
# vendor-natives.sh <blst|seal|all|verify> (run in the swift package directory or the repository root): fetches the pinned upstream sources of the package's bundled native
# pieces into Sources/, trimmed to what the build compiles, with the licenses kept, and records SHA-256s in Sources/vendored.sha256.
#   blst  supranational/blst v0.3.16 (commit-pinned): src, build, public headers          -> Sources/CBlst/blst, Sources/CBlst/include
#   seal  Microsoft SEAL v4.1.2 (+ its C export API) with the zlib 1.2.13, zstd 1.5.2 and GSL 4.0.0 it pins; all commit-pinned -> Sources/CSealC/vendor
#   verify  checks the tree against Sources/vendored.sha256 (exit 1 on drift or a missing file)
# SEAL's config.h is rendered here from the upstream template with a fixed portable feature set (no CPU intrinsics, so one tree builds on x86-64 and arm64).
# Needs git, sed and shasum or sha256sum.
set -euo pipefail
[ -f Package.swift ] || { cd "$(git rev-parse --show-toplevel)"; [ -f Package.swift ] || cd sdks/swift-pca; }
BLST_TAG=v0.3.16; BLST_COMMIT=e7f90de551e8df682f3cc99067d204d8b90d27ad
# SEAL 4.1.2 builds its dependencies from these exact commits (its cmake/ExternalZLIB.cmake, ExternalZSTD.cmake, ExternalMSGSL.cmake), so the vendored ones are the same
SEAL_TAG=v4.1.2; SEAL_COMMIT=119dc32e135cb89c1062076a69310d4413ebc824
ZLIB_TAG=v1.2.13; ZLIB_COMMIT=04f42ceca40f73e2978b50e93806c2a18c1281fc
ZSTD_TAG=v1.5.2; ZSTD_COMMIT=e47e674cd09583ff0503f0f6defd6d23d8b718d3
GSL_TAG=v4.0.0; GSL_COMMIT=a3534567187d2edc428efd3f13466ff75fe5805c
LOCK=Sources/vendored.sha256
sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
clone() { git clone --quiet --depth 1 --branch "$2" "$1" "$4"; test "$(git -C "$4" rev-parse HEAD)" = "$3" || { echo "$1 $2 is not commit $3" >&2; exit 1; }; }

blst() {
  clone https://github.com/supranational/blst "$BLST_TAG" "$BLST_COMMIT" "$tmp/blst"
  rm -rf Sources/CBlst/blst; mkdir -p Sources/CBlst/blst Sources/CBlst/include
  cp -R "$tmp/blst/src" "$tmp/blst/build" "$tmp/blst/LICENSE" Sources/CBlst/blst/
  cp "$tmp/blst/bindings/blst.h" "$tmp/blst/bindings/blst_aux.h" Sources/CBlst/include/
  test -s Sources/CBlst/blst/src/server.c
}

seal() {
  local v=Sources/CSealC/vendor
  clone https://github.com/microsoft/SEAL "$SEAL_TAG" "$SEAL_COMMIT" "$tmp/seal"
  clone https://github.com/madler/zlib "$ZLIB_TAG" "$ZLIB_COMMIT" "$tmp/zlib"
  clone https://github.com/facebook/zstd "$ZSTD_TAG" "$ZSTD_COMMIT" "$tmp/zstd"
  clone https://github.com/microsoft/GSL "$GSL_TAG" "$GSL_COMMIT" "$tmp/gsl"
  rm -rf "$v"; mkdir -p "$v/seal/seal" "$v/zlib" "$v/zstd" "$v/gsl" "$v/LICENSES"
  # SEAL: library sources and headers (the blake2b/blake2xb/fips202 C files are part of it) (the C export API is native/src/seal/c)
  ( cd "$tmp/seal/native/src" && find seal \( -name '*.cpp' -o -name '*.h' -o -name '*.c' \) | while read -r f; do mkdir -p "$OLDPWD/$v/seal/$(dirname "$f")"; cp "$f" "$OLDPWD/$v/seal/$f"; done )
  # config.h: the upstream template with a fixed feature set; any option the template has that is not decided below stops the run so it is decided explicitly
  local on="SEAL_USE_STD_BYTE SEAL_USE_SHARED_MUTEX SEAL_USE_IF_CONSTEXPR SEAL_USE_MAYBE_UNUSED SEAL_USE_NODISCARD SEAL_USE_STD_FOR_EACH_N SEAL_USE_MSGSL SEAL_USE_ZLIB SEAL_USE_ZSTD SEAL_USE_ALIGNED_ALLOC SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT SEAL_USE___BUILTIN_CLZLL SEAL_USE___INT128"
  local off="SEAL_DEBUG SEAL_USE_INTEL_HEXL SEAL_USE_INTRIN SEAL_USE__ADDCARRY_U64 SEAL_USE__SUBBORROW_U64 SEAL_USE__UMUL128 SEAL_USE_GAUSSIAN_NOISE SEAL_AVOID_BRANCHING SEAL_USE_EXPLICIT_BZERO SEAL_USE_EXPLICIT_MEMSET SEAL_USE_MEMSET_S SEAL_USE__BITSCANREVERSE64"
  local tpl="$tmp/seal/native/src/seal/util/config.h.in" out="$v/seal/seal/util/config.h" name
  cp "$tpl" "$out"
  sed -i.bak "s|#cmakedefine SEAL_DEFAULT_PRNG @SEAL_DEFAULT_PRNG@|#define SEAL_DEFAULT_PRNG Blake2xb|" "$out"
  for name in $(grep -o '#cmakedefine[01]* *[A-Z0-9_]*' "$tpl" | awk '{print $2}' | grep -vx SEAL_DEFAULT_PRNG | sort -u); do
    if [[ " $on " == *" $name "* ]]; then sed -i.bak -E "s|#cmakedefine +$name( .*)?$|#define $name\1|; s|#cmakedefine01 +$name|#define $name 1|" "$out"
    elif [[ " $off " == *" $name "* ]]; then sed -i.bak -E "s|#cmakedefine +$name( .*)?$|/* #undef $name */|; s|#cmakedefine01 +$name|#define $name 0|" "$out"
    else echo "config.h option not decided: $name" >&2; exit 1; fi
  done
  IFS=. read -r maj min pat <<<"${SEAL_TAG#v}"
  sed -i.bak "s|@SEAL_VERSION@|${SEAL_TAG#v}|g; s|@SEAL_VERSION_MAJOR@|$maj|g; s|@SEAL_VERSION_MINOR@|$min|g; s|@SEAL_VERSION_PATCH@|$pat|g" "$out"
  rm -f "$out.bak"; ! grep -q '@[A-Za-z_]*@\|#cmakedefine' "$out" || { echo "config.h not fully rendered" >&2; exit 1; }
  # zlib (C sources and headers), zstd (common, compress, decompress; no assembly), GSL (headers only)
  cp "$tmp"/zlib/*.c "$tmp"/zlib/*.h "$v/zlib/"; rm -f "$v/zlib/gzclose.c.orig"
  for d in common compress decompress; do mkdir -p "$v/zstd/$d"; cp "$tmp"/zstd/lib/$d/*.c "$tmp"/zstd/lib/$d/*.h "$v/zstd/$d/"; done
  cp "$tmp/zstd/lib/zstd.h" "$tmp/zstd/lib/zstd_errors.h" "$v/zstd/"
  cp -R "$tmp/gsl/include/gsl" "$v/gsl/gsl"
  cp "$tmp/seal/LICENSE" "$v/LICENSES/SEAL.txt"; cp "$tmp/zlib/LICENSE" "$v/LICENSES/zlib.txt" 2>/dev/null || cp "$tmp/zlib/README" "$v/LICENSES/zlib.txt"
  cp "$tmp/zstd/LICENSE" "$v/LICENSES/zstd.txt"; cp "$tmp/gsl/LICENSE" "$v/LICENSES/GSL.txt"
  test -s "$v/seal/seal/c/evaluator.cpp"
}

record() { { { find Sources/CBlst/blst Sources/CBlst/include/blst.h Sources/CBlst/include/blst_aux.h Sources/CSealC/vendor -type f 2>/dev/null || true; } | LC_ALL=C sort | while read -r f; do sum "$f"; done; } > "$LOCK"; }

case "${1:-}" in
  blst) blst; record ;;
  seal) seal; record ;;
  all) blst; seal; record ;;
  verify) sum -c "$LOCK" >/dev/null ;;
  *) echo "usage: $0 blst|seal|all|verify" >&2; exit 2 ;;
esac
