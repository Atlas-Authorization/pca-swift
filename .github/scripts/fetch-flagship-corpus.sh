#!/usr/bin/env bash
# fetch-flagship-corpus.sh [--layout]
# This repo vendors only the curated core corpus (conformance/vectors.json). The full adversarial set and the
# mutation-oracle inputs live in the flagship repo (Atlas-Authorization/pca). Fetch them from the flagship at the SAME
# ref as this run (a ci/** branch or tag pushed together with this repo, or main), waiting up to 20 min for the ref:
#   conformance/vectors-adversarial.json.gz   always
#   packages/pca/conformance/, tools/pca-audit/   with --layout (suites that locate the corpus by the flagship's layout)
set -euo pipefail
REF="${PCA_FLAGSHIP_REF:-${GITHUB_REF_NAME:-main}}"
URL="https://github.com/${GITHUB_REPOSITORY_OWNER:-Atlas-Authorization}/pca.git"
DEST="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pca-flagship"
for i in $(seq 1 40); do
  git ls-remote --exit-code "$URL" "refs/heads/$REF" "refs/tags/$REF" >/dev/null 2>&1 && break
  [ "$i" = 40 ] && { echo "::error::the flagship repo has no ref '$REF' (push it at the same ref)"; exit 1; }
  echo "waiting for the flagship ref '$REF' ($i/40)"; sleep 30
done
rm -rf "$DEST"
git clone -q --depth 1 --filter=blob:none --sparse --branch "$REF" "$URL" "$DEST"
git -C "$DEST" sparse-checkout set conformance packages/pca/conformance tools/pca-audit
echo "flagship $REF @ $(git -C "$DEST" rev-parse HEAD)"
cp "$DEST/conformance/vectors-adversarial.json.gz" conformance/
if [ "${1:-}" = --layout ]; then
  mkdir -p packages/pca tools
  rm -rf packages/pca/conformance tools/pca-audit
  cp -R "$DEST/packages/pca/conformance" packages/pca/
  cp -R "$DEST/tools/pca-audit" tools/
fi
