#!/usr/bin/env bash
# The canonical digest of each signed cluster artifact: the only allowed version.
#
#   scripts/allowed.sh          # print the lock
#   scripts/allowed.sh --write  # rewrite cluster/allowed.txt
#
# A signature says who wrote a file. This says *which* file is allowed. They are
# different questions, and with a burned key the difference is the whole guard:
# anybody can re-sign a widened certificate, so only the version can be refused.
#
# Updated by scripts/rotate.sh, in the same commit as its rotation record — never
# by hand.
set -euo pipefail
cd "$(dirname "$0")/.."

declare -a entries=(
  "certificate cluster/certificate.json"
  "skills cluster/skills.json"
  "isotopes isotopes/zaphod-base.json"
)

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@"; else sha256sum "$@"; fi
}

print_lock() {
  echo "# The only allowed version of each signed artifact, by canonical digest."
  echo "# Canonical is \`jq -S -c\`. Updated only by scripts/rotate.sh, with a rotation record."
  for entry in "${entries[@]}"; do
    name="${entry%% *}"
    path="${entry#* }"
    [ -f "$path" ] || continue
    digest="$(jq -S -c . "$path" | sha256 | awk '{print $1}')"
    printf '%s  %s\n' "$digest" "$name"
  done
}

if [ "${1:-}" = "--write" ]; then
  print_lock > cluster/allowed.txt
  echo "wrote cluster/allowed.txt"
else
  print_lock
fi
