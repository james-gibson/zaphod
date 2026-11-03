#!/usr/bin/env bash
# Sign a cluster artifact with the burned key.
#
#   scripts/sign-artifact.sh cluster/skills.json zaphod-skills
#
# The canonical form is `jq -S -c` of the file: sorted keys, compact, one trailing
# newline. That is what is signed, so reformatting the JSON does not break the
# signature and changing any value does.
set -euo pipefail
cd "$(dirname "$0")/.."

chmod 600 keys/id_ed25519 2>/dev/null || true

file="${1:-}"
namespace="${2:-}"
[ -n "$file" ] && [ -n "$namespace" ] || { echo "usage: $0 <json> <namespace>" >&2; exit 2; }
[ -f "$file" ] || { echo "no such file: $file" >&2; exit 1; }
jq -e . "$file" >/dev/null 2>&1 || { echo "$file is not JSON" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
jq -S -c . "$file" > "$tmp"
ssh-keygen -Y sign -f keys/id_ed25519 -n "$namespace" "$tmp" >/dev/null
cp "$tmp.sig" "$file.sig"
rm -f "$tmp.sig"
echo "signed: $file.sig (namespace $namespace, principal zaphod-beeblebrox)"
