#!/usr/bin/env bash
# Verify the preloaded isotope set: signature, pin, lock, and that it says what
# the cluster actually is.
#
#   scripts/isotopes-verify.sh
#
# The set is generated *from* cluster/skills.json, not maintained beside it, so
# this checks coverage in both directions: every skill the inventory carries is
# claimed by some isotope, and no isotope claims a skill the inventory does not
# have. Positions are checked against the isotope library (cmd/isotope42), because
# a rung is a claim about accumulated distance and the library already knows the
# mapping.
set -euo pipefail
cd "$(dirname "$0")/.."

set_file="isotopes/zaphod-base.json"
skills_file="cluster/skills.json"

scripts/verify-artifact.sh "$set_file" zaphod-isotopes

pin="$(awk '{print $2}' keys/FINGERPRINT)"
[ "$(jq -r .issued_by "$set_file")" = "zaphod-beeblebrox" ] || { echo "wrong issuer" >&2; exit 1; }
[ "$(jq -r .issued_by_fingerprint "$set_file")" = "$pin" ] ||
  { echo "the set is issued by a key that is not the pinned one" >&2; exit 1; }

expires="$(jq -r .expires "$set_file")"
expiry_epoch="$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$expires" +%s 2>/dev/null ||
  date -u -d "$expires" +%s 2>/dev/null || echo 0)"
if [ "$expiry_epoch" -le "$(date +%s)" ]; then
  echo "the preloaded set expired at $expires" >&2
  exit 1
fi

# Coverage, both directions.
inventory="$(jq -r '.skills[].name' "$skills_file" | sort)"
claimed="$(jq -r '.isotopes[].skills[]' "$set_file" | sort -u)"
if [ "$inventory" != "$claimed" ]; then
  echo "the isotope set and the skill inventory disagree:" >&2
  diff <(printf '%s\n' "$inventory") <(printf '%s\n' "$claimed") >&2 || true
  exit 1
fi

# Positions and rungs, by the library's own arithmetic.
if ! command -v go >/dev/null 2>&1; then
  echo "warning: go is not installed; positions unchecked (CI checks them)" >&2
else
  go run ./cmd/isotope42 check "$set_file"
fi

echo "isotopes ok: $(jq '.isotopes | length' "$set_file") isotope(s), $(printf '%s\n' "$inventory" | wc -l | tr -d ' ') skill(s), issued by $pin"
