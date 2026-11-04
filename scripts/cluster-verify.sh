#!/usr/bin/env bash
# Verify the cluster's certificate and skill inventory, and that they agree.
#
#   scripts/cluster-verify.sh
#
# The rotation chain, the signatures and the allowed version are checked by the
# scripts this calls. What is checked here is the meaning: whose certificate it is,
# what it is allowed to do, whether the skills claim rungs the certificate backs,
# and whether the preloaded isotope set says the same thing.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib-receipt.sh

cert="cluster/certificate.json"
skills="cluster/skills.json"

scripts/rotation-verify.sh
scripts/verify-artifact.sh "$cert" zaphod-certificate
scripts/verify-artifact.sh "$skills" zaphod-skills

pin="$(awk '{print $2}' keys/FINGERPRINT)"
issuer="$(jq -r .issuer "$cert")"
cluster="$(jq -r .cluster "$cert")"
# The clock is an input like any other: ZAPHOD_NOW pins it for a verifier or a
# test, and every window in this script reads the same instant.
now="${ZAPHOD_NOW:-$(date +%s)}"

[ "$issuer" = "zaphod-beeblebrox" ] || { echo "wrong issuer: $issuer" >&2; exit 1; }
[ "$(jq -r .subject_fingerprint "$cert")" = "$pin" ] ||
  { echo "certificate does not belong to the pinned identity" >&2; exit 1; }
not_after="$(jq -r .not_after "$cert")"
[ "$not_after" -gt "$now" ] || { echo "certificate expired at $not_after" >&2; exit 1; }
for scope in attest registry; do
  jq -e --arg s "$scope" '.scope | index($s)' "$cert" >/dev/null ||
    { echo "certificate is missing scope $scope" >&2; exit 1; }
done

[ "$(jq -r .cluster "$skills")" = "$cluster" ] ||
  { echo "skills belong to $(jq -r .cluster "$skills"), certificate to $cluster" >&2; exit 1; }
[ "$(jq -r .issuer "$skills")" = "$issuer" ] ||
  { echo "skills certified by $(jq -r .issuer "$skills"), certificate issued by $issuer" >&2; exit 1; }

if ! jq -e 'all(.skills[]; (.rung | type == "number") and .rung >= 0 and .rung <= 3 and
  (.hops | type == "number") and .hops >= 0 and
  (.name | startswith("zaphod/")) and (.certified_by == "zaphod-beeblebrox"))' "$skills" >/dev/null; then
  echo "skill inventory has an entry outside the model (0<=rung<=3, hops>=0, zaphod/ prefix, pinned certifier)" >&2
  exit 1
fi

# A dynamic skill is a pre-negotiated rotation: it declares, before it runs, whether
# it transforms inputs or promises never to do something. A skill with no declared
# contract has not been negotiated, so it cannot be certified — and one that tries to
# be both an operation and a prohibition is refused for the same reason.
if ! jq -e 'all(.skills[];
      (.contract | type == "object") and
      ((.contract.kind == "transforms" and (.contract.inputs | length) > 0 and (.contract.outputs | length) > 0)
       or (.contract.kind == "never" and (.contract.never | type == "string") and (.contract.never | length) > 0)))' \
     "$skills" >/dev/null; then
  echo "a skill has no negotiated contract (transforms with inputs and outputs, or never with a promise)" >&2
  exit 1
fi
jq -r '.skills[] | if .contract.kind == "transforms"
  then "  contract  \(.name): transforms \(.contract.inputs | join(",")) -> \(.contract.outputs | join(","))"
  else "  contract  \(.name): never \(.contract.never)" end' "$skills"

printf 'claims ok: %s, scope %s, expires %s\n' \
  "$cluster" "$(jq -r '.scope|join(",")' "$cert")" \
  "$(date -u -d "@$not_after" +%FT%TZ 2>/dev/null || date -u -r "$not_after" +%FT%TZ 2>/dev/null || echo "$not_after")"
jq -r '.skills[] | "  rung \(.rung)  hops \(.hops)  \(.name)  — \(.evidence)"' "$skills"

# Honesty about what "eventually" means here: rung 3 needs an isotope binding
# from a smoke-alarm, and this cluster has none yet. Say so rather than imply a
# certification the inventory does not claim.
# The announcement must be signed and monotonic. Whether it *covers* the publication is
# the cluster gate's question, not the publisher's: while a rotation is being announced
# the publication legitimately runs one step ahead of its announcement.
scripts/verify-artifact.sh cluster/announcements.json zaphod-announcement
jq -e '(.announcements | length) > 0' cluster/announcements.json >/dev/null ||
  { echo "no announcements" >&2; exit 1; }
if ! jq -e '[.announcements[].seq] == ([.announcements[].seq] | sort) and
            ([.announcements[].seq] | length) == ([.announcements[].seq] | unique | length)' \
     cluster/announcements.json >/dev/null; then
  echo "announcements are not a monotonic sequence" >&2
  exit 1
fi
scripts/isotopes-verify.sh

if ! jq -e 'any(.skills[]; .rung >= 3)' "$skills" >/dev/null; then
  echo "note: no skill is at rung 3 — isotope certification needs a smoke-alarm this cluster does not run yet"
fi
