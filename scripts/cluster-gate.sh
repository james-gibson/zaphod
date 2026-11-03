#!/usr/bin/env bash
# The cluster's own gate. Not the repository's.
#
#   scripts/cluster-gate.sh
#
# Everything in cluster/ and keys/ is a *publication*: a third party can check it,
# and an attacker with the repository can rewrite all of it — including the pin, the
# lock and every signature, because the signing key is burned and published. So the
# cluster cannot take the repository's word for what it last accepted. It keeps its
# own state, beside its identity secret, outside the repository:
#
#   <identity-dir>/state.json
#     { artifacts: {certificate: sha256, skills: sha256, isotopes: sha256},
#       receipt_head: <hex>, attested_at: <iso8601>, attestation: <hex> }
#
# Two different jobs, and they are complementary:
#
#   * security — refuse a publication this cluster never attested. That is the exit
#     code, and it is binary.
#   * noise    — say *what* diverged, and by how much, even for the parts that did
#     not trip the refusal. A layer that only refuses cannot tell you whether it
#     refused the right thing, and two publications that differ are a measurement
#     before they are an error.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib-receipt.sh

identity_file="${ZAPHOD_IDENTITY_FILE:-$HOME/.zaphod/identity.secret}"
state_file="${ZAPHOD_STATE_FILE:-$(dirname "$identity_file")/state.json}"
trail_file="${ZAPHOD_TRAIL_FILE:-$(dirname "$state_file")/trail.jsonl}"

fail() { echo "gate rejected: $*" >&2; exit 1; }

[ -f "$identity_file" ] ||
  fail "no identity secret at $identity_file — the cluster holds it; the repository cannot stand in for it"
[ -f "$state_file" ] ||
  fail "no cluster state at $state_file — this cluster has not attested anything yet"

sha256_hex() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'; else sha256sum | awk '{print $1}'; fi
}

# The state's own attestation: is this the state the cluster wrote? This is the last
# thing that cannot be reconstructed from the repository, so it is checked first and
# it fails closed.
canonical_state="$(jq -S -c 'del(.attestation)' "$state_file")"
want="$(printf '%s' "$(cat "$identity_file"):${canonical_state}:state" | sha256_hex)"
got="$(jq -r '.attestation // empty' "$state_file")"
[ -n "$got" ] || fail "cluster state carries no attestation"
[ "$got" = "$want" ] || fail "the cluster state is not the one this identity attested (not mathematically the same)"

digest() { jq -S -c . "$1" | sha256_hex; }
short() { printf '%s' "${1:0:12}"; }

# The trail: did this publication arrive by the known path? A credential proves what
# an actor holds, not how it behaves, and a stolen one is no different — so the gate
# asks what was done, in order, chained onto the trail this cluster is already on.
if [ ! -f "$trail_file" ]; then
  fail "no trail at $trail_file — this cluster does not know this path"
fi
prev="genesis"
expected_seq=0
while IFS= read -r line; do
  seq="$(jq -r .seq <<<"$line")"
  [ "$seq" = "$expected_seq" ] ||
    fail "the trail skips from $expected_seq to $seq — this is not the trail I am on"
  [ "$(jq -r .prev <<<"$line")" = "$prev" ] ||
    fail "the trail forks at $seq — this is not the trail I am on"
  body="$(jq -S -c 'del(.attestation) | del(.hash)' <<<"$line")"
  want_mac="$(printf '%s' "$(cat "$identity_file"):${body}:trail" | sha256_hex)"
  [ "$(jq -r .attestation <<<"$line")" = "$want_mac" ] ||
    fail "trail entry $seq is not attested by this identity"
  prev="$(printf '%s' "$(jq -S -c --arg m "$want_mac" '. + {attestation: $m}' <<<"$body")" | sha256_hex)"
  expected_seq=$((expected_seq + 1))
done < "$trail_file"

# The nonce: was this entry issued by this cluster, or recomputed from the transcript?
# The publication is public and a timestamp to the second is not a secret, so without
# this an actor holding the secret reproduces the trail exactly — and that is not a
# forgery any gate could see. The nonce lives only in the cluster's state.
state_nonce="$(jq -r '.trail_nonce // empty' "$state_file")"
[ -n "$state_nonce" ] || fail "cluster state does not record a trail nonce"
last_nonce="$(tail -1 "$trail_file" | jq -r '.nonce // empty')"
[ "$last_nonce" = "$state_nonce" ] ||
  fail "the trail was not walked by this cluster (nonce ${last_nonce:-absent} is not ${state_nonce:0:12}…)"


state_head="$(jq -r '.receipt_head // empty' "$state_file")"
trail_head="$(tail -1 "$trail_file" | jq -r .hash)"
state_artifacts="$(jq -S -c '.artifacts' "$state_file" | sha256_hex)"
# The trail head the cluster is on. A stolen secret can produce valid arithmetic on
# a fresh trail; it cannot produce *this* trail without having walked it.
state_trail_head="$(jq -r '.trail_head // empty' "$state_file")"
[ -n "$state_trail_head" ] || fail "cluster state does not record a trail head"
[ "$trail_head" = "$state_trail_head" ] ||
  fail "the trail ends at ${trail_head:0:12}…, but this cluster is on ${state_trail_head:0:12}… — not the trail I am on"
trail_publication="$(tail -1 "$trail_file" | jq -r .publication)"
[ "$trail_publication" = "$state_artifacts" ] ||
  fail "the trail ends at a different publication than the state names"

# Everything else is a measurement. Collect divergences instead of stopping at the
# first: a report that says only "no" is indistinguishable from a broken guard.
diverged=""
report=""
for name in certificate skills isotopes; do
  case "$name" in
    certificate) path="cluster/certificate.json" ;;
    skills)      path="cluster/skills.json" ;;
    isotopes)    path="isotopes/zaphod-base.json" ;;
  esac
  [ -f "$path" ] || { diverged="$diverged $name"; report="${report}missing   $name\n"; continue; }
  state_digest="$(jq -r --arg n "$name" '.artifacts[$n] // empty' "$state_file")"
  [ -n "$state_digest" ] || { diverged="$diverged $name"; report="${report}uncovered $name\n"; continue; }
  found="$(digest "$path")"
  [ "$found" = "$state_digest" ] || {
    diverged="$diverged $name"
    report="${report}differs   $name  attested $(short "$state_digest")  published $(short "$found")\n"
  }
done

head="$(chain_head cluster/rotations)"
head_diverged=""
if [ "$head" != "$state_head" ]; then
  head_diverged="yes"
  report="${report}differs   receipt head  attested $(short "$state_head")  published $(short "$head")\n"
fi

if [ -n "$diverged" ] || [ -n "$head_diverged" ]; then
  count=$(printf '%s' "$diverged" | wc -w | tr -d ' ')
  [ -n "$head_diverged" ] && count=$((count + 1))
  {
    printf 'gate rejected: the published artifacts are not the version this cluster attested\n\n'
    printf 'divergence (noise, not verdict):\n'
    printf "$report"
    if command -v go >/dev/null 2>&1; then
      printf '\n'
      go run ./cmd/isotope42 drift --accepted "$count" 2>/dev/null | sed 's/^/  /'
    fi
  } >&2
  exit 1
fi

echo "cluster gate ok: state attested, 3 artifact(s), head $(short "$head")…"
