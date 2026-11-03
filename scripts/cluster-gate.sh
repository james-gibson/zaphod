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
# The gate verifies the state's attestation with the cluster secret, then compares
# the repository's artifacts and chain head against it. A corpus that is internally
# consistent — but that this cluster never attested — is refused. That is the whole
# distinction the exercise is about: the repository can be rewritten, the arithmetic
# cannot.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib-receipt.sh

identity_file="${ZAPHOD_IDENTITY_FILE:-$HOME/.zaphod/identity.secret}"
state_file="${ZAPHOD_STATE_FILE:-$(dirname "$identity_file")/state.json}"

fail() { echo "gate rejected: $*" >&2; exit 1; }

[ -f "$identity_file" ] ||
  fail "no identity secret at $identity_file — the cluster holds it; the repository cannot stand in for it"
[ -f "$state_file" ] ||
  fail "no cluster state at $state_file — this cluster has not attested anything yet"

sha256_hex() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'; else sha256sum | awk '{print $1}'; fi
}

# 1. The state's own attestation: is this the state the cluster wrote?
canonical_state="$(jq -S -c 'del(.attestation)' "$state_file")"
want="$(printf '%s' "$(cat "$identity_file"):${canonical_state}:state" | sha256_hex)"
got="$(jq -r '.attestation // empty' "$state_file")"
[ -n "$got" ] || fail "cluster state carries no attestation"
[ "$got" = "$want" ] || fail "the cluster state is not the one this identity attested (not mathematically the same)"

# 2. The published artifacts: are they the ones the cluster attested?
digest() { jq -S -c . "$1" | sha256_hex; }
for name in certificate skills isotopes; do
  case "$name" in
    certificate) path="cluster/certificate.json" ;;
    skills)      path="cluster/skills.json" ;;
    isotopes)    path="isotopes/zaphod-base.json" ;;
  esac
  [ -f "$path" ] || fail "no $name artifact at $path"
  state_digest="$(jq -r --arg n "$name" '.artifacts[$n] // empty' "$state_file")"
  [ -n "$state_digest" ] || fail "the cluster state does not cover $name"
  [ "$(digest "$path")" = "$state_digest" ] ||
    fail "the published $name is not the version this cluster attested"
done

# 3. The rotation chain: is the head the one it attested?
head="$(chain_head cluster/rotations)"
state_head="$(jq -r '.receipt_head // empty' "$state_file")"
[ "$head" = "$state_head" ] ||
  fail "the chain head ${head:0:16}… is not the head this cluster attested (${state_head:0:16}…)"

echo "cluster gate ok: state attested, $(jq -r '.artifacts | length' "$state_file") artifact(s), head ${head:0:16}…"
