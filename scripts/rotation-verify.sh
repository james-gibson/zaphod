#!/usr/bin/env bash
# Verify the rotation chain.
#
#   scripts/rotation-verify.sh
#
# A rotation record is the only sanctioned way for the allowed key to move. Each
# record is signed by the key it rotates *from*, embeds that key's public half so
# it stays verifiable after the swap, and names the key it rotates *to*. The chain
# has to be contiguous and end at whatever keys/ currently holds.
#
# This is what a signature alone cannot do: zaphod and ACME both hold the burned
# key, so "correctly signed" is not a distinguishing property. A record is.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib-receipt.sh

dir="${ZAPHOD_ROTATIONS:-cluster/rotations}"
[ -d "$dir" ] || { echo "no rotation chain at $dir" >&2; exit 1; }

mapfile_supported=1
files=()
for f in "$dir"/*.json; do [ -e "$f" ] && files+=("$f"); done
[ "${#files[@]}" -gt 0 ] || { echo "empty rotation chain" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fp_of() { ssh-keygen -lf "$1" | awk '{print $2}'; }

expected_seq=0
prev_to=""
chain="genesis"
last_to=""
for record in "${files[@]}"; do
  jq -e . "$record" >/dev/null 2>&1 || { echo "$record is not JSON" >&2; exit 1; }
  seq="$(jq -r .seq "$record")"
  from="$(jq -r .from "$record")"
  to="$(jq -r .to "$record")"
  from_pub="$(jq -r .from_pub "$record")"
  to_pub="$(jq -r .to_pub "$record")"

  [ "$seq" = "$expected_seq" ] || { echo "$record: seq $seq, expected $expected_seq" >&2; exit 1; }
  [ "$(jq -r .version "$record")" = "1" ] || { echo "$record: unsupported version" >&2; exit 1; }
  if [ -n "$prev_to" ] && [ "$from" != "$prev_to" ]; then
    echo "$record rotates from $from, but the chain ends at $prev_to" >&2
    exit 1
  fi

  # The keys embedded in the record have to be the ones the fingerprints name.
  printf '%s\n' "$from_pub" > "$work/from.pub"
  printf '%s\n' "$to_pub" > "$work/to.pub"
  [ "$(fp_of "$work/from.pub")" = "$from" ] || { echo "$record: from_pub is not $from" >&2; exit 1; }
  [ "$(fp_of "$work/to.pub")" = "$to" ] || { echo "$record: to_pub is not $to" >&2; exit 1; }

  # Signed by the key it rotates from, not by the key it rotates to.
  printf 'zaphod-beeblebrox %s\n' "$from_pub" > "$work/signers"
  verdict="$(jq -S -c . "$record" | ssh-keygen -Y verify -f "$work/signers" \
    -I zaphod-beeblebrox -n zaphod-rotation -s "$record.sig" 2>&1)" ||
    { echo "$record: ${verdict##*$'\n'}" >&2; exit 1; }
  signer="$(printf '%s' "$verdict" | sed -n 's/.* key \(SHA256:[^ ]*\).*/\1/p')"
  [ "$signer" = "$from" ] || { echo "$record: signed by $signer, rotates from $from" >&2; exit 1; }

  # The receipt: the identity vouching for this rotation, chained onto the one
  # before it. A chain recreated with another identity recomputes differently,
  # which is the point — it cannot be spliced onto this one.
  prev_chain="$chain"
  computed="$(receipt_for "$record" "$prev_chain")"
  if jq -e 'has("receipt")' "$record" >/dev/null; then
    [ "$(jq -r .receipt "$record")" = "$computed" ] ||
      { echo "$record: receipt does not chain onto the previous rotation" >&2; exit 1; }
  elif [ "$seq" != "0" ]; then
    echo "$record: no receipt, and only the genesis may omit one" >&2
    exit 1
  fi
  # The attestation, when the cluster's identity is available to check it. Without
  # the identity it can only be noted; the cluster is the only place it verifies.
  if [ -f "${ZAPHOD_IDENTITY_FILE:-$HOME/.zaphod/identity.secret}" ] && [ "$seq" != "0" ]; then
    scripts/identity.sh verify "$record" "$prev_chain" >/dev/null 2>&1 ||
      { echo "$record: attestation is not mathematically the one this identity would produce" >&2; exit 1; }
  fi

  chain="$computed"

  prev_to="$to"
  last_to="$to"
  expected_seq=$((expected_seq + 1))
done

current="$(fp_of keys/id_ed25519.pub)"
[ "$last_to" = "$current" ] ||
  { echo "chain ends at $last_to, keys/ holds $current — a rotation record is missing" >&2; exit 1; }
[ "$(awk '{print $2}' keys/FINGERPRINT)" = "$current" ] ||
  { echo "keys/FINGERPRINT does not name the key in keys/id_ed25519.pub" >&2; exit 1; }

# The head the lock names. This is what a chain recreated from scratch cannot
# reproduce: its head is a different value, for a different identity.
allowed_head="$(awk '$2 == "receipt" {print $1}' cluster/allowed.txt 2>/dev/null || true)"
if [ -n "$allowed_head" ]; then
  [ "$chain" = "$allowed_head" ] ||
    { echo "chain head ${chain:0:16}… is not the head the lock names (${allowed_head:0:16}…)" >&2; exit 1; }
fi

echo "rotation chain ok: $expected_seq record(s), current $current, receipt ${chain:0:16}…"
