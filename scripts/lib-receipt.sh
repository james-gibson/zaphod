#!/usr/bin/env bash
# The rotation receipt: a rotation vouched for by the identity it rotates from.
#
#   source scripts/lib-receipt.sh
#   receipt_for <record.json> <previous-receipt|genesis>
#
# Formula (the library's receipt shape, with the identity's public half where a
# live instance would use its secret, because this fixture's identity is burned):
#
#   SHA256("zaphod-rotation-v1:" + from_fingerprint + ":" + canonical(record) + ":" + previous)
#
# where canonical(record) is `jq -S -c` of the record with `receipt` removed, and
# `previous` is the receipt of the record before it — `genesis` for the first.
#
# Two properties matter, and both are what a signature alone does not give:
#
#   * it is bound to the identity, so a receipt issued for zaphod's key cannot be
#     presented as evidence for any other key;
#   * it chains back onto itself, so a rotation corpus recreated from scratch with
#     another identity is a different chain — it cannot be spliced onto this one,
#     and its head is not the head the lock names.

sha256_hex() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    sha256sum | awk '{print $1}'
  fi
}

receipt_for() {
  local record="$1" previous="$2"
  local from canonical
  from="$(jq -r .from "$record")"
  canonical="$(jq -S -c 'del(.receipt) | del(.attestation)' "$record")"
  printf '%s' "zaphod-rotation-v1:${from}:${canonical}:${previous}" | sha256_hex
}

# chain_head <dir>: walk the rotation records in order and print the chain's head
# receipt. Sets nothing else; prints "genesis" when there are no records.
chain_head() {
  local dir="${1:-cluster/rotations}" previous="genesis" f
  for f in $(ls "$dir"/*.json 2>/dev/null | sort); do
    previous="$(receipt_for "$f" "$previous")"
  done
  printf '%s' "$previous"
}
