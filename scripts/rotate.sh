#!/usr/bin/env bash
# The sanctioned update: re-sign the cluster artifacts and record the rotation.
#
#   scripts/rotate.sh --reason "annual rotation" [--new-key /path/to/new]
#
# Without --new-key this is a content update with the same key. With it, the
# allowed key moves to the new one — accepted on the first attempt, because the
# record is signed by the key it rotates *from* and the lock is rewritten in the
# same step.
#
# Everything here is on zaphod's side of the lane. ACME can copy this script, run
# it with its own key, and produce a perfectly valid chain — and CI still refuses
# it, because the chain it produces is not the chain that was reviewed. The
# asymmetry is the review, not the cryptography: the key is burned, so there is no
# secret to keep this honest.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lib-receipt.sh
chmod +x scripts/identity.sh 2>/dev/null || true
chmod 600 keys/id_ed25519 2>/dev/null || true

reason=""
newkey=""
while [ $# -gt 0 ]; do
  case "$1" in
    --reason)  reason="${2:-}"; shift 2 ;;
    --new-key) newkey="${2:-}"; shift 2 ;;
    *) echo "usage: $0 --reason TEXT [--new-key PRIVATE_KEY_FILE]" >&2; exit 2 ;;
  esac
done
[ -n "$reason" ] || { echo "usage: $0 --reason TEXT [--new-key PRIVATE_KEY_FILE]" >&2; exit 2; }

fail() { echo "rotation refused: $*" >&2; exit 1; }

# A rotation on top of a tree that does not verify would launder the breakage into
# the chain, so refuse before touching anything.
scripts/cluster-verify.sh >/dev/null
scripts/rotation-verify.sh >/dev/null

old_fp="$(awk '{print $2}' keys/FINGERPRINT)"
old_pub="$(cat keys/id_ed25519.pub)"
old_priv="keys/id_ed25519"

if [ -n "$newkey" ]; then
  [ -f "$newkey" ] || fail "no such key: $newkey"
  case "$(cd "$(dirname "$newkey")" && pwd)/$(basename "$newkey")" in
    "$(pwd)"/*) fail "the new key must live outside the repository: a second private key in the tree is exactly what scripts/guard-keys.sh refuses" ;;
  esac
  [ -f "$newkey.pub" ] || fail "no public half beside $newkey"
  new_pub="$(cat "$newkey.pub")"
  new_fp="$(ssh-keygen -lf "$newkey.pub" | awk '{print $2}')"
  case "$new_pub" in
    *"DO NOT USE"*) ;;
    *) fail "this repository publishes burned keys only; mark the new key DO NOT USE" ;;
  esac
  [ "$new_fp" != "$old_fp" ] || fail "the new key is the key already in use"
else
  new_pub="$old_pub"
  new_fp="$old_fp"
fi

# The head of the chain *before* this record exists: the receipt links to it.
prev_receipt="$(chain_head cluster/rotations)"

last="$(ls cluster/rotations/*.json | sort | tail -1)"
seq=$(( $(jq -r .seq "$last") + 1 ))
record="$(printf 'cluster/rotations/%03d-rotation.json' "$seq")"

jq -n \
  --argjson seq "$seq" \
  --arg from "$old_fp" --arg from_pub "$old_pub" \
  --arg to "$new_fp" --arg to_pub "$new_pub" \
  --arg at "$(date -u +%FT%TZ)" --arg reason "$reason" \
  '{version: 1, seq: $seq, cluster: "zaphod-base",
    from: $from, from_pub: $from_pub, to: $to, to_pub: $to_pub,
    at: $at, reason: $reason}' > "$record"

# The receipt, chained onto the previous one: a rotation is vouched for by the
# identity it rotates from, and the chain is what makes it un-spliceable.
receipt="$(receipt_for "$record" "$prev_receipt")"
jq --arg receipt "$receipt" '. + {receipt: $receipt}' "$record" > "$record.tmp"
mv "$record.tmp" "$record"

# The attestation: the running identity vouching for this rotation with a secret
# the repository has never held. Everything else here can be reproduced by an actor
# with the repo, the key and the tooling; this cannot, and the refusal is arithmetic
# rather than policy.
attestation="$(scripts/identity.sh attest "$record" "$prev_receipt")" ||
  fail "no identity secret — only the running cluster can authorise a rotation"
jq --arg attestation "$attestation" '. + {attestation: $attestation}' "$record" > "$record.tmp"
mv "$record.tmp" "$record"

# Signed by the key being rotated away from, before it is replaced.
tmp="$(mktemp)"
trap 'rm -f "$tmp" "$tmp.sig"' EXIT
jq -S -c . "$record" > "$tmp"
ssh-keygen -Y sign -f "$old_priv" -n zaphod-rotation "$tmp" >/dev/null
cp "$tmp.sig" "$record.sig"

if [ -n "$newkey" ]; then
  install -m 600 "$newkey" keys/id_ed25519
  cp "$newkey.pub" keys/id_ed25519.pub
  ssh-keygen -lf keys/id_ed25519.pub > keys/FINGERPRINT
  {
    grep '^#' keys/allowed_signers || true
    printf 'zaphod-beeblebrox %s\n' "$new_pub"
  } > keys/allowed_signers.new
  mv keys/allowed_signers.new keys/allowed_signers
fi

# The certificate names the key it belongs to, so a key rotation has to move that
# too — otherwise the chain verifies and the certificate says somebody else.
if [ -n "$newkey" ]; then
  tmp_cert="$(mktemp)"
  jq --arg fp "$new_fp" '.subject_fingerprint = $fp' cluster/certificate.json > "$tmp_cert"
  mv "$tmp_cert" cluster/certificate.json
  if [ -f isotopes/zaphod-base.json ]; then
    tmp_iso="$(mktemp)"
    jq --arg fp "$new_fp" '.issued_by_fingerprint = $fp' isotopes/zaphod-base.json > "$tmp_iso"
    mv "$tmp_iso" isotopes/zaphod-base.json
  fi
fi

scripts/sign-artifact.sh cluster/certificate.json zaphod-certificate >/dev/null
scripts/sign-artifact.sh cluster/skills.json zaphod-skills >/dev/null
if [ -f isotopes/zaphod-base.json ]; then
  scripts/sign-artifact.sh isotopes/zaphod-base.json zaphod-isotopes >/dev/null
fi
scripts/allowed.sh --write >/dev/null

# The point of the exercise: no manual edits, no second attempt.
scripts/cluster-verify.sh >/dev/null
scripts/rotation-verify.sh >/dev/null
scripts/guard-keys.sh >/dev/null

echo "rotation accepted on the first attempt: $old_fp -> $new_fp"
echo "  record: $record (signed by the key it rotates from)"
echo "  lock:   cluster/allowed.txt rewritten"
echo "  reason: $reason"
