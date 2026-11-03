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
# The trail first: a credential says what you hold, a trail says what you did, in
# the order you did it. The cluster does not assume that holding the secret means
# behaving, and it does not assume a stolen one behaves worse — it asks whether the
# publication arrived by the known path, and refuses anything that does not extend
# the trail it is already on.
identity_file="${ZAPHOD_IDENTITY_FILE:-$HOME/.zaphod/identity.secret}"
state_file="${ZAPHOD_STATE_FILE:-$(dirname "$identity_file")/state.json}"
state_dir="$(dirname "$state_file")"
mkdir -p "$state_dir"

publication="$(jq -S -c -n \
  --arg certificate "$(jq -S -c . cluster/certificate.json | sha256_hex)" \
  --arg skills "$(jq -S -c . cluster/skills.json | sha256_hex)" \
  --arg isotopes "$(jq -S -c . isotopes/zaphod-base.json | sha256_hex)" \
  '{certificate: $certificate, skills: $skills, isotopes: $isotopes}')"

trail="$state_dir/trail.jsonl"
[ -f "$trail" ] || : > "$trail"
prev="$(tail -1 "$trail" 2>/dev/null | jq -r '.hash // empty')"
seq="$(wc -l < "$trail" | tr -d ' ')"
action="publish"
[ -n "$prev" ] || { prev="genesis"; action="init"; }
# Hash with the trailing newline jq would print, so it matches the gate exactly.
publication_hash="$(printf '%s\n' "$publication" | sha256_hex)"
# A nonce the cluster consumes and keeps in its own state. Without it an actor holding
# the secret can recompute the entry exactly — the transcript is public and a timestamp
# to the second is not a secret — which is not a forgery any gate could see.
nonce="$(head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n')"
entry="$(jq -n --argjson seq "$seq" --arg action "$action" --arg publication "$publication_hash" \
  --arg prev "$prev" --arg at "$(date -u +%FT%TZ)" --arg nonce "$nonce" \
  '{seq: $seq, action: $action, publication: $publication, prev: $prev, at: $at, nonce: $nonce}')"
mac="$(printf '%s' "$(cat "$identity_file"):$(jq -S -c . <<<"$entry"):trail" | sha256_hex)"
hash="$(printf '%s' "$(jq -S -c --arg m "$mac" '. + {attestation: $m}' <<<"$entry")" | sha256_hex)"
jq -c --arg m "$mac" --arg h "$hash" '. + {attestation: $m, hash: $h}' <<<"$entry" >> "$trail"

# The cluster's own record of what it just accepted: the publication, the chain
# head, and the trail head it is on. Kept outside the repository, attested with the
# secret. The publication can be rewritten; this cannot.
canonical_state="$(jq -S -c -n \
  --argjson artifacts "$publication" \
  --arg head "$(chain_head cluster/rotations)" \
  --arg trail_head "$hash" \
  --arg trail_nonce "$nonce" \
  --arg at "$(date -u +%FT%TZ)" \
  '{artifacts: $artifacts, receipt_head: $head, trail_head: $trail_head,
    trail_nonce: $trail_nonce, attested_at: $at}')"
attestation="$(printf '%s' "$(cat "$identity_file"):${canonical_state}:state" | sha256_hex)"
printf '%s' "$canonical_state" | jq --arg a "$attestation" '. + {attestation: $a}' > "$state_file"

# The announcement: a rotation becomes usable when it is announced, not when it is
# written. le.roy carries this shape to applications that do not speak 42i — a tick, a
# publication digest, an effective time — and a cluster tick can afford a full rebuild
# because nothing acts on a rotation it has not seen announced.
announce="cluster/announcements.json"
[ -f "$announce" ] || echo '{"version": 1, "announcements": []}' > "$announce"
publication_announced="$(jq -S -c '.artifacts' "$state_file" | sha256_hex)"
tick="$(jq '.announcements | length' "$announce")"
jq --argjson tick "$tick" --arg at "$(date -u +%FT%TZ)" \
   --arg publication "$publication_announced" \
   --arg head "$(chain_head cluster/rotations)" \
   '.announcements += [{seq: $tick, tick: $tick, verb: "rotate", claimant: "zaphod-beeblebrox",
      at: $at, effective_at: $at, publication: $publication, receipt_head: $head,
      summary: "rotation announced"}]' "$announce" > "$announce.tmp"
mv "$announce.tmp" "$announce"
scripts/sign-artifact.sh "$announce" zaphod-announcement >/dev/null


scripts/allowed.sh --write >/dev/null

scripts/cluster-verify.sh >/dev/null
scripts/rotation-verify.sh >/dev/null
scripts/guard-keys.sh >/dev/null
ZAPHOD_IDENTITY_FILE="$identity_file" ZAPHOD_STATE_FILE="$state_file" scripts/cluster-gate.sh >/dev/null

echo "rotation accepted on the first attempt: $old_fp -> $new_fp"
echo "  record: $record (signed by the key it rotates from)"
echo "  lock:   cluster/allowed.txt rewritten"
echo "  reason: $reason"
