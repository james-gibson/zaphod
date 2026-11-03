#!/usr/bin/env bash
# Verify a signed cluster artifact against the *pinned* key.
#
#   scripts/verify-artifact.sh cluster/certificate.json zaphod-certificate
#
# Two checks, in this order, and both have to hold:
#
#   1. the signature over `jq -S -c` of the file is a good signature for
#      `zaphod-beeblebrox` under the namespace;
#   2. the key that made it is the key pinned in keys/FINGERPRINT.
#
# The second is the one that matters. A signature check alone trusts whatever
# allowed_signers says, and allowed_signers is a file in the same repository as
# the certificate — so "signed by somebody the local file trusts" is not a
# protection. The pin is what an attacker has to change in a second place, in a
# diff, to be believed.
set -euo pipefail
cd "$(dirname "$0")/.."

keydir="${ZAPHOD_KEY_DIR:-keys}"
file="${1:-}"
namespace="${2:-}"

fail() { echo "rejected: $*" >&2; exit 1; }

[ -n "$file" ] && [ -n "$namespace" ] || { echo "usage: $0 <json> <namespace>" >&2; exit 2; }
[ -f "$file" ] || fail "no such artifact: $file"
[ -f "$file.sig" ] || fail "no signature: $file.sig"
jq -e . "$file" >/dev/null 2>&1 || fail "$file is not JSON"
[ -f "$keydir/FINGERPRINT" ] || fail "no pinned fingerprint at $keydir/FINGERPRINT"

pin="$(awk '{print $2}' "$keydir/FINGERPRINT")"
[ -n "$pin" ] || fail "empty pinned fingerprint at $keydir/FINGERPRINT"

# The key on disk must be the pinned key, whatever the signature says. This
# catches a swapped keys/id_ed25519.pub before anything is verified against it.
pub_fp="$(ssh-keygen -lf "$keydir/id_ed25519.pub" 2>/dev/null | awk '{print $2}')" ||
  fail "cannot read $keydir/id_ed25519.pub"
[ "$pub_fp" = "$pin" ] || fail "key on disk is $pub_fp, pinned key is $pin"

verdict="$(jq -S -c . "$file" | ssh-keygen -Y verify \
  -f "$keydir/allowed_signers" -I zaphod-beeblebrox \
  -n "$namespace" -s "$file.sig" 2>&1)" || fail "bad signature: ${verdict##*$'\n'}"

signer="$(printf '%s' "$verdict" | sed -n 's/.* key \(SHA256:[^ ]*\).*/\1/p')"
[ -n "$signer" ] || fail "cannot tell which key signed $file"
[ "$signer" = "$pin" ] || fail "signed by $signer, which is not the pinned key $pin"

echo "verified: $file (namespace $namespace, signed by $signer)"
