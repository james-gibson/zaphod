#!/usr/bin/env bash
# Verify a signed cluster artifact against the *pinned* key.
#
#   scripts/verify-artifact.sh cluster/certificate.json zaphod-certificate
#
# Three checks, in this order, and all have to hold:
#
#   1. the signature over `jq -S -c` of the file is a good signature for
#      `zaphod-beeblebrox` under the namespace;
#   2. the key that made it is the key pinned in keys/FINGERPRINT;
#   3. the canonical digest is the one recorded in cluster/allowed.txt.
#
# The second is what a signature check cannot give you on its own: allowed_signers
# lives in the same repository as the thing it vouches for, so "signed by somebody
# the local file trusts" is not a protection. The third is what a *key* cannot
# give you either: the key here is burned and published, so anybody can produce a
# valid signature over a widened certificate. Only the version can be refused, and
# that refusal is what keeps a red-team actor in lane.
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

# The only allowed version. A namespace with no entry (a rotation record, say) is
# governed by its own chain, not by this lock.
allowed="cluster/allowed.txt"
if [ -f "$allowed" ]; then
  case "$namespace" in
    zaphod-certificate) name="certificate" ;;
    zaphod-skills)      name="skills" ;;
    zaphod-isotopes)    name="isotopes" ;;
    *)                  name="" ;;
  esac
  if [ -n "$name" ]; then
    want="$(awk -v n="$name" '$2 == n {print $1}' "$allowed")"
    if [ -n "$want" ]; then
      got="$(jq -S -c . "$file" | { if command -v shasum >/dev/null 2>&1; then shasum -a 256; else sha256sum; fi } | awk '{print $1}')"
      [ "$got" = "$want" ] ||
        fail "drift from the only allowed version (content $got, allowed $want); a rotation record is required, see scripts/rotate.sh"
    fi
  fi
fi

echo "verified: $file (namespace $namespace, signed by $signer)"
