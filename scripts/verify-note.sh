#!/usr/bin/env bash
# Sign or verify a note with the burned key.
#
#   scripts/verify-note.sh sign <file>      # writes <file>.sig
#   scripts/verify-note.sh verify <file>    # verifies <file>.sig
#
# The namespace is fixed: a signature made for "zaphod-note" is not valid for
# anything else, which is the one thing a burned key can still demonstrate.
set -euo pipefail
cd "$(dirname "$0")/.."

# git cannot carry the 0600 bit, and ssh-keygen refuses a private key that is
# group- or world-readable. Tighten it here so a checkout is usable as-is.
chmod 600 keys/id_ed25519 2>/dev/null || true


action="${1:-}"
file="${2:-}"
namespace="zaphod-note"

usage() {
  echo "usage: $0 sign|verify <file>" >&2
  exit 2
}

[ -n "$action" ] && [ -n "$file" ] || usage
[ -f "$file" ] || { echo "no such file: $file" >&2; exit 1; }

case "$action" in
  sign)
    ssh-keygen -Y sign -f keys/id_ed25519 -n "$namespace" "$file"
    echo "signed: $file.sig (namespace $namespace, principal zaphod-beeblebrox)"
    ;;
  verify)
    [ -f "$file.sig" ] || { echo "no signature: $file.sig" >&2; exit 1; }
    ssh-keygen -Y verify -f keys/allowed_signers -I zaphod-beeblebrox \
      -n "$namespace" -s "$file.sig" < "$file"
    echo "verified: $file (signed with a key everybody has, which is the point)"
    ;;
  *)
    usage
    ;;
esac
