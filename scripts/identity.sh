#!/usr/bin/env bash
# The cluster's identity secret, and the attestation only it can produce.
#
#   scripts/identity.sh init                 generate a secret (0600, outside the repo)
#   scripts/identity.sh id                   the public isotope id
#   scripts/identity.sh attest <record> [prev]   the attestation for a rotation
#   scripts/identity.sh verify <record> [prev]   check the attestation in the record
#
# Why this exists: everything else in this repository is public, including the
# signing key. A competent actor with the repository, the burned key, the tooling
# and a proxy position can produce a rotation that is correct in every respect a
# third party can check — signatures, public receipt chain, lock. What it cannot
# produce is this attestation, because the secret is never in the repository and
# never written to a file the repository carries.
#
# The check is arithmetic, not policy: an attestation computed with the wrong
# secret is not "unauthorised", it is wrong, and `verify` says so.
#
# Boundary, stated rather than implied: this models access to the repository, the
# key, the tooling and the filesystem. It does not model reading a running
# process's memory. A secret in memory is a real boundary; it is not an absolute
# one, and the document says so rather than pretending otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

. scripts/lib-receipt.sh

secret_file="${ZAPHOD_IDENTITY_FILE:-$HOME/.zaphod/identity.secret}"

sha256_hex() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'; else sha256sum | awk '{print $1}'; fi
}

usage() {
  echo "usage: $0 init|id|attest <record> [prev]|verify <record> [prev]" >&2
  exit 2
}

require_secret() {
  [ -f "$secret_file" ] ||
    { echo "no identity secret at $secret_file — the cluster holds it, the repository does not" >&2; exit 1; }
}

cmd="${1:-}"
case "$cmd" in
  init)
    if [ -f "$secret_file" ]; then
      echo "identity already present at $secret_file"
    else
      mkdir -p "$(dirname "$secret_file")"
      ( umask 077; head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' > "$secret_file" )
      echo "wrote $secret_file (0600)"
    fi
    printf 'isotope %s\n' "$(sha256_hex < "$secret_file")"
    ;;
  id)
    require_secret
    printf '%s\n' "$(sha256_hex < "$secret_file")"
    ;;
  attest)
    require_secret
    record="${2:-}"; [ -f "$record" ] || usage
    prev="${3:-genesis}"
    printf '%s\n' "$(printf '%s' "$(cat "$secret_file"):$(jq -S -c 'del(.receipt) | del(.attestation)' "$record"):${prev}" | sha256_hex)"
    ;;
  verify)
    require_secret
    record="${2:-}"; [ -f "$record" ] || usage
    prev="${3:-genesis}"
    claimed="$(jq -r '.attestation // empty' "$record")"
    [ -n "$claimed" ] || { echo "no attestation on $record" >&2; exit 1; }
    want="$(printf '%s' "$(cat "$secret_file"):$(jq -S -c 'del(.receipt) | del(.attestation)' "$record"):${prev}" | sha256_hex)"
    if [ "$claimed" != "$want" ]; then
      echo "rejected: attestation is not mathematically the one this identity would produce" >&2
      exit 1
    fi
    echo "attested: $record"
    ;;
  *)
    usage
    ;;
esac
