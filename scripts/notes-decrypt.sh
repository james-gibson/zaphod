#!/usr/bin/env bash
# Decrypt the notes from the release asset.
#
#   scripts/notes-decrypt.sh <dir> [output-dir]
#
# <dir> is an extracted zaphod-notes zip (it contains encrypted/ and
# MANIFEST.sha256). The ciphertext is checked against the manifest before
# anything is decrypted; the output goes to <dir>/plain unless you say otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

# git cannot carry the 0600 bit, and ssh-keygen refuses a private key that is
# group- or world-readable. Tighten it here so a checkout is usable as-is.
chmod 600 keys/id_ed25519 2>/dev/null || true


dir="${1:-}"
out="${2:-}"
[ -n "$dir" ] || { echo "usage: $0 <extracted-zip-dir> [output-dir]" >&2; exit 2; }
[ -d "$dir" ] || { echo "no such directory: $dir" >&2; exit 1; }
[ -d "$dir/encrypted" ] || { echo "$dir does not look like an extracted notes zip" >&2; exit 1; }

dir_abs="$(cd "$dir" && pwd)"
out="${out:-$dir_abs/plain}"
mkdir -p "$out"

if [ -f "$dir_abs/MANIFEST.sha256" ]; then
  if command -v shasum >/dev/null 2>&1; then
    ( cd "$dir_abs" && shasum -a 256 -c MANIFEST.sha256 )
  else
    ( cd "$dir_abs" && sha256sum -c MANIFEST.sha256 )
  fi
else
  echo "warning: no MANIFEST.sha256; decrypting unverified ciphertext" >&2
fi

shopt -s nullglob
files=("$dir_abs"/encrypted/*.age)
[ "${#files[@]}" -gt 0 ] || { echo "no ciphertext in $dir_abs/encrypted" >&2; exit 1; }

for f in "${files[@]}"; do
  name="$(basename "$f" .age)"
  age -d -i keys/id_ed25519 -o "$out/$name" "$f"
  echo "decrypted: $out/$name"
done

echo "done. the key that opens these is published here, so this is a demonstration, not a secret."
