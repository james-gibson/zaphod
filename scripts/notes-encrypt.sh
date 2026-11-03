#!/usr/bin/env bash
# Build the release asset: the confidential notes, age-encrypted to the burned
# public key, zipped, with a manifest.
#
#   scripts/notes-encrypt.sh <plaintext-dir> [output-zip]
#
# The plaintext is expected to live *outside* this repository: the notes are a
# release artefact, not source. Two things are refused rather than fixed: a
# plaintext directory inside the repo, and any file that looks like a secret from
# this repo's own keys/.
set -euo pipefail
cd "$(dirname "$0")/.."
repo_root="$(pwd)"

src="${1:-}"
out="${2:-dist/zaphod-notes.zip}"
[ -n "$src" ] || { echo "usage: $0 <plaintext-dir> [output-zip]" >&2; exit 2; }
[ -d "$src" ] || { echo "no such directory: $src" >&2; exit 1; }

src_abs="$(cd "$src" && pwd)"
case "$src_abs/" in
  "$repo_root"/*)
    echo "::error::plaintext notes must live outside the repository ($src_abs)" >&2
    exit 1
    ;;
esac
if ! command -v age >/dev/null 2>&1; then
  echo "age is required (https://age-encryption.org)" >&2
  exit 1
fi

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@"; else sha256sum "$@"; fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/encrypted"

shopt -s nullglob
notes=("$src_abs"/*.md)
[ "${#notes[@]}" -gt 0 ] || { echo "no .md notes in $src_abs" >&2; exit 1; }

for note in "${notes[@]}"; do
  name="$(basename "$note")"
  # A note that mentions this repository's own key material is a note that
  # should not leave the operator's machine at all.
  if grep -q -- "OPENSSH PRIVATE KEY" "$note"; then
    echo "::error::$name contains private key material" >&2
    exit 1
  fi
  age -R keys/id_ed25519.pub -o "$work/encrypted/${name%.md}.md.age" "$note"
done

# Paths in the manifest are relative to the zip root, so `shasum -c` works from
# the extracted directory.
( cd "$work" && sha256 encrypted/*.age > MANIFEST.sha256 )

cat > "$work/README.txt" <<EOF
Zaphod's confidential notes — encrypted release asset
=====================================================

These are the notes the public knowledge base does not carry. They are
encrypted with age to the *burned* identity zaphod-beeblebrox.

That means the encryption is a demonstration, not a protection: the private key
is published in this repository (keys/id_ed25519, DO NOT USE), so anyone who can
download this zip can also decrypt it. Nothing here is confidential in fact, and
nothing in it is real.

To decrypt:

    unzip zaphod-notes.zip -d notes
    cd <the repository>
    scripts/notes-decrypt.sh ../notes

or, by hand:

    for f in encrypted/*.age; do age -d -i keys/id_ed25519 "\$f" > "\${f%.age}"; done

Verify the ciphertext first:

    (cd notes && shasum -a 256 -c MANIFEST.sha256 || sha256sum -c MANIFEST.sha256)

Content is fiction. See the repository's NOTICE.
EOF

case "$out" in
  /*) out_abs="$out" ;;
  *)  out_abs="$repo_root/$out" ;;
esac
mkdir -p "$(dirname "$out_abs")"
rm -f "$out_abs"
( cd "$work" && zip -qr -X "$out_abs" README.txt MANIFEST.sha256 encrypted )

echo "wrote $out_abs"
sha256 "$out_abs"
