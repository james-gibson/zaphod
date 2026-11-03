#!/usr/bin/env bash
# Guard the one thing this repository must never get wrong: it is expected to
# commit a private key, so the key on disk has to be the *burned* one and
# nothing else. A real key pasted in by accident is refused here, in CI,
# before it can be mistaken for a test fixture.
set -euo pipefail
cd "$(dirname "$0")/.."

# git cannot carry the 0600 bit, and ssh-keygen refuses a private key that is
# group- or world-readable. Tighten it here so a checkout is usable as-is.
chmod 600 keys/id_ed25519 2>/dev/null || true


fail() { echo "::error::$*" >&2; exit 1; }

expected="$(tr -d '\n' < keys/FINGERPRINT)"
actual="$(ssh-keygen -lf keys/id_ed25519.pub)"
[ "$expected" = "$actual" ] || fail "public key does not match the pinned fingerprint
  pinned: $expected
  actual: $actual"

# The committed private half must be the pair of the committed public half, or
# a test that signs here would not verify against the key everyone else fetches.
derived="$(ssh-keygen -y -f keys/id_ed25519 | awk '{print $1" "$2}')"
published="$(awk '{print $1" "$2}' keys/id_ed25519.pub)"
[ "$derived" = "$published" ] || fail "keys/id_ed25519 is not the pair of keys/id_ed25519.pub"

# Exactly one private key may exist in the tree. The pattern is assembled at
# runtime so this script does not match itself.
pattern="BEGIN"" OPENSSH PRIVATE KEY"
found="$(grep -rl -- "$pattern" . --exclude-dir=.git 2>/dev/null | sed 's|^\./||' || true)"
count="$(printf '%s\n' "$found" | grep -c . || true)"
if [ "$count" -ne 1 ] || [ "$found" != "keys/id_ed25519" ]; then
  fail "expected exactly one private key (keys/id_ed25519), found: ${found:-none}"
fi

# The key must be the vector whose private half is public on purpose. Anything
# else here is a credential leak wearing a test fixture's clothes.
if ! grep -q "DO NOT USE" keys/id_ed25519.pub; then
  fail "keys/id_ed25519.pub is no longer marked DO NOT USE; this repository only publishes burned keys"
fi

echo "keys ok: $(printf '%s' "$actual" | awk '{print $2}') ($(awk '{print $3}' keys/id_ed25519.pub))"
