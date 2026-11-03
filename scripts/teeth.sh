#!/usr/bin/env bash
# Prove the suite can fail.
#
#   scripts/teeth.sh
#
# A red-team suite that passes because nothing verifies is worse than no suite, so
# this removes each layer of the guard in a throwaway copy and requires the suite
# to go red — naming the attack, and showing the drift on the 42i axis.
#
#   layer 1  the pin (keys/FINGERPRINT)  -> ACME's own key must be accepted
#   layer 2  the allowed version (cluster/allowed.txt) -> a *correctly signed*
#            change must be accepted, and the cluster must drift off 42+0i
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "::error::$*" >&2; exit 1; }

# expect_red <copy> <label> <needle>
expect_red() {
  local repo="$1" label="$2" needle="$3"
  if ( cd "$repo" && scripts/redteam.sh > "$work/out" 2>&1 ); then
    cat "$work/out" >&2
    fail "$label: redteam.sh passed with the guard removed; the suite proves nothing"
  fi
  grep -q "$needle" "$work/out" ||
    { cat "$work/out" >&2; fail "$label: the suite went red without saying why ($needle)"; }
  echo "teeth: $label — the suite went red, as it must"
}

# ── layer 1: remove the fingerprint comparison ────────────────────────────────
cp -R . "$work/pin"
(cd "$work/pin" && perl -0pi -e 's/\[ "\$signer" = "\$pin" \] \|\| fail .*/true/' scripts/verify-artifact.sh)
grep -q '^true$' "$work/pin/scripts/verify-artifact.sh" || fail "pin removal did not apply"
expect_red "$work/pin" "pin removed" "RED TEAM SUCCEEDED"

# ── layer 2: remove the allowed-version comparison ────────────────────────────
cp -R . "$work/lock"
(cd "$work/lock" && perl -0pi -e 's/fail "drift from the only allowed version[^"]*"/true/' scripts/verify-artifact.sh)
grep -q 'drift from the only allowed version' "$work/lock/scripts/verify-artifact.sh" &&
  fail "allowed-version removal did not apply"
expect_red "$work/lock" "allowed version removed" "verdict: drifted"

echo "both layers are load-bearing: removing either one lets a change through, and the 42i reading shows the drift"
