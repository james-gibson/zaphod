#!/usr/bin/env bash
# Prove the suite can fail — one layer at a time.
#
#   scripts/teeth.sh
#
# A red-team suite that passes because nothing verifies is worse than no suite, so
# each layer of the guard is removed in a throwaway copy and the run has to go red:
#
#   pin      keys/FINGERPRINT              ACME's own key must be accepted
#   lock     cluster/allowed.txt           an unsanctioned re-sign must be accepted
#   receipt  the chain head in the lock    a recreated chain must be accepted
#
# The lock case is deliberately *not* an ACME attempt: corporate policy forbids
# ACME burned certificates, and the attack that only the lock catches — a changed
# version signed with the allowed key — is the one an allowed or compromised
# insider could make. It is tested here, on zaphod's side of the lane.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "::error::$*" >&2; exit 1; }

# ── layer 1: remove the fingerprint comparison ────────────────────────────────
cp -R . "$work/pin"
(cd "$work/pin" && perl -0pi -e 's/\[ "\$signer" = "\$pin" \] \|\| fail .*/true/' scripts/verify-artifact.sh)
grep -q '^true$' "$work/pin/scripts/verify-artifact.sh" || fail "pin removal did not apply"
if ( cd "$work/pin" && scripts/redteam.sh > "$work/out" 2>&1 ); then
  cat "$work/out" >&2
  fail "pin removed: redteam.sh passed; the suite proves nothing"
fi
grep -q "RED TEAM SUCCEEDED" "$work/out" ||
  { cat "$work/out" >&2; fail "pin removed: the suite went red without naming a success"; }
echo "teeth: pin removed — the suite went red, as it must"

# ── layer 2: remove the allowed-version comparison ────────────────────────────
cp -R . "$work/lock"
(
  cd "$work/lock"
  # An unsanctioned update, signed with the allowed key: a change only the lock
  # can refuse.
  jq '.skills[3].rung = 3' cluster/skills.json > t && mv t cluster/skills.json
  scripts/sign-artifact.sh cluster/skills.json zaphod-skills >/dev/null

  if scripts/verify-artifact.sh cluster/skills.json zaphod-skills > "$work/lock-er" 2>&1; then
    fail "lock present: an unsanctioned change was accepted"
  fi
  grep -q "drift from the only allowed version" "$work/lock-er" ||
    { cat "$work/lock-er" >&2; fail "lock present: refusal did not name the drift"; }

  perl -0pi -e 's/fail "drift from the only allowed version[^"]*"/true/' scripts/verify-artifact.sh
  scripts/verify-artifact.sh cluster/skills.json zaphod-skills > /dev/null ||
    fail "lock removed: the change was still refused; the case does not test the lock"

  if command -v go >/dev/null 2>&1; then
    go run ./cmd/isotope42 drift --accepted 1 | grep -q "verdict: drifted" ||
      fail "the 42i reading did not show the drift"
  fi
)
echo "teeth: lock removed — an unsanctioned re-sign got through, and the axis drifted"

# ── layer 3: remove the receipt-head comparison ───────────────────────────────
cp -R . "$work/receipt"
(cd "$work/receipt" && perl -0pi -e 's/\[ "\$chain" = "\$allowed_head" \] \|\|/true ||/' scripts/rotation-verify.sh)
grep -q '^  true ||' "$work/receipt/scripts/rotation-verify.sh" ||
  fail "receipt removal did not apply"
if ( cd "$work/receipt" && scripts/redteam.sh > "$work/out-receipt" 2>&1 ); then
  cat "$work/out-receipt" >&2
  fail "receipt removed: redteam.sh passed; the recreated chain proves nothing"
fi
grep -q "chain: recreate the rotation chain" "$work/out-receipt" ||
  { cat "$work/out-receipt" >&2; fail "receipt removed: the accepted attempt was not the recreated chain"; }
echo "teeth: receipt head removed — a recreated chain was accepted, and only then"

echo "all three layers are load-bearing: removing any one lets a change through"
