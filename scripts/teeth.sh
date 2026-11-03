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
#   gate     the gate's artifact digests   a rewritten publication must be accepted
#   expiry   the publication's windows     the allowed version outside its window must be accepted
#   window   the gate's state window       a stale but genuine publication must be accepted
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

# ── layer 4: remove the cluster gate's digest comparison ──────────────────────
cp -R . "$work/gate"
(
  cd "$work/gate"
  export ZAPHOD_IDENTITY_FILE="$work/gate-identity.secret"
  export ZAPHOD_STATE_FILE="$work/gate-state.json"
  scripts/identity.sh init >/dev/null
  scripts/rotate.sh --reason "teeth: attest the publication" >/dev/null 2>&1
  # A self-consistent rewrite: content changed, re-signed, lock rebuilt.
  jq '.scope += ["admin"]' cluster/certificate.json > t && mv t cluster/certificate.json
  scripts/sign-artifact.sh cluster/certificate.json zaphod-certificate >/dev/null 2>&1
  scripts/allowed.sh --write >/dev/null

  if scripts/cluster-gate.sh >/dev/null 2>&1; then fail "gate present: a rewritten publication was accepted"; fi
  perl -0pi -e 's/\[ "\$found" = "\$state_digest" \] \|\|/true ||/' scripts/cluster-gate.sh
  grep -q '^  true ||' scripts/cluster-gate.sh || fail "gate removal did not apply"
  scripts/cluster-gate.sh >/dev/null 2>&1 || fail "gate removed: still refused; the case does not test the gate"
)
echo "teeth: cluster gate removed — a rewritten publication got through"

# ── layer 5: remove the publication's window comparisons ──────────────────────
# The window is asked twice on the publication side — the certificate's
# not_after and the set's expires — and both must go before the pure time attack
# succeeds: the allowed version, unmodified and correctly signed, presented
# outside its window with a pinned clock.
cp -R . "$work/expiry"
(
  cd "$work/expiry"
  perl -0pi -e 's/\[ "\$not_after" -gt "\$now" \] \|\| \{ .*/true/' scripts/cluster-verify.sh
  perl -0pi -e 's/if \[ "\$expiry_epoch" -le "\$now" \]; then/if false; then/' scripts/isotopes-verify.sh
  grep -q '^true$' scripts/cluster-verify.sh || fail "expiry removal did not apply"
  grep -q 'if false; then' scripts/isotopes-verify.sh || fail "set expiry removal did not apply"
)
if ( cd "$work/expiry" && scripts/redteam.sh > "$work/out-expiry" 2>&1 ); then
  cat "$work/out-expiry" >&2
  fail "expiry removed: redteam.sh passed; the window cases prove nothing"
fi
grep -q "RED TEAM SUCCEEDED" "$work/out-expiry" ||
  { cat "$work/out-expiry" >&2; fail "expiry removed: the suite went red without naming a success"; }
grep -q "outside its window" "$work/out-expiry" ||
  { cat "$work/out-expiry" >&2; fail "expiry removed: the accepted attempt was not the window replay"; }
echo "teeth: expiry removed — the allowed version outside its window got through"

# ── layer 6: remove the cluster gate's window comparison ──────────────────────
# The out-of-band window: the state records valid_until, and the gate refuses a
# publication presented after it. With the comparison gone, the allowed version —
# genuine, attested, unmodified — is accepted with the clock past its window.
cp -R . "$work/gate-window"
mkdir -p "$work/gate-window-id"
(
  cd "$work/gate-window"
  export ZAPHOD_IDENTITY_FILE="$work/gate-window-id/identity.secret"
  export ZAPHOD_STATE_FILE="$work/gate-window-id/state.json"
  scripts/identity.sh init >/dev/null
  scripts/rotate.sh --reason "teeth: attest the publication" >/dev/null 2>&1
  if ZAPHOD_NOW=4102444800 scripts/cluster-gate.sh >/dev/null 2>&1; then
    fail "gate window present: a stale publication was accepted"
  fi
  perl -0pi -e 's/\[ "\$now" -lt "\$state_valid_until" \] \|\|/true ||/' scripts/cluster-gate.sh
  grep -q '^true ||' scripts/cluster-gate.sh || fail "gate window removal did not apply"
  ZAPHOD_NOW=4102444800 scripts/cluster-gate.sh >/dev/null 2>&1 ||
    fail "gate window removed: still refused; the case does not test the gate's window"
)
echo "teeth: gate window removed — the allowed version after its window got through"

echo "all six layers are load-bearing: removing any one lets a change through"
