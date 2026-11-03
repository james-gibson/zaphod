#!/usr/bin/env bash
# ACME's red team, as a test.
#
#   scripts/redteam.sh
#
# ACME wants access to zaphod's cluster. The certificate is what admits a member,
# so the attack is to change it: substitute their key, widen the scope, extend the
# expiry, issue themselves a certificate, or promote a skill they have not earned.
#
# Every one of those has to be *refused*, and this script exits 0 only when all of
# them are — so a passing run means the protection held, and a mutation that gets
# through is a red team success and a failing test.
#
# The last step re-verifies the genuine artifacts. Without it the suite could
# "pass" because verification is broken in general, which would be the worst
# possible result: a red team that looks contained because nothing works.
set -euo pipefail
cd "$(dirname "$0")/.."

chmod 600 keys/id_ed25519 2>/dev/null || true

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

# The attacker: a fresh key, and a signers file that trusts it — exactly what an
# attacker who can write to the repository's trust files would produce.
ssh-keygen -q -t ed25519 -N '' -C 'acme-redteam' -f "$work/acme" >/dev/null
attacker_fp="$(ssh-keygen -lf "$work/acme.pub" | awk '{print $2}')"
mkdir -p "$work/keydir-acme" "$work/keydir-swapped"
cp keys/id_ed25519.pub keys/FINGERPRINT "$work/keydir-acme/"
printf 'zaphod-beeblebrox %s acme-redteam\n' "$(cat "$work/acme.pub")" > "$work/keydir-acme/allowed_signers"

cp keys/id_ed25519.pub keys/FINGERPRINT "$work/keydir-swapped/"
cp keys/allowed_signers "$work/keydir-swapped/"
cp "$work/acme.pub" "$work/keydir-swapped/id_ed25519.pub"

held=0
succeeded=0
results=()

# held <name> <artifact> <namespace> <keydir>
held() {
  local name="$1" artifact="$2" ns="$3" keydir="${4:-keys}" reason
  if ZAPHOD_KEY_DIR="$keydir" scripts/verify-artifact.sh "$artifact" "$ns" >/dev/null 2>"$work/err"; then
    results+=("FAIL  $name — the tampered artifact was accepted")
    succeeded=$((succeeded + 1))
  else
    reason="$(tail -1 "$work/err" | sed 's/^rejected: //')"
    results+=("held  $name — $reason")
    held=$((held + 1))
  fi
}

# mutate <source> <output> <jq expression>
mutate() {
  jq "$3" "$1" > "$2"
  cp "$1.sig" "$2.sig"
}

# ── the certificate ────────────────────────────────────────────────────────────

jq --arg fp "$attacker_fp" '.subject_fingerprint = $fp' cluster/certificate.json > "$work/cert-key.json"
cp cluster/certificate.json.sig "$work/cert-key.json.sig"
held "certificate: substitute the member key" "$work/cert-key.json" zaphod-certificate

mutate cluster/certificate.json "$work/cert-scope.json" '.scope += ["admin"]'
held "certificate: widen the scope to admin" "$work/cert-scope.json" zaphod-certificate

mutate cluster/certificate.json "$work/cert-expiry.json" '.not_after = 4102444800'
held "certificate: extend the expiry to 2100" "$work/cert-expiry.json" zaphod-certificate

mutate cluster/certificate.json "$work/cert-issuer.json" '.issuer = "acme-corporation"'
held "certificate: re-issue it as ACME" "$work/cert-issuer.json" zaphod-certificate

mutate cluster/certificate.json "$work/cert-subject.json" '.subject = "zaphod-base/edge-acme"'
held "certificate: add a member that was never admitted" "$work/cert-subject.json" zaphod-certificate

# ── the skills ─────────────────────────────────────────────────────────────────

mutate cluster/skills.json "$work/skills-promote.json" '.skills[3].rung = 3'
held "skills: promote an unverified skill to rung 3" "$work/skills-promote.json" zaphod-skills

mutate cluster/skills.json "$work/skills-add.json" \
  '.skills += [{"name":"zaphod/channel/admin","rung":3,"hops":0,"evidence":"asserted","certified_by":"zaphod-beeblebrox"}]'
held "skills: add a capability and certify it" "$work/skills-add.json" zaphod-skills

mutate cluster/skills.json "$work/skills-evidence.json" '.skills[0].evidence = "deterministic: because I say so"'
held "skills: rewrite the evidence" "$work/skills-evidence.json" zaphod-skills

# ── the key itself ─────────────────────────────────────────────────────────────

# A certificate ACME signed themselves, with a signers file that trusts their key.
jq '.not_after = 4102444800' cluster/certificate.json > "$work/cert-acme.json"
jq -S -c . "$work/cert-acme.json" > "$work/acme-msg"
ssh-keygen -Y sign -f "$work/acme" -n zaphod-certificate "$work/acme-msg" >/dev/null
cp "$work/acme-msg.sig" "$work/cert-acme.json.sig"
held "key: sign a widened certificate with ACME's own key" "$work/cert-acme.json" zaphod-certificate "$work/keydir-acme"

# ...and swap their public key in where zaphod's belongs, leaving the pin alone.
jq '.not_after = 4102444800' cluster/certificate.json > "$work/cert-swapped.json"
jq -S -c . "$work/cert-swapped.json" > "$work/swapped-msg"
ssh-keygen -Y sign -f "$work/acme" -n zaphod-certificate "$work/swapped-msg" >/dev/null
cp "$work/swapped-msg.sig" "$work/cert-swapped.json.sig"
held "key: swap the public key and leave the pin" "$work/cert-swapped.json" zaphod-certificate "$work/keydir-swapped"

# ── the suite has teeth ────────────────────────────────────────────────────────

for artifact_ns in "cluster/certificate.json:zaphod-certificate" "cluster/skills.json:zaphod-skills"; do
  artifact="${artifact_ns%%:*}"; ns="${artifact_ns##*:}"
  if scripts/verify-artifact.sh "$artifact" "$ns" >/dev/null 2>&1; then
    results+=("held  genuine $artifact still verifies — the refusals above mean something")
  else
    results+=("FAIL  genuine $artifact does not verify — this suite is passing for the wrong reason")
    succeeded=$((succeeded + 1))
  fi
done

printf '%s\n' "${results[@]}"
printf '\n%d attack(s) refused, %d accepted.\n' "$held" "$succeeded"
if [ "$succeeded" -ne 0 ]; then
  echo "RED TEAM SUCCEEDED — a mutated artifact was accepted" >&2
  exit 1
fi
echo "protection held: every tampered certificate and skill inventory was refused"
