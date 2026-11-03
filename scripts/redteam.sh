#!/usr/bin/env bash
# ACME's red team, as a test.
#
#   scripts/redteam.sh
#
# The attacks live in redteam/acme/attempts.json, which ACME owns: it can add
# attempts, change mutations, choose a signing key. The guard — the pinned
# fingerprint, cluster/allowed.txt, verify-artifact.sh, and CI — is not in that
# file, and that is the whole demonstration: an actor may change everything it
# owns and still stay in lane.
#
# Every attempt has to be *refused*. A passing run means the protection held; an
# accepted attempt is a red team success and a failing test, and the run ends by
# asking the isotope library where the cluster would now be on the 42i axis.
#
# The genuine artifacts are re-verified last. Without that the suite could pass
# because verification is broken in general — a red team that looks contained
# because nothing works.
set -euo pipefail
cd "$(dirname "$0")/.."

chmod 600 keys/id_ed25519 2>/dev/null || true

attempts_file="redteam/acme/attempts.json"
[ -f "$attempts_file" ] || { echo "no attempts file at $attempts_file" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The attacker: a fresh key, and a signers file that trusts it — what an attacker
# who can write the repository's trust files would produce.
ssh-keygen -q -t ed25519 -N '' -C 'acme-redteam' -f "$work/acme" >/dev/null
attacker_fp="$(ssh-keygen -lf "$work/acme.pub" | awk '{print $2}')"
mkdir -p "$work/keydir-acme" "$work/keydir-swapped"
cp keys/id_ed25519.pub keys/FINGERPRINT "$work/keydir-acme/"
printf 'zaphod-beeblebrox %s acme-redteam\n' "$(cat "$work/acme.pub")" > "$work/keydir-acme/allowed_signers"
cp keys/id_ed25519.pub keys/FINGERPRINT "$work/keydir-swapped/"
cp keys/allowed_signers "$work/keydir-swapped/"
cp "$work/acme.pub" "$work/keydir-swapped/id_ed25519.pub"

artifact_path() {
  case "$1" in
    certificate) echo "cluster/certificate.json:zaphod-certificate" ;;
    skills)      echo "cluster/skills.json:zaphod-skills" ;;
    isotopes)    echo "isotopes/zaphod-base.json:zaphod-isotopes" ;;
    *)           echo "" ;;
  esac
}

sign_with() { # <file-under-work> <mode> <namespace> <keydir>
  local file="$1" mode="$2" ns="$3" keydir="$4" key
  case "$mode" in
    none)   cp "$file.base.sig" "$file.sig" 2>/dev/null || true ;;
    burned) key="keys/id_ed25519" ;;
    own)    key="$work/acme" ;;
    *)      echo "unknown sign mode: $mode" >&2; return 1 ;;
  esac
  if [ "$mode" != "none" ]; then
    jq -S -c . "$file" > "$file.msg"
    ssh-keygen -Y sign -f "$key" -n "$ns" "$file.msg" >/dev/null
    cp "$file.msg.sig" "$file.sig"
  fi
  return 0
}

held=0
accepted=0
results=()

# ACME's list, one attempt at a time. Owned by the actor; nothing here is the guard.
# No policy gate. The model grants ACME the burned key — it is published, so using
# it is lawful — and anything it can do with it is in scope. An attack may only fail
# on mathematics.
count="$(jq '.refused | length' "$attempts_file")"
i=0
while [ "$i" -lt "$count" ]; do
  name="$(jq -r ".refused[$i].name" "$attempts_file")"
  artifact="$(jq -r ".refused[$i].artifact" "$attempts_file")"
  expr="$(jq -r ".refused[$i].jq // empty" "$attempts_file")"
  mode="$(jq -r ".refused[$i].sign" "$attempts_file")"
  keydir_name="$(jq -r ".refused[$i].keydir // \"keys\"" "$attempts_file")"
  i=$((i + 1))

  case "$keydir_name" in
    keys)    keydir="keys" ;;
    acme)    keydir="$work/keydir-acme" ;;
    swapped) keydir="$work/keydir-swapped" ;;
    *)       keydir="$keydir_name" ;;
  esac

  target="$work/attempt-$i.json"
  if [ "$artifact" = "chain" ]; then
    # ACME's faithful recreation: a whole rotation corpus with its own identity,
    # its own receipts, every record correctly signed, and a consistent lock. It
    # is a different chain — which is exactly what the receipt head catches.
    chain_dir="$work/attempt-$i-chain"
    mkdir -p "$chain_dir"
    . scripts/lib-receipt.sh
    acme_fp="$(ssh-keygen -lf "$work/acme.pub" | awk '{print $2}')"
    zaphod_fp="$(awk '{print $2}' keys/FINGERPRINT)"
    zaphod_pub="$(cat keys/id_ed25519.pub)"
    prev="genesis"
    for seq in 0 1; do
      # seq 0: ACME to ACME. seq 1: ACME to zaphod's current key, so the chain
      # ends where keys/ ends and every structural check passes. Only the receipt
      # can tell this chain from the one that was reviewed.
      to_fp="$acme_fp"; to_pub="$(cat "$work/acme.pub")"
      if [ "$seq" = "1" ]; then to_fp="$zaphod_fp"; to_pub="$zaphod_pub"; fi
      rec="$chain_dir/$(printf '%03d-acme.json' "$seq")"
      jq -n --argjson seq "$seq" --arg from "$acme_fp" --arg from_pub "$(cat "$work/acme.pub")" \
        --arg to "$to_fp" --arg to_pub "$to_pub" --arg at "$(date -u +%FT%TZ)" \
        '{version: 1, seq: $seq, cluster: "zaphod-base", from: $from, from_pub: $from_pub,
          to: $to, to_pub: $to_pub, at: $at, reason: "acme"}' > "$rec"
      r="$(receipt_for "$rec" "$prev")"
      jq --arg r "$r" '. + {receipt: $r}' "$rec" > "$rec.tmp" && mv "$rec.tmp" "$rec"
      jq -S -c . "$rec" > "$rec.msg"
      ssh-keygen -Y sign -f "$work/acme" -n zaphod-rotation "$rec.msg" >/dev/null
      cp "$rec.msg.sig" "$rec.sig"
      prev="$r"
    done
    if ZAPHOD_ROTATIONS="$chain_dir" scripts/rotation-verify.sh >/dev/null 2>"$work/err"; then
      results+=("FAIL  $name — ACCEPTED (red team success)"); accepted=$((accepted + 1))
    else
      results+=("held  $name — $(tail -1 "$work/err")"); held=$((held + 1))
    fi
    continue
  fi

  if [ "$artifact" = "rotation" ]; then
    # A rotation to ACME's key, signed by ACME. Correctly formed, and not the
    # chain that was reviewed.
    last="$(ls cluster/rotations/*.json | sort | tail -1)"
    jq -n \
      --argjson seq $(( $(jq -r .seq "$last") + 1 )) \
      --arg from "$(awk '{print $2}' keys/FINGERPRINT)" \
      --arg from_pub "$(cat keys/id_ed25519.pub)" \
      --arg to "$attacker_fp" --arg to_pub "$(cat "$work/acme.pub")" \
      --arg at "$(date -u +%FT%TZ)" \
      '{version: 1, seq: $seq, cluster: "zaphod-base", from: $from, from_pub: $from_pub,
        to: $to, to_pub: $to_pub, at: $at, reason: "acme"}' > "$target"
    ns="zaphod-rotation"
  else
    spec="$(artifact_path "$artifact")"
    [ -n "$spec" ] || { results+=("SKIP  $name — unknown artifact $artifact"); continue; }
    base="$(printf '%s' "$spec" | cut -d: -f1)"
    ns="$(printf '%s' "$spec" | cut -d: -f2)"
    cp "$base" "$target"
    cp "$base.sig" "$target.base.sig"
    [ -z "$expr" ] || jq "$expr" "$base" > "$target"
  fi

  sign_with "$target" "$mode" "$ns" "$keydir"

  if ZAPHOD_KEY_DIR="$keydir" scripts/verify-artifact.sh "$target" "$ns" >/dev/null 2>"$work/err"; then
    results+=("FAIL  $name — ACCEPTED (red team success)")
    accepted=$((accepted + 1))
  else
    results+=("held  $name — $(tail -1 "$work/err" | sed 's/^rejected: //')")
    held=$((held + 1))
  fi
done

# The suite has teeth: the genuine artifacts must still verify.
for artifact_ns in "cluster/certificate.json:zaphod-certificate" "cluster/skills.json:zaphod-skills" "isotopes/zaphod-base.json:zaphod-isotopes"; do
  artifact="${artifact_ns%%:*}"; ns="${artifact_ns##*:}"
  if scripts/verify-artifact.sh "$artifact" "$ns" >/dev/null 2>&1; then
    results+=("held  genuine $artifact still verifies — the refusals above mean something")
  else
    results+=("FAIL  genuine $artifact does not verify — this suite is passing for the wrong reason")
    accepted=$((accepted + 1))
  fi
done

# ── ACME's own operations, which must succeed ──────────────────────────────────
# A guard that only ever says no is indistinguishable from a broken guard, and a
# red team that never does anything competently is not a red team. ACME rotates its
# own key, extends its own chain, verifies its own cluster and signs with its own
# key — on the first attempt. The claim was never that it cannot act.
acme_cluster="$work/acme-cluster"
cp -R . "$acme_cluster"
ssh-keygen -q -t ed25519 -N '' -C "acme-redteam DO NOT USE" -f "$work/acme-own-key" >/dev/null
succeeded=0
s_count="$(jq '.succeeds | length' "$attempts_file")"
i=0
while [ "$i" -lt "$s_count" ]; do
  name="$(jq -r ".succeeds[$i].name" "$attempts_file")"
  action="$(jq -r ".succeeds[$i].action" "$attempts_file")"
  i=$((i + 1))
  case "$action" in
    rotate)
      # ACME's own identity, for ACME's own cluster. It is entitled to one, and
      # holding it is what lets it rotate its own key on the first attempt.
      ZAPHOD_IDENTITY_FILE="$work/acme-identity" scripts/identity.sh init >/dev/null 2>&1 || true
      if ( cd "$acme_cluster" && ZAPHOD_IDENTITY_FILE="$work/acme-identity" \
             scripts/rotate.sh --reason "acme operating its own cluster" \
             --new-key "$work/acme-own-key" > "$work/op" 2>&1 ); then
        acme_head="$(awk '$2 == "receipt" {print $1}' "$acme_cluster/cluster/allowed.txt")"
        zaphod_head="$(awk '$2 == "receipt" {print $1}' cluster/allowed.txt)"
        if [ -n "$acme_head" ] && [ "$acme_head" != "$zaphod_head" ]; then
          results+=("ok    $name — accepted on the first attempt; its own head, not zaphod's")
          succeeded=$((succeeded + 1))
        else
          results+=("FAIL  $name — the rotation produced zaphod's head, which it cannot")
          accepted=$((accepted + 1))
        fi
      else
        results+=("FAIL  $name — ACME cannot operate its own cluster: $(tail -1 "$work/op")")
        accepted=$((accepted + 1))
      fi
      ;;
    extend)
      if ( cd "$acme_cluster" && ZAPHOD_IDENTITY_FILE="$work/acme-identity" \
             scripts/rotate.sh --reason "acme content update" > "$work/op" 2>&1 ); then
        results+=("ok    $name — accepted; the chain grew by one")
        succeeded=$((succeeded + 1))
      else
        results+=("FAIL  $name — $(tail -1 "$work/op")")
        accepted=$((accepted + 1))
      fi
      ;;
    verify)
      if ( cd "$acme_cluster" && scripts/cluster-verify.sh > "$work/op" 2>&1 ); then
        results+=("ok    $name — verifies under ACME's own pin")
        succeeded=$((succeeded + 1))
      else
        results+=("FAIL  $name — $(tail -1 "$work/op")")
        accepted=$((accepted + 1))
      fi
      ;;
    sign)
      if ( cd "$acme_cluster" && scripts/verify-note.sh sign kb/reading-list.md > "$work/op" 2>&1 &&
           scripts/verify-note.sh verify kb/reading-list.md >> "$work/op" 2>&1 ); then
        results+=("ok    $name — signed and verified with its own key")
        succeeded=$((succeeded + 1))
      else
        results+=("FAIL  $name — $(tail -1 "$work/op")")
        accepted=$((accepted + 1))
      fi
      ;;
  esac
done

# ── set up to lose: everything legal, and the rotation still fails ────────────
# ACME is given what a lawful actor could have: the repository, the burned signing
# key, the tooling, and a proxy position. It produces a rotation that is correct in
# every respect a third party can check — signatures, public receipt chain, a
# coherent lock. The cluster refuses it on arithmetic, because the attestation is
# the one thing the repository never held.
identity="$work/zaphod-identity"
ZAPHOD_IDENTITY_FILE="$identity" scripts/identity.sh init >/dev/null
genuine="$work/genuine-rotation.json"
jq -n '{version: 1, seq: 9, cluster: "zaphod-base", from: "SHA256:a", from_pub: "ssh-ed25519 a",
        to: "SHA256:b", to_pub: "ssh-ed25519 b", at: "2026-11-03T00:00:00Z", reason: "genuine"}' > "$genuine"
r="$(receipt_for "$genuine" genesis)"
jq --arg r "$r" '. + {receipt: $r}' "$genuine" > "$genuine.tmp" && mv "$genuine.tmp" "$genuine"
a="$(ZAPHOD_IDENTITY_FILE="$identity" scripts/identity.sh attest "$genuine" genesis)"
jq --arg a "$a" '. + {attestation: $a}' "$genuine" > "$genuine.tmp" && mv "$genuine.tmp" "$genuine"
if ZAPHOD_IDENTITY_FILE="$identity" scripts/identity.sh verify "$genuine" genesis >/dev/null 2>&1; then
  results+=("ok    rotation: the identity's own attestation — accepted, as it must be")
  succeeded=$((succeeded + 1))
else
  results+=("FAIL  rotation: the identity cannot verify its own attestation")
  accepted=$((accepted + 1))
fi

jq '.to = "SHA256:acme-target"' "$genuine" > "$work/forged-rotation.json"
if ZAPHOD_IDENTITY_FILE="$identity" scripts/identity.sh verify "$work/forged-rotation.json" genesis \
     >"$work/forged" 2>&1; then
  results+=("FAIL  rotation: forged with everything legal — ACCEPTED (red team success)")
  accepted=$((accepted + 1))
else
  results+=("held  rotation: forged with the repository, the key and the tooling — $(tail -1 "$work/forged" | sed 's/^rejected: //')")
  held=$((held + 1))
fi

# ── the repository is not the authority ───────────────────────────────────────
# ACME rewrites the whole publication with the burned key: a widened certificate,
# a fresh signature, a rewritten lock. Every check a third party can run against the
# repository passes, because the repository is self-consistent. The cluster refuses
# it, because the cluster's own attested state names the artifacts it published.
gate_repo="$work/gate-repo"
cp -R . "$gate_repo"
gate_id="$work/gate-identity.secret"
(
  cd "$gate_repo"
  export ZAPHOD_IDENTITY_FILE="$gate_id"
  export ZAPHOD_STATE_FILE="$work/gate-state.json"
  scripts/identity.sh init >/dev/null
  scripts/rotate.sh --reason "cluster attests its own publication" >/dev/null 2>&1
  # The rewrite: content changed, re-signed with the key in the tree, lock rebuilt.
  jq '.scope += ["admin"]' cluster/certificate.json > t && mv t cluster/certificate.json
  scripts/sign-artifact.sh cluster/certificate.json zaphod-certificate >/dev/null 2>&1
  scripts/allowed.sh --write >/dev/null
  if ! scripts/cluster-verify.sh >/dev/null 2>&1; then
    echo "note: the rewritten corpus is not even self-consistent; the case is weaker than intended" >&2
  fi
  if ZAPHOD_IDENTITY_FILE="$gate_id" ZAPHOD_STATE_FILE="$work/gate-state.json" \
       scripts/cluster-gate.sh > "$work/gate" 2>&1; then
    echo "FAIL  publication: rewritten with the signing key — ACCEPTED (red team success)"
    exit 1
  fi
  grep -q "not the version this cluster attested" "$work/gate" || {
    echo "FAIL  publication: refused for the wrong reason: $(tail -1 "$work/gate")"
    exit 1
  }
) && {
  results+=("held  publication: rewritten corpus, self-consistent, with the signing key — $(tail -1 "$work/gate" | sed 's/^gate rejected: //')")
  held=$((held + 1))
} || {
  results+=("FAIL  publication: the rewritten corpus was accepted")
  accepted=$((accepted + 1))
}

printf '%s\n' "${results[@]}"
printf '\n%d attack(s) refused, %d accepted; %d ACME operation(s) succeeded.\n' \
  "$held" "$accepted" "$succeeded"

# Where the cluster would be, in the library's own terms.
if command -v go >/dev/null 2>&1; then
  echo
  go run ./cmd/isotope42 drift --accepted "$accepted"
fi

if [ "$accepted" -ne 0 ]; then
  echo "RED TEAM SUCCEEDED — an attempted change was accepted" >&2
  exit 1
fi
echo "protection held: ACME changed everything it owns, and the guard refused all of it"
