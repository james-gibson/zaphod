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
count="$(jq '.attempts | length' "$attempts_file")"
i=0
while [ "$i" -lt "$count" ]; do
  name="$(jq -r ".attempts[$i].name" "$attempts_file")"
  artifact="$(jq -r ".attempts[$i].artifact" "$attempts_file")"
  expr="$(jq -r ".attempts[$i].jq // empty" "$attempts_file")"
  mode="$(jq -r ".attempts[$i].sign" "$attempts_file")"
  keydir_name="$(jq -r ".attempts[$i].keydir // \"keys\"" "$attempts_file")"
  i=$((i + 1))

  case "$keydir_name" in
    keys)    keydir="keys" ;;
    acme)    keydir="$work/keydir-acme" ;;
    swapped) keydir="$work/keydir-swapped" ;;
    *)       keydir="$keydir_name" ;;
  esac

  target="$work/attempt-$i.json"
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

printf '%s\n' "${results[@]}"
printf '\n%d attack(s) refused, %d accepted.\n' "$held" "$accepted"

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
