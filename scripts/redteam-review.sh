#!/usr/bin/env bash
# Ask the red team for more attacks.
#
#   scripts/redteam-review.sh            print the request
#   scripts/redteam-review.sh --issue    post it as an issue (needs gh + a token)
#
# A corpus that stops growing is a corpus that has stopped looking. This asks, on a
# schedule, whether the adversary wants to add more — because the value of the suite
# is the questions it still has, not the ones it already answers.
set -euo pipefail
cd "$(dirname "$0")/.."

file="redteam/acme/attempts.json"
[ -f "$file" ] || { echo "no attempt corpus at $file" >&2; exit 1; }

refused="$(jq '.refused | length' "$file")"
succeeds="$(jq '.succeeds | length' "$file")"
wanted="$(jq '.wanted | length' "$file")"

body="$(
  printf 'The corpus currently holds **%s** attacks that must be refused and **%s** operations\n' "$refused" "$succeeds"
  printf 'that must succeed. %s categor%s not yet attempted. The suite also builds two\n' "$wanted" "$([ "$wanted" = "1" ] && echo y || echo ies)"
  printf 'cases at run time — a forged rotation, and a rewritten publication — so the\n'
  printf 'summary reads one higher than the corpus count.\n\n' 
  printf '## Wanted\n\n'
  jq -r '.wanted[] | "- [ ] \(.)"' "$file"
  printf '\n## Covered\n\n'
  jq -r '.refused[] | "- \(.name)"' "$file"
  printf '\n## Adding one\n\n'
  printf 'Add an entry to `refused` or `succeeds` in [`%s`](../blob/main/%s):\n\n' "$file" "$file"
  printf '```json\n{"name": "what it attempts", "artifact": "certificate|skills|isotopes|rotation|chain",\n'
  printf ' "jq": "mutation, or omit", "sign": "none|burned|own", "keydir": "keys|acme|swapped"}\n```\n\n'
  printf 'An attack that gets through is a red team success and a failing test, so the\n'
  printf 'corpus is expected to grow whenever something new becomes thinkable.\n\n'
  printf '_Asked on a schedule by `zaphod/channel/redteam-review`; see\n'
  printf '`docs/lane.md` for why the adversary is given every lawful advantage._\n'
)"

if [ "${1:-}" != "--issue" ]; then
  printf '%s\n' "$body"
  exit 0
fi

title="Red team: the corpus wants more attacks"
command -v gh >/dev/null || { echo "gh is required for --issue" >&2; exit 1; }
# Search by title is unreliable for punctuation, and a duplicate request every month
# is noise the skill would be generating on purpose. List and match exactly.
existing="$(gh issue list --state open --limit 100 --json number,title |
  jq -r --arg t "$title" '[.[] | select(.title == $t)][0].number // empty')"
if [ -n "$existing" ]; then
  # If the issue already says this, say nothing. A monthly job that adds an identical
  # comment is a skill generating noise on purpose.
  current="$(gh issue view "$existing" --json body,comments \
    -q '.body + "\n---\n" + ((.comments // []) | map(.body) | join("\n---\n"))')"
  case "$current" in
    *"$body"*)
      echo "issue #$existing is already current — nothing to add"
      exit 0
      ;;
  esac
  gh issue comment "$existing" --body "$body"
  echo "commented on #$existing"
else
  gh issue create --title "$title" --body "$body" --label redteam 2>/dev/null ||
    gh issue create --title "$title" --body "$body"
fi
