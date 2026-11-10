#!/usr/bin/env bash
# merge-step.sh <pr> <worktree> [<pr> <worktree> ...]: for each PR in order, merge origin/main into its worktree,
# push, wait for CI on that head, and squash-merge only if green and the head contains origin/main. Stops at the
# first PR that does not merge.
set -u
step() {
  n=$1; w=$2
  git -C "$w" fetch -q origin
  if ! git -C "$w" merge --no-edit -q origin/main >/dev/null 2>&1; then
    # Only docs/DECISIONS.md in conflict (two PRs appended D-rows): keep every row, ordered by number. Anything else stops.
    c=$(git -C "$w" diff --name-only --diff-filter=U)
    if [ "$c" = "docs/DECISIONS.md" ] && python3 "$(dirname "$0")/resolve_decisions.py" "$w/docs/DECISIONS.md" >/dev/null 2>&1 \
       && ! grep -q '^<<<<<<<' "$w/docs/DECISIONS.md"; then
      git -C "$w" add docs/DECISIONS.md && git -C "$w" commit -q --no-edit && echo "#$n DECISIONS conflict resolved"
    else
      echo "#$n merge conflict: $c"; git -C "$w" merge --abort; return 1
    fi
  fi
  # A merge (or resolve_decisions.py) must never delete a decision row that main has (D-143 was lost once, #156).
  # Amending a row is fine; losing one is not: every "| D-nn |" on main must still be in the branch.
  lost=$(comm -23 <(git -C "$w" show origin/main:docs/DECISIONS.md | grep -o '^| D-[0-9]*' | sort -u) \
                  <(grep -o '^| D-[0-9]*' "$w/docs/DECISIONS.md" | sort -u) | tr '\n' ' ')
  if [ -n "$lost" ]; then
    echo "#$n DECISIONS.md would drop rows that main has: $lost— stop"; return 1
  fi
  git -C "$w" push -q 2>/dev/null
  h=$(git -C "$w" rev-parse HEAD)
  for _ in $(seq 1 40); do
    c=$(gh pr view "$n" -R KNT048/vedette --json headRefOid -q .headRefOid)
    k=$(gh pr checks "$n" -R KNT048/vedette 2>/dev/null | wc -l | tr -d ' ')
    [ "$c" = "$h" ] && [ "$k" -gt 0 ] && break
    sleep 15
  done
  sleep 20
  # --watch can return early (network blips): wait until no check is pending, 45 min at most.
  for _ in $(seq 1 90); do
    gh pr checks "$n" -R KNT048/vedette --watch --interval 30 >/dev/null 2>&1
    gh pr checks "$n" -R KNT048/vedette 2>/dev/null | awk -F'\t' '{print $2}' | grep -q pending || break
    sleep 30
  done
  git -C "$w" fetch -q origin
  anc=$(git -C "$w" merge-base --is-ancestor origin/main "$h" && echo yes || echo no)
  st=$(gh pr checks "$n" -R KNT048/vedette 2>/dev/null | awk -F'\t' '{printf "%s:%s ", $1, $2}')
  echo "#$n head=$h main-included=$anc: $st"
  # main moved while CI ran: merge it again and wait once more (the caller retries on 2).
  if [ "$anc" = no ] && echo "$st" | grep -q 'go:pass' && echo "$st" | grep -q 'web:pass'; then echo "#$n main moved, retrying"; return 2; fi
  # Both required checks must have passed (an empty answer, e.g. no network, is not green).
  if [ "$anc" = yes ] && echo "$st" | grep -q 'go:pass' && echo "$st" | grep -q 'web:pass' && ! echo "$st" | grep -qE 'fail|pending'; then
    gh pr merge "$n" -R KNT048/vedette --squash --delete-branch=false --match-head-commit "$h" 2>&1 | tail -1
    s=$(gh pr view "$n" -R KNT048/vedette --json state,mergeCommit -q '.state+" "+(.mergeCommit.oid // "")')
    case "$s" in MERGED\ ?*) echo "MERGED #$n ${s#MERGED }" ;; *) echo "#$n NOT merged (state: ${s:-unknown})"; return 1 ;; esac
  else
    return 1
  fi
}
while [ $# -ge 2 ]; do
  for try in 1 2 3; do step "$1" "$2"; rc=$?; [ $rc -eq 2 ] || break; done
  [ $rc -eq 0 ] || exit 1
  shift 2
done
