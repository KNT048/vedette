#!/usr/bin/env bash
# merge-step.sh <pr> <worktree> [<pr> <worktree> ...]: for each PR in order, wait for its CI, then hand it to GitHub's
# merge queue (D-245) and wait until GitHub merges it or drops it from the queue. The worktree HEAD is pushed to the PR branch first. Stops at the first PR that does not merge.
# The queue tests the PR merged onto main (and the PRs ahead of it), so nobody chases main here any more: main is merged
# into the branch only when GitHub reports a conflict. Exit 0 = all merged, 1 = one did not, 3 = already running for a PR.
set -u
R=KNT048/vedette
q() { gh api graphql -f query="query{repository(owner:\"KNT048\",name:\"vedette\"){pullRequest(number:$1){state isInMergeQueue autoMergeRequest{enabledAt} mergeQueueEntry{state position} mergeCommit{oid}}}}" \
      -q '.data.repository.pullRequest | "\(.state) \(.isInMergeQueue) \(.autoMergeRequest != null) \(.mergeQueueEntry.state // "-") \(.mergeQueueEntry.position // "-") \(.mergeCommit.oid // "")"' 2>/dev/null; }
step() {
  n=$1; w=$2
  git -C "$w" fetch -q origin
  m=UNKNOWN; for _ in 1 2 3 4 5 6; do m=$(gh pr view "$n" -R $R --json mergeable -q .mergeable 2>/dev/null); [ "$m" = UNKNOWN ] || break; sleep 10; done
  if [ "$m" = CONFLICTING ]; then
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
    if [ -n "$lost" ]; then echo "#$n DECISIONS.md would drop rows that main has: $lost— stop"; return 1; fi
  fi
  # Push to the PR's own branch by name: a worktree's local branch often has another name and no upstream.
  b=$(gh pr view "$n" -R $R --json headRefName -q .headRefName)
  [ -n "$b" ] && git -C "$w" push -q origin "HEAD:refs/heads/$b" 2>/dev/null
  h=$(git -C "$w" rev-parse HEAD)
  for _ in $(seq 1 40); do
    c=$(gh pr view "$n" -R $R --json headRefOid -q .headRefOid)
    k=$(gh pr checks "$n" -R $R 2>/dev/null | wc -l | tr -d ' ')
    [ "$c" = "$h" ] && [ "$k" -gt 0 ] && break
    sleep 15
  done
  [ "$c" = "$h" ] || { echo "#$n: GitHub head $c is not the worktree head $h (unpushed commits?)"; return 1; }
  sleep 20
  # --watch can return early (network blips): wait until no check is pending, 45 min at most.
  for _ in $(seq 1 90); do
    gh pr checks "$n" -R $R --watch --interval 30 >/dev/null 2>&1
    gh pr checks "$n" -R $R 2>/dev/null | awk -F'\t' '{print $2}' | grep -q pending || break
    sleep 30
  done
  st=$(gh pr checks "$n" -R $R 2>/dev/null | awk -F'\t' '{printf "%s:%s ", $1, $2}')
  echo "#$n head=$h: $st"
  # Both required checks must have passed (an empty answer, e.g. no network, is not green).
  echo "$st" | grep -q 'go:pass' && echo "$st" | grep -q 'web:pass' && ! echo "$st" | grep -qE 'fail|pending' || return 1
  gh pr merge "$n" -R $R --squash --match-head-commit "$h" 2>&1 | tail -1
  # The queue reruns CI on the merged result (~12 min, longer behind other PRs): wait up to 90 min.
  for _ in $(seq 1 180); do
    s=$(q "$n"); set -- $s
    case "${1:-}" in
      MERGED) echo "MERGED #$n ${6:-}"; return 0 ;;
      CLOSED) echo "#$n closed without merging"; return 1 ;;
      OPEN) [ "$2" = true ] || [ "$3" = true ] || { echo "#$n left the merge queue unmerged (its merge_group CI failed or it conflicted): see gh run list -R $R --event merge_group"; return 1; } ;;
    esac
    sleep 30
  done
  echo "#$n still not merged after 90 min (queue: $(q "$n"))"; return 1
}
# One merge-step per PR at a time (two runs on one worktree race each other's merge and push).
L=${MERGE_LOCK_DIR:-$HOME/.cache/vedette-merge-lock}; mkdir -p "$L"; prs=()
for ((i=1; i<=$#; i+=2)); do
  n=${!i}; f="$L/$n.pid"
  if [ -f "$f" ] && kill -0 "$(cat "$f")" 2>/dev/null; then echo "#$n: merge-step already running (pid $(cat "$f")); not starting another"; exit 3; fi
  echo $$ > "$f"; prs+=("$n")
done
trap 'for n in "${prs[@]}"; do [ "$(cat "$L/$n.pid" 2>/dev/null)" = "$$" ] && rm -f "$L/$n.pid"; done' EXIT
while [ $# -ge 2 ]; do
  step "$1" "$2" || exit 1
  shift 2
done
