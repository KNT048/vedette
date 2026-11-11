#!/usr/bin/env bash
# Mutation runs on the risky paths of logs L1. One behaviour broken at a time in the committed source; the package tests run;
# the tests that go red are listed; the file is restored with git checkout. Logs: ~/agents/feat-logs-module/mut-<id>.log.
# Run under ONE heavy hold:   heavy bash mutate.sh
set -u
cd ~/src/vedette-wt/logs-module
D=~/agents/feat-logs-module
SUMMARY=$D/mut-summary${SUFFIX:-}.log
: > "$SUMMARY"
if ! git diff --quiet; then echo "working tree not clean: commit first" | tee -a "$SUMMARY"; exit 2; fi

run_tests() { go test -count=1 -timeout 90s ./modules/logs/ 2>&1; }

base=$(run_tests)
echo "$base" > "$D/mut-00-baseline.log"
if echo "$base" | grep -q "^FAIL\|^--- FAIL"; then echo "BASELINE RED, stop" | tee -a "$SUMMARY"; exit 3; fi
echo "baseline: green" | tee -a "$SUMMARY"

# id | file | perl substitution (applied with -0777) | what it breaks
mutate() {
  [[ -n "${ONLY:-}" && ! "$1" =~ $ONLY ]] && return
  local id=$1 file=$2 expr=$3 what=$4 log=$D/mut-$1.log
  perl -0777 -pi -e "$expr" "$file"
  if git diff --quiet -- "$file"; then
    echo "$id NOT APPLIED ($what)" | tee -a "$SUMMARY"; return
  fi
  { echo "### $id: $what"; echo "### diff:"; git diff -U0 -- "$file" | grep '^[-+][^-+]'; echo "### test output:"; } > "$log"
  out=$(run_tests)
  echo "$out" >> "$log"
  git checkout -q -- "$file"
  if echo "$out" | grep -q "build failed\|\[setup failed\]"; then
    echo "$id BUILD BROKEN, mutation invalid ($what)" | tee -a "$SUMMARY"; return
  fi
  names=$(echo "$out" | grep -E '^--- FAIL' | sed -E 's/^--- FAIL: ([A-Za-z0-9_]+).*/\1/' | sort -u | tr '\n' ' ')
  n=$(echo "$out" | grep -cE '^--- FAIL|^panic: test timed out')
  if [ "$n" -eq 0 ]; then echo "$id SURVIVED (no test red): $what" | tee -a "$SUMMARY"
  else echo "$id KILLED by $n test(s) [$names]: $what" | tee -a "$SUMMARY"; fi
}

I=modules/logs/ingest.go; E=modules/logs/events.go; P=modules/logs/purge.go; S=modules/logs/service.go; X=modules/logs/export.go; V=modules/logs/migrations/volume/0001_logs_volume.sql

# ---- sanitizeLine (M1: unicode Cc, Cf, Zl, Zp except tab)
mutate sanitize-no-Cc $I 's/unicode.In\(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp\)/unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)/' "controls (C0, DEL 0x7f, C1 incl. NEL) no longer stripped"
mutate sanitize-no-Cf $I 's/unicode.In\(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp\)/unicode.In(r, unicode.Cc, unicode.Zl, unicode.Zp)/' "format characters (bidi, zero-width, BOM, soft hyphen) no longer stripped"
mutate sanitize-no-Zl-Zp $I 's/unicode.In\(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp\)/unicode.In(r, unicode.Cc, unicode.Cf)/' "U+2028 and U+2029 line separators no longer stripped"
mutate sanitize-tab-too $I 's/return r != .\\t. && unicode.In/return unicode.In/' "tab no longer allowed (control check without the tab exception)"
mutate sanitize-length $I 's/if len\(s\) <= MaxLineBytes \{/if len(s) <= MaxLineBytes*4 {/' "length cap raised from 2048 to 8192 bytes"
mutate sanitize-boundary $I 's/for cut > 0 && !utf8.RuneStart\(s\[cut\]\) \{/for cut > 0 \&\& !utf8.RuneStart(s[cut]) \&\& cut < 0 {/' "a long line is cut in the middle of a character"
mutate sanitize-utf8 $I 's/s = strings.ToValidUTF8\(s, "[^"]*"\)/_ = strings.ToValidUTF8/' "invalid UTF-8 is kept"

# ---- the events query
mutate events-like-wildcards $E 's/cond := "instr\(lower\(line\), \?\) > 0"\n\t\targs = append\(args, needle\)/cond := "lower(line) LIKE ?"\n\t\targs = append(args, "%"+needle+"%")/' "keyword matched with LIKE: % and _ become wildcards"
mutate events-source-concat $E 's/where \+= " AND source_id = \?"\n\t\targs = append\(args, q.Source\)/where += " AND source_id = \x27" + q.Source + "\x27"/' "the source filter is concatenated into the SQL, not bound"
mutate events-case-ascii-vs-unicode $E 's/needle := asciiLower\(/needle := strings.ToLower(/' "keyword folded with Go's Unicode lowercasing (M5: SQLite folds ASCII only)"
mutate events-case-none $E 's/needle := asciiLower\(strings.TrimSpace\(q.Q\)\)/needle := strings.TrimSpace(q.Q)/' "keyword search no longer case-insensitive"
mutate events-or-parentheses $E 's/where \+= " AND \(" \+ cond \+ "\)"/where += " AND " + cond/' "no parentheses around the keyword OR: a source-name match ignores the window and the source filter"
mutate events-source-filter $E 's/if q.Source != "" \{/if false \&\& q.Source != "" {/' "source filter ignored"
mutate events-window $E 's/where, args := "ts >= \?", \[\]any\{store.FormatTS\(s.now\(\).Add\(-span\)\)\}/where, args := "ts >= ?", []any{store.FormatTS(s.now().Add(-span * 4))}/' "time window four times too wide"
mutate events-window-clamp $E 's/span = keep/span = keep \/ 2/' "window clamp to the retention changed (equivalent: retention >= 7 d and window <= 7 d)"
mutate events-no-timeout $E 's/context.WithTimeout\(ctx, s.searchTimeout\)/context.WithTimeout(ctx, time.Hour)/' "a search has no 5 s deadline"
mutate events-no-concurrency-cap $S 's/searchSem: make\(chan struct\{\}, MaxSearches\)/searchSem: make(chan struct{}, 1000)/' "any number of searches at once"
mutate events-busy-not-mapped $E 's/errors.Is\(err, context.DeadlineExceeded\)/errors.Is(err, context.Canceled)/' "a search that hits its deadline answers a raw error, not 503 server_busy"

# ---- Ingest
mutate ingest-unknown-sender $I 's/if !known\[l.SourceID\] \{/if !known[l.SourceID] \&\& l.SourceID == "" {/' "lines of an undeclared source are stored"
mutate ingest-batch-limit $I 's/len\(lines\) > MaxBatch/len(lines) > MaxBatch*10/' "batch limit raised tenfold"
mutate ingest-future-clamp $I 's/if l.At.IsZero\(\) \|\| l.At.After\(now\) \{/if l.At.IsZero() {/' "a timestamp in the future is kept"
mutate ingest-writes-core-db $I 's/err = s.cfg.Volume.Write\(ctx, func\(tx \*sql.Tx\) error \{\n\t\tins/err = s.cfg.Config.Write(ctx, func(tx *sql.Tx) error {\n\t\tins/' "ingest writes the main database instead of logs.db"
mutate ids-reused $V 's/ AUTOINCREMENT,/,/' "the line id is not AUTOINCREMENT: ids are reused after a purge"

# ---- purge
mutate purge-boundary $P 's/WHERE ts < \? ORDER BY ts, id LIMIT/WHERE ts <= ? ORDER BY ts, id LIMIT/' "a line exactly at the retention boundary is purged"
mutate purge-retention-days $P 's/time.Duration\(days\) \* 24 \* time.Hour\)\)\n\tvar expired/time.Duration(days) * 23 * time.Hour))\n\tvar expired/' "retention counted as 23 hours a day"
mutate purge-cap-off $P 's/if over \{/if false {/' "the cap on stored lines is not enforced"
mutate purge-cap-off-by-one $P 's/newest.Int64-s.maxEvents\); err != nil/newest.Int64-s.maxEvents-1); err != nil/' "the cap keeps one line too many"
mutate purge-chunk-size $S 's/chunk: purgeChunk,/chunk: purgeChunk * 1000,/' "one transaction deletes everything instead of 10,000 rows"
mutate purge-stops-after-first-chunk $P 's/if n < int64\(s.chunk\) \{/if true {/' "deleteChunks returns after the first chunk"
mutate purge-ctx-ignored $P 's/\t\tif err := ctx.Err\(\); err != nil \{\n\t\t\treturn total, err\n\t\t\}\n\t\tvar n int64\n\t\terr := s.cfg.Volume.Write\(ctx,/\t\tvar n int64\n\t\terr := s.cfg.Volume.Write(context.Background(),/' "purge ignores a cancelled context"
mutate purge-ctx-check-removed $P 's/\t\tif err := ctx.Err\(\); err != nil \{\n\t\t\treturn total, err\n\t\t\}\n\t\tvar n int64/\t\tvar n int64/' "the ctx.Err check of deleteChunks removed (Write still honours ctx, but the context error is then wrapped)"
mutate purge-dropstale-all $P 's/if len\(ids\) > 0 \{/if false {/' "dropStale deletes every last-received mark, also those of sources that exist"
mutate purge-audit-only-expired $P 's/if res.Expired\+res.Over == 0 \{/if res.Expired == 0 {/' "no end audit row when only the cap removed lines"
mutate purge-audit-started-always $P 's/if expired > 0 \|\| over \{/if true {/' "a purge with nothing to delete still writes audit rows"
mutate purge-audit-never $P 's/if expired > 0 \|\| over \{/if false {/' "a purge that deletes lines writes no audit row"
mutate purge-audit-needs-live-ctx $P 's/context.WithTimeout\(context.WithoutCancel\(ctx\), 10\*time.Second\)/context.WithTimeout(ctx, 10*time.Second)/' "the end audit row uses the purge's own context: lost when the purge is cancelled"

# ---- guards and export
mutate guard-two-databases $S 's/if cfg.Config == cfg.Volume \{/if false {/' "NewService accepts the main database as the volume"
mutate export-inclusive $X 's/ts >= \? AND ts <= \?/ts > ? AND ts < ?/' "export range excludes both ends"
mutate export-open-end $X 's/"9999-12-31T23:59:59.999Z"/"2000-01-01T00:00:00.000Z"/' "an open upper end of the export range stops in 2000"
mutate export-order $X 's/ORDER BY id`/ORDER BY id DESC`/' "export newest first instead of oldest first"

# D-151: a migration of logs.db that is not add-only must turn TestVolumeMigrationsAreAddOnly red; an add-only one must not.
tmpmig() {
  local id=$1 body=$2 expect=$3 f=modules/logs/migrations/volume/0002_tmp_$1.sql log=$D/mut-$1.log
  printf -- '-- +goose Up\n%s\n' "$body" > "$f"
  { echo "### $id: temporary migration $f"; cat "$f"; echo "### test output:"; } > "$log"
  out=$(run_tests)
  echo "$out" >> "$log"
  rm -f "$f"
  n=$(echo "$out" | grep -cE '^--- FAIL|^panic: test timed out')
  names=$(echo "$out" | grep -E '^--- FAIL' | sed -E 's/^--- FAIL: ([A-Za-z0-9_]+).*/\1/' | sort -u | tr '\n' ' ')
  if [ "$expect" = red ] && [ "$n" -gt 0 ]; then echo "$id KILLED by $n test(s) [$names]: D-151 guard works" | tee -a "$SUMMARY"
  elif [ "$expect" = green ] && [ "$n" -eq 0 ]; then echo "$id PASSES as it should (add-only migration accepted)" | tee -a "$SUMMARY"
  else echo "$id UNEXPECTED (expected $expect, $n failures [$names])" | tee -a "$SUMMARY"; fi
}
tmpmig d151-drop-table 'DROP TABLE logs_source_seen;' red
tmpmig d151-rename-column 'ALTER TABLE logs_events RENAME COLUMN line TO text;' red
tmpmig d151-drop-column 'ALTER TABLE logs_events DROP COLUMN line;' red
tmpmig d151-delete-rows 'DELETE FROM logs_events;' red
tmpmig d151-add-column 'ALTER TABLE logs_events ADD COLUMN src_ip TEXT;' green

echo "--- done" | tee -a "$SUMMARY"
git status --short | tee -a "$SUMMARY"
