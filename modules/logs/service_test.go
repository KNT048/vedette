package logs

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

var t0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

type fakeInv struct{ byIP map[string]Device }

func (f fakeInv) DevicesByIP(_ context.Context, ips []string) (map[string]Device, error) {
	out := map[string]Device{}
	for _, ip := range ips {
		if d, ok := f.byIP[ip]; ok {
			out[ip] = d
		}
	}
	return out, nil
}

type env struct {
	t     *testing.T
	cfg   *store.DB // the main database: core tables + the logs configuration
	vol   *store.DB // logs.db
	svc   *Service
	clock *time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg, vol := storetest.New(t), storetest.New(t)
	for _, m := range []struct {
		name string
		fs   func() error
	}{
		{"core", func() error { return store.Migrate(t.Context(), cfg, "core", core.Migrations) }},
		{"logs config", func() error { return store.Migrate(t.Context(), cfg, "logs", ConfigMigrations) }},
		{"logs volume", func() error { return store.Migrate(t.Context(), vol, "logs", VolumeMigrations) }},
	} {
		if err := m.fs(); err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
	}
	e := &env{t: t, cfg: cfg, vol: vol, clock: new(time.Time)}
	*e.clock = t0
	svc, err := NewService(Config{Config: cfg, Volume: vol, Audit: audit.New(func() time.Time { return *e.clock }), Log: slog.New(slog.DiscardHandler),
		Inventory: fakeInv{byIP: map[string]Device{"192.168.10.1": {ID: "a-fw", Name: "FW-HQ"}}}, Clock: func() time.Time { return *e.clock }})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func (e *env) advance(d time.Duration) { *e.clock = e.clock.Add(d) }

func (e *env) add(name, ip string) Source {
	e.t.Helper()
	s, err := e.svc.AddSource(e.t.Context(), "admin@acme.example", Input{Kind: "fortigate", Name: name, SenderIP: ip, Proto: "udp", Port: 514})
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func count(t *testing.T, db *store.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func code(err error) string {
	var ae *apierr.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func lines(source string, at time.Time, texts ...string) []Line {
	out := make([]Line, len(texts))
	for i, s := range texts {
		out[i] = Line{SourceID: source, At: at, Text: s}
	}
	return out
}

func TestMigrationsUsePrefixAndAreSeparate(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "logs", ConfigMigrations, "logs_", storetest.Migration{Module: "core", FS: core.Migrations})
	storetest.AssertMigrationsUsePrefix(t, "logs", VolumeMigrations, "logs_")
	e := newEnv(t)
	if count(t, e.cfg, `SELECT count(*) FROM sqlite_master WHERE name IN ('logs_events', 'logs_source_buckets', 'logs_source_seen')`) != 0 {
		t.Fatal("the volume tables are in the main database")
	}
	if count(t, e.vol, `SELECT count(*) FROM sqlite_master WHERE name IN ('logs_sources', 'logs_retention')`) != 0 {
		t.Fatal("the configuration tables are in logs.db")
	}
}

func TestNewServiceRefusesTheMainDatabaseAsTheVolume(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := NewService(Config{Config: e.cfg, Volume: e.cfg, Audit: audit.New(nil), Log: slog.New(slog.DiscardHandler)}); err == nil {
		t.Fatal("one database for both must be refused")
	}
}

// The state of a source follows its last line: never until the first, receiving, silent after an hour (the mock).
func TestContract_INV3_SourceStateAndDeviceName(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW-HQ", "192.168.10.1")
	if s.State != "never" || s.LastReceived != nil || s.AssetID == nil || *s.AssetID != "a-fw" || *s.AssetName != "FW-HQ" {
		t.Fatalf("new source = %+v", s)
	}
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, e.clock.Add(-time.Minute), "a")); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.Sources(t.Context())
	if err != nil || v.Sources[0].State != "receiving" || v.Sources[0].LastReceived == nil || v.Sources[0].LinesPerHour != 1 {
		t.Fatalf("%+v %v", v.Sources, err)
	}
	e.advance(61 * time.Minute)
	v, _ = e.svc.Sources(t.Context())
	if v.Sources[0].State != "silent" || v.Sources[0].LinesPerHour != 0 {
		t.Fatalf("after an hour: %+v", v.Sources[0])
	}
	if v.RetentionDays != 30 {
		t.Fatalf("default retention = %d", v.RetentionDays)
	}
}

func TestContract_INV3_SourceValidationFollowsTheMock(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ok := Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "192.168.10.1", Proto: "udp", Port: 514}
	e.add("existing", "192.168.10.9")
	for name, tc := range map[string]struct {
		mut  func(*Input)
		want string
	}{
		"unknown kind":              {func(i *Input) { i.Kind = "cisco-9000" }, "bad_kind"},
		"empty name":                {func(i *Input) { i.Name = "  " }, "bad_name"},
		"name with a space":         {func(i *Input) { i.Name = "FW HQ" }, "bad_name"},
		"name with an accent":       {func(i *Input) { i.Name = "Tường" }, "bad_name"},
		"name of 65 characters":     {func(i *Input) { i.Name = strings.Repeat("a", 65) }, "bad_name"},
		"ip with a leading zero":    {func(i *Input) { i.SenderIP = "192.168.010.1" }, "bad_ip"},
		"ip out of range":           {func(i *Input) { i.SenderIP = "192.168.10.256" }, "bad_ip"},
		"ipv6":                      {func(i *Input) { i.SenderIP = "::1" }, "bad_ip"},
		"ipv4 in ipv6":              {func(i *Input) { i.SenderIP = "::ffff:10.0.0.1" }, "bad_ip"},
		"tcp for a udp-only kind":   {func(i *Input) { i.Kind, i.Proto = "sophos", "tcp" }, "bad_proto"},
		"unknown protocol":          {func(i *Input) { i.Proto = "sctp" }, "bad_proto"},
		"port 0":                    {func(i *Input) { i.Port = 0 }, "bad_port"},
		"port 65536":                {func(i *Input) { i.Port = 65536 }, "bad_port"},
		"another source has the ip": {func(i *Input) { i.SenderIP = "192.168.10.9" }, "duplicate"},
	} {
		in := ok
		tc.mut(&in)
		if _, err := e.svc.AddSource(t.Context(), "admin@acme.example", in); code(err) != tc.want {
			t.Errorf("%s: code %q (%v), want %s", name, code(err), err, tc.want)
		}
	}
	if count(t, e.cfg, `SELECT count(*) FROM logs_sources`) != 1 {
		t.Fatal("a refused source was stored")
	}
	s, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: "sophos", Name: "  SF-1  ", SenderIP: "192.168.10.2", Proto: "udp", Port: 5140})
	if err != nil || s.Name != "SF-1" || s.Port != 5140 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestContract_INV3_EditAndDeleteSourceAreAudited(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.add("one", "192.168.10.1"), e.add("two", "192.168.10.2")
	if _, err := e.svc.UpdateSource(t.Context(), "admin@acme.example", "ls-nope", Input{Kind: "fortigate", Name: "x", SenderIP: "192.168.10.3", Proto: "udp", Port: 514}); code(err) != "not_found" {
		t.Fatalf("missing source: %v", err)
	}
	if _, err := e.svc.UpdateSource(t.Context(), "admin@acme.example", a.ID, Input{Kind: "fortigate", Name: "one", SenderIP: b.SenderIP, Proto: "udp", Port: 514}); code(err) != "duplicate" {
		t.Fatalf("another source's IP: %v", err)
	}
	got, err := e.svc.UpdateSource(t.Context(), "admin@acme.example", a.ID, Input{Kind: "fortigate", Name: "one-renamed", SenderIP: a.SenderIP, Proto: "tcp", Port: 1514})
	if err != nil || got.Name != "one-renamed" || got.Proto != "tcp" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := e.svc.DeleteSource(t.Context(), "admin@acme.example", "ls-nope"); code(err) != "not_found" {
		t.Fatalf("delete missing: %v", err)
	}
	if err := e.svc.DeleteSource(t.Context(), "admin@acme.example", b.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := e.cfg.Reader().QueryContext(t.Context(), `SELECT action, user FROM core_audit WHERE action LIKE 'logs.%' ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got2 []string
	for rows.Next() {
		var a, u string
		if err := rows.Scan(&a, &u); err != nil {
			t.Fatal(err)
		}
		got2 = append(got2, a+":"+u)
	}
	want := "logs.source_add:admin@acme.example logs.source_add:admin@acme.example logs.source_edit:admin@acme.example logs.source_delete:admin@acme.example"
	if strings.Join(got2, " ") != want {
		t.Fatalf("audit = %v", got2)
	}
}

func TestContract_INV4_RetentionChoicesAndPurge(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	for _, d := range []int{0, 1, 14, 365} {
		if _, err := e.svc.SetRetention(t.Context(), "admin@acme.example", d); code(err) != "bad_days" {
			t.Fatalf("%d days: %v", d, err)
		}
	}
	old, recent := e.clock.Add(-10*24*time.Hour), e.clock.Add(-time.Hour)
	if _, err := e.svc.Ingest(t.Context(), append(lines(s.ID, old, "old 1", "old 2", "old 3"), lines(s.ID, recent, "recent")...)); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.Purge(t.Context())
	if err != nil || res.Expired != 0 {
		t.Fatalf("30 days keeps 10-day-old lines: %+v %v", res, err)
	}
	if d, err := e.svc.SetRetention(t.Context(), "admin@acme.example", 7); err != nil || d != 7 {
		t.Fatal(d, err)
	}
	res, err = e.svc.Purge(t.Context())
	if err != nil || res.Expired != 3 {
		t.Fatalf("7 days: %+v %v", res, err)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_events`) != 1 {
		t.Fatal("wrong lines purged")
	}
	if count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge_started'`) != 1 || count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge'`) != 1 || count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.retention'`) != 1 {
		t.Fatal("retention change and purge must each leave an audit row")
	}
	if res, _ = e.svc.Purge(t.Context()); res.Expired != 0 || count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action LIKE 'logs.purge%'`) != 2 {
		t.Fatal("a purge that removed nothing writes no audit row")
	}
}

// Deleting a source keeps what it sent until retention expires (INV-4); the lines are then named by the id.
func TestContract_INV4_DeletingASourceKeepsItsLines(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW-HQ", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, e.clock.Add(-time.Minute), "kept")); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteSource(t.Context(), "admin@acme.example", s.ID); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.Events(t.Context(), EventQuery{Window: "24h"})
	if err != nil || len(v.Events) != 1 || v.Events[0].Line != "kept" || v.Events[0].SourceName != s.ID {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := e.svc.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_source_seen`) != 0 {
		t.Fatal("the last-received mark of a deleted source stays")
	}
	if n, err := e.svc.Ingest(t.Context(), lines(s.ID, e.clock.Add(-time.Second), "late")); err != nil || n.Stored != 0 || n.Unknown != 1 {
		t.Fatalf("a deleted source is unknown again: %+v %v", n, err)
	}
}

func TestContract_INV5_EventsWindowKeywordSourceAndPage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fw, rt := e.add("FW-HQ", "192.168.10.1"), e.add("RT-BACKUP", "192.168.10.2")
	if _, err := e.svc.Ingest(t.Context(), lines(fw.ID, e.clock.Add(-3*24*time.Hour), "three days ago srcip=10.0.0.5")); err != nil {
		t.Fatal(err)
	}
	var batch []Line
	for i := range 250 {
		batch = append(batch, Line{SourceID: fw.ID, At: e.clock.Add(-time.Duration(250-i) * time.Second), Text: "traffic deny srcip=10.0.0." + string(rune('0'+i%10))})
	}
	for start := 0; start < len(batch); start += 100 {
		if _, err := e.svc.Ingest(t.Context(), batch[start:min(start+100, len(batch))]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.Ingest(t.Context(), lines(rt.ID, *e.clock, "Winbox login from 10.0.0.9")); err != nil {
		t.Fatal(err)
	}
	ev := func(q EventQuery) EventsView {
		t.Helper()
		v, err := e.svc.Events(t.Context(), q)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := ev(EventQuery{Window: "24h"}); v.Total != 251 || len(v.Events) != EventsPage || v.Events[0].Line != "Winbox login from 10.0.0.9" || v.Events[0].SourceName != "RT-BACKUP" || v.Events[0].TS.Before(v.Events[1].TS) {
		t.Fatalf("24h: total %d, %d events, first %+v", v.Total, len(v.Events), v.Events[0])
	}
	if v := ev(EventQuery{Window: "1h"}); v.Total != 251 {
		t.Fatalf("1h total = %d", v.Total)
	}
	if v := ev(EventQuery{Window: "7d"}); v.Total != 252 {
		t.Fatalf("7d total = %d, want the 3-day-old line too", v.Total)
	}
	if v := ev(EventQuery{Window: "24h", Source: rt.ID}); v.Total != 1 {
		t.Fatalf("one source: %d", v.Total)
	}
	if v := ev(EventQuery{Window: "24h", Q: "WINBOX"}); v.Total != 1 {
		t.Fatalf("keyword in the line, any case: %d", v.Total)
	}
	if v := ev(EventQuery{Window: "24h", Q: "rt-backup"}); v.Total != 1 || v.Events[0].SourceID != rt.ID {
		t.Fatalf("keyword in the source name: %+v", v)
	}
	if v := ev(EventQuery{Window: "24h", Q: "nothing like this"}); v.Total != 0 || v.Events == nil || len(v.Events) != 0 {
		t.Fatalf("no match must be an empty list, not null: %+v", v)
	}
	if _, err := e.svc.Events(t.Context(), EventQuery{Window: "30d"}); code(err) != "bad_window" {
		t.Fatalf("bad window: %v", err)
	}
	if _, err := e.svc.SetRetention(t.Context(), "admin@acme.example", 7); err != nil {
		t.Fatal(err)
	}
	if v := ev(EventQuery{Window: "7d"}); v.Total != 252 {
		t.Fatalf("a window within the retention is unchanged: %d", v.Total)
	}
}

func TestIngestDropsUnknownSourcesAndBoundsABatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	res, err := e.svc.Ingest(t.Context(), append(lines(s.ID, t0, "ok"), lines("ls-stranger", t0, "from nowhere", "again")...))
	if err != nil || res.Stored != 1 || res.Unknown != 2 || count(t, e.vol, `SELECT count(*) FROM logs_events`) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := e.svc.Ingest(t.Context(), make([]Line, MaxBatch+1)); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("501 lines: %v", err)
	}
	if res, err := e.svc.Ingest(t.Context(), nil); err != nil || res.Stored != 0 {
		t.Fatal(res, err)
	}
	// a line that claims to come from the future is stored with the receive time
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0.Add(48*time.Hour), "future")); err != nil {
		t.Fatal(err)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_events WHERE ts > ?`, store.FormatTS(t0)) != 0 {
		t.Fatal("a future timestamp was kept")
	}
}

func TestIngestMakesDeviceTextSafe(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	long := strings.Repeat("é", 3000) // 6000 bytes
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, "nul\x00in\x1b[31mred\x07\ttab", "bad \xff\xfe utf8", long, "trailing spaces   ")); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.Events(t.Context(), EventQuery{Window: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range v.Events {
		got[e.Line] = true
		if len(e.Line) > MaxLineBytes {
			t.Errorf("a line of %d bytes was stored", len(e.Line))
		}
	}
	for _, want := range []string{"nul in [31mred \ttab", "bad � utf8", "trailing spaces"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	for l := range got {
		if strings.HasSuffix(l, "[cut]") && (len(l) > MaxLineBytes || !strings.HasPrefix(l, "ééé")) {
			t.Errorf("bad cut line: %d bytes", len(l))
		}
	}
}

// The configuration database has one writer and ingest has another: a transaction that holds the core writer does not
// stop the ingest of a flood (this is why the volume is a database of its own).
func TestIngestNeverWaitsForTheCoreWriter(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = e.cfg.Write(context.Background(), func(*sql.Tx) error { close(held); <-release; return nil })
	}()
	<-held
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for range 20 {
		if res, err := e.svc.Ingest(ctx, lines(s.ID, t0, "a", "b", "c")); err != nil || res.Stored != 3 {
			close(release)
			<-done
			t.Fatalf("ingest while the core writer is held: %+v %v", res, err)
		}
	}
	close(release)
	<-done
	if count(t, e.vol, `SELECT count(*) FROM logs_events`) != 60 {
		t.Fatal("lines were lost")
	}
}

// A purge works in chunks, honours its context, and respects the byte bound on stored lines whatever the retention: it
// removes the oldest lines until 90% of the bound is left, and the counter says what the table holds.
func TestPurgeChunksCapAndContext(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, slices.Repeat([]string{"0123456789"}, 500)...)); err != nil { // 5,000 bytes
		t.Fatal(err)
	}
	e.svc.maxBytes, e.svc.chunk = 4000, 100 // down to 3,600: two chunks of 1,000 bytes
	res, err := e.svc.Purge(t.Context())
	if err != nil || res.Over != 200 || res.Expired != 0 {
		t.Fatalf("over the bound: %+v %v", res, err)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_events`) != 300 || count(t, e.vol, `SELECT min(id) FROM logs_events`) != 201 {
		t.Fatal("the oldest lines must go first")
	}
	if got, want := count(t, e.vol, `SELECT line_bytes FROM logs_volume`), count(t, e.vol, `SELECT sum(length(line)) FROM logs_events`); got != want || got != 3000 {
		t.Fatalf("the byte counter says %d, the lines hold %d, want 3000", got, want)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.svc.Purge(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled purge: %v", err)
	}
}

func TestExportDeviceLogsWritesJSONLinesInRange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	e.advance(5 * time.Hour) // the lines are in the past, so their receive times are kept
	for i, text := range []string{"first", "second", "third"} {
		if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0.Add(time.Duration(i)*time.Hour), text)); err != nil {
			t.Fatal(err)
		}
	}
	var all, mid strings.Builder
	if err := e.svc.ExportDeviceLogs(t.Context(), time.Time{}, time.Time{}, &all); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ExportDeviceLogs(t.Context(), t0.Add(time.Hour), t0.Add(time.Hour), &mid); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(all.String(), "\n"); n != 3 || !strings.Contains(all.String(), `"line":"first"`) || strings.Index(all.String(), "first") > strings.Index(all.String(), "third") {
		t.Fatalf("all: %q", all.String())
	}
	if !strings.Contains(mid.String(), `"line":"second"`) || strings.Count(mid.String(), "\n") != 1 {
		t.Fatalf("both ends inclusive: %q", mid.String())
	}
}

func TestDigestCountsTheLast24Hours(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), append(lines(s.ID, e.clock.Add(-time.Hour), "a", "b"), lines(s.ID, e.clock.Add(-30*time.Hour), "c")...)); err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.Digest(t.Context())
	if err != nil || d.Lines24h != 2 || d.BaselineDays != 7 || d.New == nil || len(d.BadConnections) != 0 {
		t.Fatalf("%+v %v", d, err)
	}
}

// Bidirectional formatting characters and line separators in a device's line cannot change how the line reads or split it.
func TestIngestStripsBidiAndLineSeparators(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, "user "+ch(0x202e)+"admin"+ch(0x202c)+" ok", "a"+ch(0x2028)+"b"+ch(0x2029)+"c"+ch(0x85)+"d", "isolate "+ch(0x2066)+"x"+ch(0x2069)+" mark"+ch(0x200e)+ch(0x200f)+ch(0x61c))); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.Events(t.Context(), EventQuery{Window: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, ev := range v.Events {
		got[ev.Line] = true
	}
	for _, want := range []string{"user  admin  ok", "a b c d", "isolate  x  mark"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

// What the user types in the search box and in the source filter is data, never SQL (INV-5).
func TestEventsInputsAreDataNotSQL(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, "100% done", "a_b", "x' OR '1'='1", "plain")); err != nil {
		t.Fatal(err)
	}
	total := func(q EventQuery) int {
		t.Helper()
		v, err := e.svc.Events(t.Context(), q)
		if err != nil {
			t.Fatalf("%+v: %v", q, err)
		}
		return v.Total
	}
	if n := total(EventQuery{Window: "1h", Q: "%"}); n != 1 {
		t.Errorf("a percent sign is a character, not a wildcard: %d lines", n)
	}
	if n := total(EventQuery{Window: "1h", Q: "_"}); n != 1 {
		t.Errorf("an underscore is a character, not a wildcard: %d lines", n)
	}
	if n := total(EventQuery{Window: "1h", Q: "x' OR '1'='1"}); n != 1 {
		t.Errorf("a quote is a character: %d lines", n)
	}
	if n := total(EventQuery{Window: "1h", Q: "'; DROP TABLE logs_events; --"}); n != 0 {
		t.Errorf("injection text matches nothing: %d", n)
	}
	if n := total(EventQuery{Window: "1h", Source: "x' OR '1'='1"}); n != 0 {
		t.Errorf("a source id with a quote matches nothing: %d", n)
	}
	if n := total(EventQuery{Window: "1h", Source: s.ID}); n != 4 {
		t.Errorf("the source filter: %d", n)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_events`) != 4 {
		t.Fatal("the table changed")
	}
}

// The retention boundary: a line exactly as old as the retention stays, one millisecond older goes.
func TestContract_INV4_PurgeBoundaryIsStrict(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.SetRetention(t.Context(), "admin@acme.example", 7); err != nil {
		t.Fatal(err)
	}
	edge := *e.clock
	if _, err := e.svc.Ingest(t.Context(), append(lines(s.ID, edge, "exactly at the boundary"), lines(s.ID, edge.Add(-time.Millisecond), "one millisecond too old")...)); err != nil {
		t.Fatal(err)
	}
	e.advance(7 * 24 * time.Hour) // now the first line is exactly 7 days old
	res, err := e.svc.Purge(t.Context())
	if err != nil || res.Expired != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_events WHERE line = 'exactly at the boundary'`) != 1 {
		t.Fatal("the line at the boundary was purged")
	}
}

func (e *env) bulk(sourceID string, n int, ts time.Time) {
	e.t.Helper()
	err := e.vol.Write(e.t.Context(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(e.t.Context(), `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?) INSERT INTO logs_events (ts, source_id, line) SELECT ?, ?, 'l' FROM c`, n, store.FormatTS(ts), sourceID); err != nil {
			return err
		}
		_, err := tx.ExecContext(e.t.Context(), `UPDATE logs_volume SET line_bytes = line_bytes + ?`, n) // each line is one byte
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// A purge of 25,000 lines is three transactions of at most 10,000 (the writer is free between them), and a cancelled
// context stops it between two chunks.
func TestPurgeRunsInChunksAndStopsWhenCancelled(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	e.bulk(s.ID, 25_000, e.clock.Add(-60*24*time.Hour))
	calls := 0
	e.svc.afterChunk = func() {
		calls++
		// the writer of logs.db is free between two chunks: a write from here does not wait
		if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, "between chunks")); err != nil {
			t.Error(err)
		}
	}
	res, err := e.svc.Purge(t.Context())
	if err != nil || res.Expired != 25_000 || calls != 3 {
		t.Fatalf("%+v %v after %d chunks, want 25000 in 3", res, err, calls)
	}
	// cancelled after the first chunk: only that chunk is gone
	e.bulk(s.ID, 25_000, e.clock.Add(-60*24*time.Hour))
	ctx, cancel := context.WithCancel(t.Context())
	e.svc.afterChunk = cancel
	res, err = e.svc.Purge(ctx)
	if err != context.Canceled || res.Expired != 10_000 { //nolint:errorlint // the context error itself, not a wrapped one: the check between chunks answered
		t.Fatalf("%+v %v, want 10000 removed and context.Canceled", res, err)
	}
	if got := count(t, e.vol, `SELECT count(*) FROM logs_events WHERE ts < ?`, store.FormatTS(e.clock.Add(-30*24*time.Hour))); got != 15_000 {
		t.Fatalf("%d old lines left, want 15000", got)
	}
}

// Zero-width and format characters, DEL and C1 controls (NEL) are not kept either: they hide text from the search and
// forge a second line.
func TestIngestStripsInvisibleCharacters(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, "ad"+ch(0x200b)+"min", "x"+ch(0xfeff)+"y", "del\x7fchar", "c1"+ch(0x80)+ch(0x9f)+"x", "z"+ch(0x200d)+"w"+ch(0xad)+"j")); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"ad min", "x y", "del char", "c1  x", "z w j"} {
		if v, err := e.svc.Events(t.Context(), EventQuery{Window: "1h", Q: q}); err != nil || v.Total != 1 {
			t.Errorf("%q: %d lines, %v", q, v.Total, err)
		}
	}
}

// The search is case-insensitive for ASCII letters and exact for the rest, the same way on both sides (SQLite's lower()
// is ASCII-only): a Vietnamese keyword typed as the line has it matches.
func TestEventsKeywordIsCaseInsensitiveForASCIIOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, "Đăng nhập thất bại user=ADMIN")); err != nil {
		t.Fatal(err)
	}
	total := func(q string) int {
		v, err := e.svc.Events(t.Context(), EventQuery{Window: "1h", Q: q})
		if err != nil {
			t.Fatal(err)
		}
		return v.Total
	}
	for _, q := range []string{"Đăng", "Đăng nhập", "thất bại", "user=admin", "USER=ADMIN"} {
		if total(q) != 1 {
			t.Errorf("%q must match", q)
		}
	}
	if total("đăng") != 0 {
		t.Error("a different non-ASCII case is a different character: documented, not folded")
	}
}

// The OR of a source-name match stays inside the window and the source filter.
func TestEventsNameMatchRespectsTheWindowAndTheSourceFilter(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fw, rt := e.add("FW-HQ", "192.168.10.1"), e.add("RT-BACKUP", "192.168.10.2")
	if _, err := e.svc.Ingest(t.Context(), append(lines(fw.ID, e.clock.Add(-3*24*time.Hour), "old line of the firewall"), lines(fw.ID, e.clock.Add(-time.Minute), "new line of the firewall")...)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Ingest(t.Context(), lines(rt.ID, e.clock.Add(-time.Minute), "a line of the router")); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.Events(t.Context(), EventQuery{Window: "1h", Q: "fw-hq"})
	if err != nil || v.Total != 1 || v.Events[0].Line != "new line of the firewall" {
		t.Fatalf("name match inside the window: %+v %v", v, err)
	}
	v, err = e.svc.Events(t.Context(), EventQuery{Window: "24h", Source: rt.ID, Q: "fw-hq"})
	if err != nil || v.Total != 0 {
		t.Fatalf("name match must not leak past the source filter: %+v %v", v, err)
	}
}

// A search has a deadline and a box runs at most MaxSearches at once: past either the answer is 503 server_busy.
func TestEventsSearchIsBoundedInTimeAndInNumber(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, "a")); err != nil {
		t.Fatal(err)
	}
	for range MaxSearches { // every slot taken
		e.svc.searchSem <- struct{}{}
	}
	e.svc.searchTimeout = 50 * time.Millisecond
	if _, err := e.svc.Events(t.Context(), EventQuery{Window: "1h"}); code(err) != "server_busy" {
		t.Fatalf("with every slot taken: %v", err)
	}
	for range MaxSearches {
		<-e.svc.searchSem
	}
	e.svc.searchTimeout = time.Nanosecond // a deadline that has passed
	if _, err := e.svc.Events(t.Context(), EventQuery{Window: "1h", Q: "a"}); code(err) != "server_busy" {
		t.Fatalf("with an expired deadline: %v", err)
	}
	e.svc.searchTimeout = SearchTimeout
	if v, err := e.svc.Events(t.Context(), EventQuery{Window: "1h"}); err != nil || v.Total != 1 {
		t.Fatalf("a search after the slots are free: %+v %v", v, err)
	}
	if len(e.svc.searchSem) != 0 {
		t.Fatal("a search left its slot taken")
	}
}

// The id of a line is never given to another line (AUTOINCREMENT), even after a purge removed the newest ones.
func TestEventIDsAreNeverReused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, "a", "b", "c")); err != nil {
		t.Fatal(err)
	}
	e.advance(40 * 24 * time.Hour)
	if res, err := e.svc.Purge(t.Context()); err != nil || res.Expired != 3 || count(t, e.vol, `SELECT count(*) FROM logs_events`) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, "d")); err != nil {
		t.Fatal(err)
	}
	if id := count(t, e.vol, `SELECT id FROM logs_events`); id != 4 {
		t.Fatalf("the new line has id %d, want 4: an id was reused", id)
	}
}

// A purge keeps the "last received" mark of a source that exists, and the cap alone (nothing expired) leaves an audit row.
func TestPurgeKeepsLiveMarksAndAuditsTheCapAlone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, "1", "2", "3", "4", "5")); err != nil {
		t.Fatal(err)
	}
	e.svc.maxBytes, e.svc.chunk = 3, 1 // five bytes of lines, one line per chunk: two lines go
	res, err := e.svc.Purge(t.Context())
	if err != nil || res.Over != 2 || res.Expired != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_source_seen WHERE source_id = ?`, s.ID) != 1 {
		t.Fatal("the mark of a source that exists was dropped")
	}
	v, _ := e.svc.Sources(t.Context())
	if v.Sources[0].State != "receiving" || v.Sources[0].LastReceived == nil {
		t.Fatalf("the source looks silent after a purge: %+v", v.Sources[0])
	}
	if count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge_started'`) != 1 || count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge'`) != 1 {
		t.Fatal("a purge that only enforced the cap must leave its audit rows")
	}
}

// Whatever way a purge ends, the lines it removed have an audit row, and the "started" row exists before the first delete.
func TestPurgeAuditsEveryWayOut(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	e.bulk(s.ID, 25_000, e.clock.Add(-60*24*time.Hour))
	ctx, cancel := context.WithCancel(t.Context())
	first := true
	e.svc.afterChunk = func() {
		if first {
			first = false
			if count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge_started'`) != 1 {
				t.Error("no started row after the first chunk was deleted")
			}
			cancel() // the purge is cut short after 10,000 lines
		}
	}
	res, err := e.svc.Purge(ctx)
	if err != context.Canceled || res.Expired != 10_000 { //nolint:errorlint // the context error itself
		t.Fatalf("%+v %v", res, err)
	}
	var detail string
	if err := e.cfg.Reader().QueryRowContext(t.Context(), `SELECT detail FROM core_audit WHERE action = 'logs.purge'`).Scan(&detail); err != nil || !strings.HasPrefix(detail, "10000 lines") {
		t.Fatalf("a purge cut short by its context must still say what it removed: %q %v", detail, err)
	}
}

// ch is a character given by its code point, so that the invisible ones are visible in this file.
func ch(c rune) string { return string(c) }

// ---- production safety (fix/logs-production-safety) ----

// wait blocks until the purge that Ingest started has ended.
func (e *env) wait() {
	e.t.Helper()
	for end := time.Now().Add(20 * time.Second); e.svc.purging.Load(); {
		if time.Now().After(end) {
			e.t.Fatal("the purge started by Ingest did not end")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// M2: past the byte bound, Ingest starts one purge in the background, never waits for it (here it is stuck behind the core
// writer, which the audit rows need), and many batches over the bound start one purge, not one each.
func TestIngestStartsOneBackgroundPurgeWhenOverTheByteBound(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	e.svc.maxBytes = 1000
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_ = e.cfg.Write(context.Background(), func(*sql.Tx) error { close(held); <-release; return nil })
	}()
	<-held
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for range 5 { // 5 x 500 bytes: over the bound from the third batch on
		if res, err := e.svc.Ingest(ctx, lines(s.ID, t0, slices.Repeat([]string{"0123456789"}, 50)...)); err != nil || res.Stored != 50 {
			close(release)
			<-done
			t.Fatalf("ingest while a purge waits for the core writer: %+v %v", res, err)
		}
	}
	if !e.svc.purging.Load() {
		t.Fatal("no purge was started although the volume is over the bound")
	}
	close(release)
	<-done
	e.wait()
	if left := count(t, e.vol, `SELECT line_bytes FROM logs_volume`); left > 900 {
		t.Fatalf("%d bytes left after the purge, want at most 900 (90%% of the bound)", left)
	}
	if n := count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge_started'`); n != 1 {
		t.Fatalf("%d purges started, want 1 (coalesced)", n)
	}
	if count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge'`) != 1 {
		t.Fatal("the purge has no end row")
	}
}

func TestIngestUnderTheByteBoundStartsNoPurge(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	e.svc.maxBytes = 1000
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, "a", "b")); err != nil {
		t.Fatal(err)
	}
	if e.svc.purging.Load() || count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action LIKE 'logs.purge%'`) != 0 {
		t.Fatal("a purge ran under the bound")
	}
	if count(t, e.vol, `SELECT line_bytes FROM logs_volume`) != 2 {
		t.Fatal("the byte counter does not count the stored lines")
	}
}

// L1: device_logs has its own cap: the newest lines up to it, then one marker line that says older lines are left out.
func TestExportDeviceLogsIsCappedNewestFirstWithAMarker(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	e.advance(5 * time.Hour)
	for i, text := range []string{"old1", "old2", "new1", "new2"} {
		if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0.Add(time.Duration(i)*time.Hour), text)); err != nil {
			t.Fatal(err)
		}
	}
	e.svc.exportBytes = 2*(2*4+128) + 10 // room for two lines of four bytes
	var out strings.Builder
	if err := e.svc.ExportDeviceLogs(t.Context(), time.Time{}, time.Time{}, &out); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(rows) != 3 || !strings.Contains(rows[0], `"line":"new1"`) || !strings.Contains(rows[1], `"line":"new2"`) || !strings.Contains(rows[2], `"id":"cut"`) || !strings.Contains(rows[2], "older lines are left out") {
		t.Fatalf("export = %q, want new1, new2, then the marker", out.String())
	}
	if strings.Contains(out.String(), `"line":"old`) {
		t.Fatal("an old line was kept over a newer one")
	}
	e.svc.exportBytes = 1 // not even one line fits
	out.Reset()
	if err := e.svc.ExportDeviceLogs(t.Context(), time.Time{}, time.Time{}, &out); err != nil || strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), `"id":"cut"`) {
		t.Fatalf("export with no room = %q %v, want the marker alone", out.String(), err)
	}
	out.Reset() // an empty range has nothing left out: no marker
	if err := e.svc.ExportDeviceLogs(t.Context(), t0.Add(48*time.Hour), time.Time{}, &out); err != nil || out.Len() != 0 {
		t.Fatalf("empty range = %q %v", out.String(), err)
	}
}

// L1 end to end: a category over its cap does not make core refuse the whole export.
func TestExportDeviceLogsCannotMakeTheCoreExportTooLarge(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, slices.Repeat([]string{strings.Repeat("x", 1000)}, 100)...)); err != nil { // about 100 KB
		t.Fatal(err)
	}
	e.svc.exportBytes = 20_000
	r := logexport.New()
	r.Register("device_logs", e.svc.ExportDeviceLogs)
	exp, err := r.Build(t.Context(), logexport.Request{Categories: []string{"device_logs"}, Format: logexport.JSON, MaxBytes: 25_000, ExportedAt: t0, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("a capped category must fit core's cap: %v", err)
	}
	_ = exp.Close()
}

// L2: a time outside [now - retention, now] is the receive time, now, and the next purge (an hour later) keeps the line.
func TestIngestClampsTheTimeToNow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, e.clock.Add(-400*24*time.Hour), "far past")); err != nil {
		t.Fatal(err)
	}
	var ts string
	if err := e.vol.Reader().QueryRowContext(t.Context(), `SELECT ts FROM logs_events`).Scan(&ts); err != nil || ts != store.FormatTS(*e.clock) {
		t.Fatalf("ts = %q %v, want now", ts, err)
	}
	e.advance(PurgeEvery) // the clock moves: a line that sat on the boundary would now be expired
	if res, err := e.svc.Purge(t.Context()); err != nil || res.Expired != 0 {
		t.Fatalf("%+v %v: the clamped line must survive the next purge", res, err)
	}
}

// L2: a huge line is cut before the sanitizer walks it (9,000 NULs then text: cut first, nothing but spaces is left; walked
// first, the text would survive behind the spaces).
func TestSanitizeCutsBeforeItWalks(t *testing.T) {
	t.Parallel()
	if got := sanitizeLine(strings.Repeat("\x00", 9000) + "tail"); got != " ...[cut]" {
		t.Fatalf("got %q, want the line cut at %d bytes first, trimmed to nothing, and marked", got, maxIngestLineBytes)
	}
	if got := sanitizeLine("ab" + strings.Repeat(" ", 9000)); got != "ab ...[cut]" {
		t.Fatalf("got %q: a line cut before sanitizing is always marked", got)
	}
	if got := sanitizeLine(strings.Repeat("\x80", 9000)); len(got) > MaxLineBytes || !strings.HasSuffix(got, "...[cut]") || !utf8.ValidString(got) {
		t.Fatalf("a line of continuation bytes: %d bytes", len(got))
	}
	got := sanitizeLine(strings.Repeat("é", 10_000_000))
	if len(got) > MaxLineBytes || !strings.HasSuffix(got, "...[cut]") || !utf8.ValidString(got) {
		t.Fatalf("a 20 MB line: %d bytes, valid=%t", len(got), utf8.ValidString(got))
	}
}

// A purge that has nothing to do deletes nothing and leaves no audit row; one that is cancelled right after its "started" row
// still writes the end row, with zeros.
func TestPurgeWithNothingToDoIsSilentAndAStartedPurgeAlwaysEnds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, "fresh")); err != nil {
		t.Fatal(err)
	}
	e.svc.afterChunk = func() { t.Error("a delete ran with nothing to delete") }
	if res, err := e.svc.Purge(t.Context()); err != nil || res != (PurgeResult{}) {
		t.Fatalf("%+v %v", res, err)
	}
	if count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action LIKE 'logs.purge%'`) != 0 {
		t.Fatal("a purge with nothing to do left audit rows")
	}
	e.svc.afterChunk = nil
	e.bulk(s.ID, 100, e.clock.Add(-60*24*time.Hour))
	ctx, cancel := context.WithCancel(t.Context())
	e.svc.afterStart = cancel // cancelled after "started", before the first chunk
	if _, err := e.svc.Purge(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation", err)
	}
	var detail string
	if err := e.cfg.Reader().QueryRowContext(t.Context(), `SELECT detail FROM core_audit WHERE action = 'logs.purge'`).Scan(&detail); err != nil || !strings.HasPrefix(detail, "0 lines") {
		t.Fatalf("the end row of a purge cancelled before its first chunk: %q %v", detail, err)
	}
}

// M-B: the over-bound step stops when the expired delete alone got the volume under 90% of the bound.
func TestPurgeDoesNotDeleteMoreThanTheBoundNeeds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, slices.Repeat([]string{"0123456789"}, 100)...)); err != nil { // 1,000 bytes, to expire
		t.Fatal(err)
	}
	e.advance(40 * 24 * time.Hour)
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, slices.Repeat([]string{"0123456789"}, 100)...)); err != nil { // 1,000 fresh bytes
		t.Fatal(err)
	}
	e.svc.maxBytes = 1500 // 2,000 stored is over; the expired 1,000 alone leaves 1,000, under 1,350
	res, err := e.svc.Purge(t.Context())
	if err != nil || res.Expired != 100 || res.Over != 0 {
		t.Fatalf("%+v %v, want 100 expired and nothing over", res, err)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_events`) != 100 {
		t.Fatal("fresh lines were deleted although the bound was met")
	}
}

// M-C: a counter that is too high (lines the counter never saw leave) is recomputed from the rows when the over-bound step runs
// out of lines and is still over; the first run of the job after a start recomputes it too.
func TestPurgeResyncsAnOvercountedCounter(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, "0123456789", "0123456789")); err != nil {
		t.Fatal(err)
	}
	set := func(n int) {
		t.Helper()
		if err := e.vol.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(t.Context(), `UPDATE logs_volume SET line_bytes = ?`, n)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	set(1_000_000)
	e.svc.maxBytes = 100
	if _, err := e.svc.Purge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, want := count(t, e.vol, `SELECT line_bytes FROM logs_volume`), count(t, e.vol, `SELECT coalesce(sum(length(line)), 0) FROM logs_events`); got != want {
		t.Fatalf("counter %d after the purge, rows hold %d: not recomputed", got, want)
	}
	e.svc.maxBytes = MaxEventBytes
	if _, err := e.svc.Ingest(t.Context(), lines(s.ID, *e.clock, "0123456789", "0123456789")); err != nil {
		t.Fatal(err)
	}
	set(1_000_000)
	if err := Jobs(e.svc)[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := count(t, e.vol, `SELECT line_bytes FROM logs_volume`); got != 20 {
		t.Fatalf("counter %d after the first run of the job, want 20", got)
	}
}

// M-D: the job does not run a purge while one that Ingest started is under way.
func TestTheJobSkipsWhileAPurgeRuns(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	e.bulk(s.ID, 10, e.clock.Add(-60*24*time.Hour))
	e.svc.purging.Store(true)
	if err := Jobs(e.svc)[0].Run(t.Context()); err != nil || count(t, e.vol, `SELECT count(*) FROM logs_events`) != 10 {
		t.Fatalf("the job purged while another purge was running: %v", err)
	}
	e.svc.purging.Store(false)
	if err := Jobs(e.svc)[0].Run(t.Context()); err != nil || count(t, e.vol, `SELECT count(*) FROM logs_events`) != 0 {
		t.Fatalf("the job did not purge when none was running: %v", err)
	}
	if e.svc.purging.Load() {
		t.Fatal("the job left the purge flag set")
	}
}

// M-D / L-5: background purges start at least a minute apart.
func TestBackgroundPurgesStartAMinuteApart(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	e.svc.maxBytes = 1000
	big := lines(s.ID, *e.clock, slices.Repeat([]string{"0123456789"}, 150)...) // 1,500 bytes: over on its own
	started := func() int {
		return count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge_started'`)
	}
	if _, err := e.svc.Ingest(t.Context(), big); err != nil {
		t.Fatal(err)
	}
	e.wait()
	if _, err := e.svc.Ingest(t.Context(), big); err != nil { // over again at once
		t.Fatal(err)
	}
	e.wait()
	if n := started(); n != 1 {
		t.Fatalf("%d purges started within a minute, want 1", n)
	}
	e.advance(time.Minute)
	if _, err := e.svc.Ingest(t.Context(), big); err != nil {
		t.Fatal(err)
	}
	e.wait()
	if n := started(); n != 2 {
		t.Fatalf("%d purges started after the minute, want 2", n)
	}
}
