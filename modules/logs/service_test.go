package logs

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
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
	if count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge'`) != 1 || count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.retention'`) != 1 {
		t.Fatal("retention change and purge must each leave an audit row")
	}
	if res, _ = e.svc.Purge(t.Context()); res.Expired != 0 || count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.purge'`) != 1 {
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

// A purge works in chunks, honours its context, and respects the cap on stored lines whatever the retention.
func TestPurgeChunksCapAndContext(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.add("FW", "192.168.10.1")
	for range 5 {
		if _, err := e.svc.Ingest(t.Context(), lines(s.ID, t0, strings.Split(strings.Repeat("x ", 100), " ")...)); err != nil {
			t.Fatal(err)
		}
	}
	total := count(t, e.vol, `SELECT count(*) FROM logs_events`)
	e.svc.maxEvents = int64(total) - 50
	res, err := e.svc.Purge(t.Context())
	if err != nil || res.Over != 50 || res.Expired != 0 {
		t.Fatalf("over the cap: %+v %v", res, err)
	}
	if count(t, e.vol, `SELECT count(*) FROM logs_events`) != total-50 || count(t, e.vol, `SELECT min(id) FROM logs_events`) != 51 {
		t.Fatal("the oldest lines must go first")
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
