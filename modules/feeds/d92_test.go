package feeds

import (
	"database/sql"
	"strings"
	"testing"
)

// D-92: the retired SSLBL feed leaves the box, and Home can tell "no exploited vulnerabilities" from "the CISA list never loaded".

func TestContract_D92_RetiredBuiltinRowIsRemovedAtStartWithWhatItLoaded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	const ts = "2026-11-01T10:00:00.000Z"
	write(t, e.db, func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT OR IGNORE INTO feeds_source (id, builtin, name, kind, format, url, default_url, interval_hours, created_at, status)
			 VALUES ('abusech-sslbl', 1, 'abuse.ch SSLBL', 'ioc', 'csv', 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', 6, '` + ts + `', 'error')`,
			`INSERT INTO feeds_ioc (id, type, value, first_seen, last_seen) VALUES ('only-sslbl', 'ip', '203.0.113.7', '` + ts + `', '` + ts + `'), ('shared', 'ip', '203.0.113.8', '` + ts + `', '` + ts + `')`,
			`INSERT INTO feeds_ioc_source (ioc_id, source_id, last_seen, confidence) VALUES ('only-sslbl', 'abusech-sslbl', '` + ts + `', 0.5), ('shared', 'abusech-sslbl', '` + ts + `', 0.5), ('shared', 'abusech-feodo', '` + ts + `', 0.5)`,
			`INSERT INTO feeds_fetch_log (id, source_id, started_at, status, error) VALUES ('log-1', 'abusech-sslbl', '` + ts + `', 'error', 'no valid rows')`,
		} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		return nil
	})

	if err := e.svc.Seed(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_source WHERE id = 'abusech-sslbl'`); n != 0 {
		t.Errorf("the retired built-in row is still there")
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_ioc_source WHERE source_id = 'abusech-sslbl'`) + count(t, e.db, `SELECT count(*) FROM feeds_fetch_log WHERE source_id = 'abusech-sslbl'`); n != 0 {
		t.Errorf("%d rows of its listings or pull history remain", n)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_ioc WHERE id = 'only-sslbl'`); n != 0 {
		t.Errorf("an indicator only SSLBL listed is still stored")
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_ioc WHERE id = 'shared'`) + count(t, e.db, `SELECT count(*) FROM feeds_ioc_source WHERE ioc_id = 'shared' AND source_id = 'abusech-feodo'`); n != 2 {
		t.Errorf("an indicator Feodo also lists must stay with Feodo's listing (%d of 2 rows)", n)
	}
	if _, ok := BuiltinByID("abusech-sslbl"); ok {
		t.Errorf("abusech-sslbl is still a built-in feed")
	}
	// a custom feed is never touched by this cleanup
	e.addVulnFeed("Kept", "https://feeds.example.net/kev.csv")
	if err := e.svc.Seed(t.Context()); err != nil || count(t, e.db, `SELECT count(*) FROM feeds_source WHERE builtin = 0`) != 1 {
		t.Errorf("seeding removed a custom feed: %v", err)
	}
}

func kevState(t *testing.T, e *env) (string, any) {
	t.Helper()
	c, b := e.get("/feeds/status")
	if c != 200 {
		t.Fatalf("status: %d %v", c, b)
	}
	s, _ := at(b, "kev", "state").(string)
	return s, at(b, "kev", "error")
}

func TestContract_D92_StatusTellsNeverLoadedFromLoadedFromOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if s, er := kevState(t, e); s != "never_loaded" || er != nil {
		t.Errorf("fresh box: %q %v, want never_loaded and no error", s, er)
	}

	// the last pull failed: the reason comes back as one cleaned line
	long := strings.Repeat("x", 500)
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET status = 'error', error = ? WHERE id = 'cisa-kev'`, "cisa.gov answered HTTP 403\n\tsecond line\r\n"+long)
		return err
	})
	s, er := kevState(t, e)
	msg, _ := er.(string)
	if s != "never_loaded" || !strings.HasPrefix(msg, "cisa.gov answered HTTP 403 second line xxx") || strings.ContainsAny(msg, "\r\n\t") || len([]rune(msg)) > 201 {
		t.Errorf("never loaded with an error: %q %q", s, msg)
	}

	// loaded once, last pull failed since: still loaded, the count stays honest
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET last_success = '2026-11-04T10:00:00.000Z' WHERE id = 'cisa-kev'`)
		return err
	})
	if s, er := kevState(t, e); s != "loaded" || er != nil {
		t.Errorf("loaded once: %q %v", s, er)
	}

	// turned off wins over everything
	if c, b := e.put("cisa-kev", `{"enabled":false}`); c != 200 {
		t.Fatalf("switch off: %d %v", c, b)
	}
	if s, _ := kevState(t, e); s != "off" {
		t.Errorf("turned off: %q", s)
	}
}
