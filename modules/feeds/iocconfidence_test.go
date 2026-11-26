package feeds

import (
	"database/sql"
	"strings"
	"testing"
)

// The built-in indicator lists carry no confidence per line, so every listing is stored with the default 0.5. A lookup rates a
// listing by what its feed is (a confirmed command-and-control list, a curated compromised-host list, an aggregate by its level,
// Tor exit relays), and the confidence of an indicator rises when independent feeds list it. The stored rows are not rewritten: an
// indicator stored before is rated the same way on its next lookup.
func TestIOCConfidenceRatesEachFeedAndRisesWithIndependentFeeds(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	addCustom(t, db, "fs-mine", "My list", KindIOC)
	write(t, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET enabled = 1 WHERE kind = 'ioc'`)
		return err
	})
	ip := func(v string) iocInput { return iocInput{Kind: "ip", Value: v} }
	lists := map[string][]string{ // the addresses each feed lists
		"abusech-feodo": {"198.51.100.1", "198.51.100.6"},
		"et-open":       {"198.51.100.2", "198.51.100.6", "198.51.100.7", "198.51.100.8", "198.51.100.9"},
		"ipsum":         {"198.51.100.3", "198.51.100.5", "198.51.100.7", "198.51.100.9"},
		"tor-exit":      {"198.51.100.4", "198.51.100.5", "198.51.100.8", "198.51.100.9"},
		"fs-mine":       {"198.51.100.10", "198.51.100.11"},
	}
	for src, vals := range lists {
		var recs []iocInput
		for _, v := range vals {
			recs = append(recs, ip(v))
		}
		applyI(t, db, epoch0, src, recs)
	}
	applyI(t, db, epoch0, "hagezi-tif", []iocInput{{Kind: "domain", Value: "tif-listed.example.net"}})
	strong := 0.6
	applyI(t, db, epoch0.Add(1), "fs-mine", []iocInput{ip("198.51.100.10"), {Kind: "ip", Value: "198.51.100.11", Confidence: &strong}})
	applyI(t, db, epoch0.Add(2), "et-open", []iocInput{ip("198.51.100.2"), ip("198.51.100.6"), ip("198.51.100.7"), ip("198.51.100.8"), ip("198.51.100.9"), ip("198.51.100.11")})
	if n := count(t, db, `SELECT count(*) FROM feeds_ioc_source WHERE confidence <> 0.5 AND source_id <> 'fs-mine'`); n != 0 {
		t.Fatalf("%d built-in listings stored with a confidence other than the default", n)
	}
	cases := []struct {
		kind, value string
		conf        float64
		c2          bool
		why         string
	}{
		{"ip", "198.51.100.1", 0.95, true, "a confirmed botnet command-and-control server"},
		{"ip", "198.51.100.2", 0.85, false, "a curated compromised host"},
		{"ip", "198.51.100.3", 0.78, false, "IPsum level 3: on at least three blocklists"},
		{"ip", "198.51.100.4", 0.2, false, "a Tor exit relay alone"},
		{"ip", "198.51.100.5", 0.39, false, "a Tor exit relay on aggregated blocklists counts half"},
		{"ip", "198.51.100.6", 0.99, true, "two independent feeds, one of them command-and-control"},
		{"ip", "198.51.100.7", 0.85, false, "IPsum includes ET Open: not a second source"},
		{"ip", "198.51.100.8", 0.85, false, "a curated compromised host that is also a Tor exit"},
		{"ip", "198.51.100.9", 0.85, false, "ET Open, IPsum and Tor"},
		{"ip", "198.51.100.10", 0.5, false, "a custom feed that gives no confidence"},
		{"ip", "198.51.100.11", 0.94, false, "a custom feed's own 0.6 and ET Open's 0.85 together"},
		{"domain", "tif-listed.example.net", 0.75, false, "hagezi TIF"},
	}
	for _, c := range cases {
		rec, found, err := s.IOCLookup(t.Context(), c.kind, c.value)
		if err != nil || !found {
			t.Fatalf("%s: %v %v", c.value, found, err)
		}
		conf, c2 := IOCConfidence(rec.Sightings)
		if conf != c.conf || c2 != c.c2 {
			t.Errorf("%s (%s): confidence %v c2 %v, want %v %v", c.value, c.why, conf, c2, c.conf, c.c2)
		}
	}
	// A feed switched off does not count: its listings are not pulled and go stale.
	write(t, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET enabled = 0 WHERE id = 'abusech-feodo'`)
		return err
	})
	rec, _, _ := s.IOCLookup(t.Context(), "ip", "198.51.100.6")
	if conf, c2 := IOCConfidence(rec.Sightings); conf != 0.85 || c2 {
		t.Errorf("with Feodo off: %v %v", conf, c2)
	}
	if conf, c2 := IOCConfidence(nil); conf != 0 || c2 {
		t.Errorf("no sighting: %v %v", conf, c2)
	}
}

// IPsum's address names its level (levels/N.txt: on at least N blocklists); a mirror of another level is rated by that level, and an
// address that names none keeps the weight of the default list.
func TestIOCConfidenceOfIPsumFollowsTheLevelOfItsAddress(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	write(t, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET enabled = 1 WHERE id = 'ipsum'`)
		return err
	})
	applyI(t, db, epoch0, "ipsum", []iocInput{{Kind: "ip", Value: "198.51.100.3"}})
	for url, want := range map[string]float64{
		"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt":       0.4,
		"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt":       0.64,
		"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt":       0.78,
		"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt":       0.87,
		"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt":       0.9,
		"https://mirror.example.net/ipsum/levels/5.txt?ref=main":                     0.9,
		"https://mirror.example.net/ipsum.txt":                                       0.78,
		"https://mirror.example.net/levels/0.txt":                                    0.78,
		"https://mirror.example.net/levels/" + strings.Repeat("9", 30) + ".txt":      0.78,
		"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt/x.txt": 0.78,
	} {
		write(t, db, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET url = ? WHERE id = 'ipsum'`, url)
			return err
		})
		rec, _, err := s.IOCLookup(t.Context(), "ip", "198.51.100.3")
		if err != nil {
			t.Fatal(err)
		}
		if conf, _ := IOCConfidence(rec.Sightings); conf != want {
			t.Errorf("%s: %v, want %v", url, conf, want)
		}
	}
}

// Every built-in indicator list has a weight in (0, 1], and only Feodo Tracker is a command-and-control list.
func TestIOCEveryBuiltinListIsRated(t *testing.T) {
	t.Parallel()
	for _, b := range BuiltinSources() {
		if b.Kind != KindIOC {
			if b.Weight != 0 || b.C2 {
				t.Errorf("%s is not an indicator list but has a weight", b.ID)
			}
			continue
		}
		if !(b.Weight > 0 && b.Weight <= 1) {
			t.Errorf("%s: weight %v", b.ID, b.Weight)
		}
		if b.C2 != (b.ID == "abusech-feodo") {
			t.Errorf("%s: c2 %v", b.ID, b.C2)
		}
		if b.Informational && b.Weight >= 0.5 {
			t.Errorf("%s says what an address is, not that it is bad, but weighs %v", b.ID, b.Weight)
		}
	}
}
