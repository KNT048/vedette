package feeds

import (
	"database/sql"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// dropBody is a Spamhaus DROP list in the newline-delimited JSON form Spamhaus publishes (drop_v4.json): one record per network, then
// one metadata record that counts them.
const dropBody = `{"cidr":"80.0.2.0/24","sblid":"SBL000001","rir":"ripencc"}
{"cidr":"80.0.8.0/22","sblid":"SBL000002","rir":"ripencc"}
{"type":"metadata","timestamp":1795674404,"size":120,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
`

// Spamhaus DROP is off on a new box: the box asks spamhaus.org nothing until an administrator turns it on. Once on, it lists networks, and
// an address inside a listed network is a hit (0.9, so high), one outside is not. Wherever the listing is named, Spamhaus DROP is
// credited with the time the box fetched the list.
func TestSpamhausDROPIsOffByDefaultAndMatchesTheAddressesInsideItsNetworks(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	for _, b := range BuiltinSources() { // every other feed off, so the job could contact only this one
		if b.ID != dropFeedID {
			if c, body := e.put(b.ID, `{"enabled":false}`); c != 200 {
				t.Fatalf("%s: %d %v", b.ID, c, body)
			}
		}
	}
	e.mirror(dropFeedID, o.url("/drop_v4.json"))
	o.body("/drop_v4.json", `"d1"`, dropBody)
	if f := e.feed(dropFeedID); f.Enabled {
		t.Fatal("Spamhaus DROP is on by default")
	}
	if err := e.runPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(o.all()); n != 0 {
		t.Fatalf("%d requests to Spamhaus while the feed is off", n)
	}
	if c, err := e.svc.st.IOCCredits(t.Context()); err != nil || len(c) != 0 {
		t.Errorf("credits of a feed that is off: %v %v", c, err)
	}

	if c, body := e.put(dropFeedID, `{"enabled":true}`); c != 200 {
		t.Fatalf("%d %v", c, body)
	}
	if c, b := e.fetch(dropFeedID); c != 200 || at(b, "status") != "ok" || at(b, "records") != 2.0 {
		t.Fatalf("pull: %d %v", c, b)
	}
	fetched := "Spamhaus DROP (list fetched 5 Nov 2026, 12:00 UTC)" // the box's clock; no organization zone in this test: UTC, named
	// logs stores the plain name on a hit and shows this credit, from the feed's last good pull
	if c, err := e.svc.st.IOCCredits(t.Context()); err != nil || len(c) != 1 || c["Spamhaus DROP"] != fetched {
		t.Errorf("credits: %v %v", c, err)
	}
	for ip, want := range map[string]bool{
		"80.0.2.0": true, "80.0.2.77": true, "80.0.2.255": true, // inside the /24
		"80.0.8.1": true, "80.0.11.254": true, // inside the /22
		"80.0.3.1": false, "80.0.1.255": false, "80.0.12.0": false, // just outside
	} {
		rec, found, err := e.svc.st.IOCLookup(t.Context(), "ip", ip)
		if err != nil {
			t.Fatal(err)
		}
		if found != want {
			t.Errorf("%s: found %v, want %v", ip, found, want)
			continue
		}
		if !want {
			continue
		}
		if rec.Value != ip || rec.Type != "ip" || len(rec.Sightings) != 1 || rec.Sightings[0].SourceID != dropFeedID {
			t.Errorf("%s: %+v", ip, rec)
			continue
		}
		if conf, c2 := IOCConfidence(rec.Sightings); conf != 0.9 || c2 {
			t.Errorf("%s: confidence %v c2 %v, want 0.9", ip, conf, c2)
		}
		if got := e.svc.st.CreditName(t.Context(), rec.Sightings[0]); got != fetched {
			t.Errorf("%s: credited as %q, want %q", ip, got, fetched)
		}
	}
	// Feeds -> Look up says the same: listed by Spamhaus DROP with its fetch time, block (a list meant to be dropped outright)
	_, s := e.get("/feeds/search?q=80.0.2.77")
	if at(s, "hit", "sources", 0) != fetched || at(s, "hit", "score") != 0.9 || at(s, "hit", "verdict") != "block" {
		t.Errorf("look up: %v", s)
	}
	if _, s = e.get("/feeds/search?q=80.0.3.1"); at(s, "hit") != nil {
		t.Errorf("look up outside the network: %v", s)
	}
}

// A listing of the address itself and a listing of a network around it are two feeds' evidence on the same address: they add up.
func TestSpamhausDROPAndAnAddressListAddUp(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	write(t, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET enabled = 1 WHERE kind = 'ioc'`)
		return err
	})
	applyI(t, db, epoch0, dropFeedID, []iocInput{{Kind: "ip", Value: "198.51.100.0/24"}, {Kind: "ip", Value: "2001:db8:40::/48"}})
	applyI(t, db, epoch0, "et-open", []iocInput{{Kind: "ip", Value: "198.51.100.7"}})
	cases := []struct {
		ip    string
		found bool
		conf  float64
	}{
		{"198.51.100.7", true, 0.99},    // ET Open lists it, and it is inside a DROP network
		{"198.51.100.8", true, 0.9},     // inside the DROP network only
		{"2001:db8:40:1::5", true, 0.9}, // inside the IPv6 network
		{"2001:db8:41::5", false, 0},    // outside it
		{"198.51.101.7", false, 0},      // outside every network
	}
	for _, c := range cases {
		rec, found, err := s.IOCLookup(t.Context(), "ip", c.ip)
		if err != nil {
			t.Fatal(err)
		}
		if found != c.found {
			t.Errorf("%s: found %v, want %v", c.ip, found, c.found)
			continue
		}
		if conf, _ := IOCConfidence(rec.Sightings); found && conf != c.conf {
			t.Errorf("%s: confidence %v, want %v (%+v)", c.ip, conf, c.conf, rec.Sightings)
		}
	}
}

func TestParseSpamhausDROP(t *testing.T) {
	t.Parallel()
	meta := func(n int) string {
		return `{"type":"metadata","timestamp":1795674404,"size":1,"records":` + itoa(n) + `,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}` + "\n"
	}
	rec := func(cidr string) string { return `{"cidr":"` + cidr + `","sblid":"SBL1","rir":"ripencc"}` + "\n" }
	cases := []struct {
		name, body string
		want       []string
		rejected   int
		err        bool
	}{
		{"json", dropBody, []string{"80.0.2.0/24", "80.0.8.0/22"}, 0, false},
		{"a single address is stored as the address", rec("80.0.5.5/32") + rec("2a06:e480::1/128") + meta(2), []string{"80.0.5.5", "2a06:e480::1"}, 0, false},
		{"ipv6", rec("2a06:e480::/29") + meta(1), []string{"2a06:e480::/29"}, 0, false},
		{"a duplicate is one network", rec("80.0.2.0/24") + rec("80.0.2.0/24") + meta(2), []string{"80.0.2.0/24"}, 0, false},
		{"host bits set", rec("80.0.2.1/24") + rec("80.0.8.0/22") + meta(2), []string{"80.0.8.0/22"}, 1, false},
		{"private, reserved and documentation ranges", rec("10.0.0.0/8") + rec("192.168.0.0/16") + rec("100.64.0.0/10") + rec("198.51.100.0/24") + rec("2001:db8::/32") + rec("fc00::/8") + rec("80.0.8.0/22") + meta(7), []string{"80.0.8.0/22"}, 6, false},
		{"a network that covers a reserved range", rec("192.0.0.0/8") + rec("80.0.8.0/22") + meta(2), []string{"80.0.8.0/22"}, 1, false},
		{"too wide", rec("0.0.0.0/0") + rec("64.0.0.0/2") + rec("80.0.0.0/7") + rec("2a00::/12") + rec("80.0.8.0/22") + meta(5), []string{"80.0.8.0/22"}, 4, false},
		{"not a network", rec("80.0.2.0") + rec("80.0.2.0/33") + rec("80.0.2.0/-1") + rec("fe80::1%eth0/64") + rec("::ffff:80.0.2.0/120") + `{"sblid":"SBL1"}` + "\n" + `["80.0.2.0/24"]` + "\n" + "not json\n" + rec("80.0.8.0/22") + meta(9), []string{"80.0.8.0/22"}, 8, false},
		{"text form: comments after a semicolon", "; Spamhaus DROP List 2026/11/26 - (c) 2026 The Spamhaus Project SLU\n; https://www.spamhaus.org/drop/drop.txt\n\n80.0.2.0/24 ; SBL000001\r\n80.0.8.0/22;SBL000002\nbad ; SBL3\n; EOF\n", []string{"80.0.2.0/24", "80.0.8.0/22"}, 1, false},
		{"cut short: fewer records than the metadata counts", rec("80.0.2.0/24") + meta(2), nil, 0, true},
		{"cut short: no metadata", rec("80.0.2.0/24") + rec("80.0.8.0/22"), nil, 0, true},
		{"metadata not last", meta(1) + rec("80.0.2.0/24"), nil, 0, true},
		{"two metadata records", rec("80.0.2.0/24") + meta(1) + meta(1), nil, 0, true},
		{"empty", "", nil, 0, true},
	}
	for _, c := range cases {
		l, err := ParseSpamhausDROP([]byte(c.body), 100)
		if (err != nil) != c.err {
			t.Errorf("%s: error %v", c.name, err)
			continue
		}
		if c.err {
			if !errors.Is(err, ErrBadSample) {
				t.Errorf("%s: error %v is not a bad sample", c.name, err)
			}
			continue
		}
		if strings.Join(l.Prefixes, " ") != strings.Join(c.want, " ") || l.Rejected != c.rejected || l.Accepted != len(c.want) {
			t.Errorf("%s: %v accepted %d rejected %d (%v), want %v rejected %d", c.name, l.Prefixes, l.Accepted, l.Rejected, l.Reasons, c.want, c.rejected)
		}
	}
	// more networks than the row cap: the list is refused whole, never cut
	var many strings.Builder
	for i := range 101 {
		many.WriteString(rec("80.1." + itoa(i) + ".0/24"))
	}
	many.WriteString(meta(101))
	if _, err := ParseSpamhausDROP([]byte(many.String()), 100); !errors.Is(err, ErrBadSample) {
		t.Errorf("over the cap: %v", err)
	}
	if _, err := ParseSpamhausDROP([]byte(strings.Repeat(" ", MaxBodyBytes+1)), 100); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the size limit: %v", err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// Whatever the input, what the DROP parser accepts is a canonical public network within the length bounds, never more than the cap,
// and every dropped row is counted with a reason.
func FuzzParseSpamhausDROP(f *testing.F) {
	f.Add([]byte(dropBody))
	f.Add([]byte("80.0.2.0/24 ; SBL1\n; EOF\n"))
	f.Add([]byte(`{"cidr":"2a06:e480::/29"}` + "\n" + `{"type":"metadata","records":1}`))
	f.Add([]byte(`{"cidr":"10.0.0.0/8"}` + "\n" + `{"type":"metadata","records":1e309}`))
	f.Add([]byte("{\"cidr\":\"80.0.2.0/24\"\x00}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := ParseSpamhausDROP(data, 50)
		if err != nil {
			return
		}
		if l.Accepted != len(l.Prefixes) || len(l.Prefixes) > 50 || len(l.Prefixes) == 0 {
			t.Fatalf("accounting: accepted %d, %d networks", l.Accepted, len(l.Prefixes))
		}
		sum := 0
		for _, r := range l.Reasons {
			sum += r.Count
		}
		if sum != l.Rejected {
			t.Fatalf("reasons sum %d != rejected %d", sum, l.Rejected)
		}
		seen := map[string]bool{}
		for _, v := range l.Prefixes {
			if seen[v] {
				t.Fatalf("duplicate %q", v)
			}
			seen[v] = true
			if a, err := netip.ParseAddr(v); err == nil {
				if a.String() != v || isSpecialAddr(a) {
					t.Fatalf("bad address accepted: %q", v)
				}
				continue
			}
			p, err := netip.ParsePrefix(v)
			if err != nil || p.String() != v || p.Masked() != p || p.Addr().Is4In6() {
				t.Fatalf("not a canonical network: %q", v)
			}
			lo, hi := dropMinBits4, 31
			if p.Addr().Is6() {
				lo, hi = dropMinBits6, 127
			}
			if p.Bits() < lo || p.Bits() > hi {
				t.Fatalf("length out of bounds: %q", v)
			}
			for _, sp := range specialPrefixes {
				if sp.Overlaps(p) {
					t.Fatalf("network overlaps the reserved range %s: %q", sp, v)
				}
			}
		}
	})
}
