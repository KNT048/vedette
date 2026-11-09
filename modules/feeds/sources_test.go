package feeds

import (
	"net/url"
	"testing"
)

func TestContract_INV1_BuiltinSourcesAreDeclaredHTTPS(t *testing.T) {
	t.Parallel()
	// Exactly the hosts listed in PRIVACY.md flow 1.
	allowed := map[string]bool{
		"www.cisa.gov": true, "api.first.org": true, "raw.githubusercontent.com": true,
		"rules.emergingthreats.net": true, "feodotracker.abuse.ch": true, "sslbl.abuse.ch": true, "check.torproject.org": true,
	}
	seenID, seenName := map[string]bool{}, map[string]bool{}
	for _, s := range BuiltinSources() {
		u, err := url.Parse(s.URL)
		if err != nil || u.Scheme != "https" || !allowed[u.Host] {
			t.Errorf("%s: URL %q is not an allowed https source", s.ID, s.URL)
		}
		if err := CheckURL(s.URL); err != nil {
			t.Errorf("%s: default URL fails INV-2: %v", s.ID, err)
		}
		if err := CheckInterval(s.IntervalHours); err != nil {
			t.Errorf("%s: %v", s.ID, err)
		}
		if s.Kind == KindVulnerabilities && s.IntervalHours != 24 || s.Kind == KindIOC && s.IntervalHours != 6 {
			t.Errorf("%s: default interval %d", s.ID, s.IntervalHours)
		}
		if seenID[s.ID] || seenName[s.Name] {
			t.Errorf("duplicate built-in %s / %s", s.ID, s.Name)
		}
		seenID[s.ID], seenName[s.Name] = true, true
		if s.Decoder == DecoderParser {
			if s.Parser == nil || s.Parser.Format != s.Format {
				t.Errorf("%s: missing or mismatched parser", s.ID)
			}
		} else if s.Parser != nil {
			t.Errorf("%s: dedicated decoder must not carry a parser", s.ID)
		}
	}
	if len(seenID) != 9 {
		t.Fatalf("expected the 9 built-ins of sourcesMock.ts, got %d", len(seenID))
	}
}

func TestBuiltinLookupAndBlockClass(t *testing.T) {
	t.Parallel()
	if _, ok := BuiltinByID("nope"); ok {
		t.Fatal("unknown id found")
	}
	feodo, _ := BuiltinByID("abusech-feodo")
	ipsum, _ := BuiltinByID("ipsum")
	kev, _ := BuiltinByID("cisa-kev")
	if !feodo.BlockClass() || ipsum.BlockClass() || kev.BlockClass() {
		t.Fatal("BlockClass: only CC0 IOC lists qualify")
	}
	// Mutating the returned slice must not change the registry.
	l := BuiltinSources()
	l[0].Name = "changed"
	if s, _ := BuiltinByID("cisa-kev"); s.Name != "CISA KEV" {
		t.Fatal("registry mutated through the copy")
	}
}

func TestProductKey(t *testing.T) {
	t.Parallel()
	if got := ProductKey("QNAP", "Photo Station"); got != "qnap|photo station" {
		t.Fatalf("ProductKey = %q", got)
	}
}

func TestDefaultParserShape(t *testing.T) {
	t.Parallel()
	for _, k := range []Kind{KindVulnerabilities, KindIOC} {
		for _, f := range FormatsFor(k) {
			p := DefaultParser(k, f)
			if p.Format != f || len(p.Fields) != len(FieldIDs(k)) || !p.HasHeader || p.Delimiter != "," {
				t.Errorf("%s/%s: bad default parser %+v", k, f, p)
			}
			for id, fmap := range p.Fields {
				if !fmap.Trim || fmap.DateFormat != DateAuto && (id != "date" || fmap.DateFormat != DateDMY) {
					t.Errorf("%s/%s/%s: unexpected field map %+v", k, f, id, fmap)
				}
			}
		}
	}
}
