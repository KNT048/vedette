package nucleipack

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/pack"
)

// D-527 over the real committed index: the KEV set is the one of D-528 (928 templates, 186 own_ip), the deep set never holds a
// template of the disruptive checks, a write method or an out-of-band check, and the templates of review FULL-4b r1 are out or
// behind the tick.
func TestFullSetsOfTheCommittedPack(t *testing.T) {
	t.Parallel()
	ix, err := Index()
	if err != nil {
		t.Fatal(err)
	}
	n := map[string]int{}
	for _, tp := range ix.Templates {
		for _, s := range tp.Sets {
			n[s]++
		}
		if tp.OwnIP {
			n["own_ip"]++
		}
		if tp.FullSet() == pack.SetDeep {
			for _, tag := range append(nucleiargv.DisruptiveTags(), "intrusive", "fuzz", "oast") {
				for _, x := range tp.Tags {
					if x == tag {
						t.Errorf("%s: tag %s in the deep set", tp.ID, tag)
					}
				}
			}
			if strings.HasPrefix(tp.Path, "http/default-logins/") || strings.HasPrefix(tp.Request, "PUT ") || strings.HasPrefix(tp.Request, "DELETE ") || strings.HasPrefix(tp.Request, "PATCH ") {
				t.Errorf("%s (%s, %q) in the deep set", tp.ID, tp.Path, tp.Request)
			}
		}
	}
	if n["kev"] != 327 || n["own_ip"] != 185 {
		t.Errorf("KEV set %d, own_ip %d: D-527 must not change the KEV set of D-528 step 2 (327, 185)", n["kev"], n["own_ip"])
	}
	// D-528 step 2: without the tick only read-only GETs and the reviewed list (4 non-GET http checks, the TLS handshakes)
	post := 0
	for _, tp := range ix.Templates {
		if tp.FullSet() == pack.SetDeep && !strings.HasPrefix(tp.Request, "GET ") && !strings.HasPrefix(tp.Request, "HEAD ") && !strings.HasPrefix(tp.Path, "ssl/") {
			post++
		}
	}
	if post > 4 {
		t.Errorf("%d deep templates are not GET or HEAD: only the reviewed ones may be", post)
	}
	if n["deep"] < 5000 || n["disruptive"] < 300 {
		t.Errorf("deep %d, disruptive %d: the rule changed, look again before shipping", n["deep"], n["disruptive"])
	}
	// review FULL-4b r1: writes, account creation and takeover, uploads, third parties and other ports are in no set (H1, H2, M1, M3)
	for _, id := range []string{"CVE-2022-1903", "CVE-2024-5276", "CVE-2024-4358", "CVE-2024-6396", "CVE-2023-26802", "weaver-group-xml-sqli",
		"CVE-2022-41352", "idocview-2word-fileupload", "gestsup-account-takeover", "dragonfly-public-signup", "rdap-whois", "azure-domain-tenant",
		"google-gemini-key-exposure", "hpe-autopass-panel", "CVE-2018-8024", "unifi-nfc-credentials", "CVE-2021-22054", "microstrategy-ssrf",
		"imgproxy-unauth", "CVE-2021-29203", "CVE-2024-2862"} {
		if tp, ok := ix.Get(id); ok {
			t.Errorf("%s is in the pack: %+v", id, tp.Sets)
		}
	}
	// M2: logins with known credentials need the tick
	for _, id := range []string{"CVE-2019-15642", "CVE-2023-38433", "CVE-2025-34509", "CVE-2013-4982", "CVE-2021-41691", "CVE-2020-17463"} {
		if tp, ok := ix.Get(id); ok && tp.FullSet() != pack.SetDisruptive {
			t.Errorf("%s: sets %v, want disruptive", id, tp.Sets)
		}
	}
	for _, tp := range ix.Templates {
		if slices.Contains(tp.Tags, "osint") {
			t.Errorf("%s: tag osint in the pack", tp.ID)
		}
	}
	if tp, ok := ix.Get("git-config"); !ok || tp.FullSet() != pack.SetDeep || !tp.Generic {
		t.Errorf("git-config, the exposed .git a deep scan must find: %+v", tp)
	}
}
