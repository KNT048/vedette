package nucleipack

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/pack"
)

// D-527 over the real committed index: the KEV set is the one of D-520 (988 templates, 186 own_ip), the deep set never holds a
// template of the disruptive checks, a write method or an out-of-band check, and the known writes stay out of every full set.
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
	if n["kev"] != 988 || n["own_ip"] != 186 {
		t.Errorf("KEV set %d, own_ip %d: D-527 must not change them (988, 186)", n["kev"], n["own_ip"])
	}
	if n["deep"] < 5000 || n["disruptive"] < 300 {
		t.Errorf("deep %d, disruptive %d: the rule changed, look again before shipping", n["deep"], n["disruptive"])
	}
	for _, id := range []string{"CVE-2021-29203", "CVE-2024-2862", "CVE-2024-50334", "CVE-2025-47539"} { // PATCH, PUT, out-of-band: KEV only, never at full depth
		if tp, ok := ix.Get(id); !ok || tp.FullSet() != "" {
			t.Errorf("%s: %+v", id, tp)
		}
	}
	if tp, ok := ix.Get("git-config"); !ok || tp.FullSet() != pack.SetDeep || !tp.Generic {
		t.Errorf("git-config, the exposed .git a deep scan must find: %+v", tp)
	}
}
