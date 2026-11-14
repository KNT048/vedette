package nucleipack

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/scan/pack"
)

// D-520 over the real committed index: every template marked own_ip is an http GET or HEAD check without a refused tag, and the
// known state-changing, credential and command templates of the pack are not marked (review H1). CVE-2021-41773 is not marked
// either: its template ends with a POST that runs a command on the server when the read-only GETs did not match.
func TestOwnIPTemplatesOfTheCommittedPack(t *testing.T) {
	t.Parallel()
	ix, err := Index()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, tp := range ix.Templates {
		if !tp.OwnIP {
			continue
		}
		n++
		if !strings.HasPrefix(tp.Path, "http/") || !strings.HasPrefix(tp.Request, "GET ") && !strings.HasPrefix(tp.Request, "HEAD ") {
			t.Errorf("%s: own_ip but %q under %s", tp.ID, tp.Request, tp.Path)
		}
		for _, tag := range tp.Tags {
			if pack.OwnIPRefusedTag(tag) {
				t.Errorf("%s: own_ip with tag %s", tp.ID, tag)
			}
		}
	}
	if n < 100 || n > len(ix.Templates)/2 {
		t.Errorf("%d of %d templates marked own_ip: the rule changed, look again before shipping", n, len(ix.Templates))
	}
	byID := map[string]pack.Template{}
	for _, tp := range ix.Templates {
		byID[tp.ID] = tp
	}
	for _, id := range []string{
		"CVE-2021-29203",                                                    // PATCH: resets an HPE password
		"CVE-2024-2862",                                                     // PUT: changes an LG password
		"CVE-2024-50334",                                                    // PUT /api;/config
		"CVE-2024-6396",                                                     // file-write
		"CVE-2020-9043", "CVE-2025-2075", "CVE-2018-7602", "CVE-2022-37061", // log in with credentials (wp-login, user/login, dologin)
		"CVE-2019-9733",                    // tag login
		"CVE-2025-4396",                    // time-based-sqli
		"CVE-2022-31499",                   // a command in a delay
		"CVE-2026-0768",                    // code-injection
		"CVE-2007-3010",                    // a command in the query
		"CVE-2020-36333",                   // resets a WordPress site by GET
		"CVE-2022-36804",                   // a command by GET
		"CVE-2021-41773", "CVE-2021-42013", // a POST that runs a command after the GETs
		"CVE-2025-2636",  // an SQL comment injection by GET that dumps wp_users (review round 2 M1)
		"CVE-2024-52875", // a CRLF header injection and a base64 <script> by GET
		"CVE-2024-11740", // a shortcode injection through %27 by GET
	} {
		tp, ok := byID[id]
		if !ok {
			t.Errorf("%s is not in the pack any more: pick another known bad template", id)
		} else if tp.OwnIP {
			t.Errorf("%s is marked own_ip", id)
		}
	}
	for _, id := range []string{"CVE-2018-13379", "CVE-2019-19781", "CVE-2024-38816"} { // read-only GETs (a file read)
		if !byID[id].OwnIP {
			t.Errorf("%s, a read-only GET, is not marked own_ip", id)
		}
	}
}
