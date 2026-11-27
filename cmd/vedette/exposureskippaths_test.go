package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// The web paths to skip against every request a nuclei template can send, over the committed pack: a template runs only when all
// of its requests are known and outside every prefix to skip.

// sentIDs runs one scan of the box's own IP with skip as the web paths to skip and returns the ids handed to nuclei and the lines.
func sentIDs(t *testing.T, full bool, skip []string, jobs ...exposure.TemplateJob) ([]string, []string) {
	t.Helper()
	f := &templatesFake{gateOK: true, answer: func(r sensoractive.NucleiRequest) nucleiout.Outcome {
		var o nucleiout.Outcome
		for _, id := range r.Templates {
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: "8.8.8.8:18443"})
		}
		return o
	}}
	a := f.scanner()
	st := exposure.ScanTarget{User: "u-admin"}
	if full {
		a.mode = (&modes{list: []exposure.ScanMode{modeAllGroups}}).now
		st = fullTarget(true)
	}
	st.SkipPaths = skip
	got, err := a.ScanTemplates(t.Context(), st, ownPublicIP, jobs)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range f.reqs {
		ids = append(ids, r.Templates...)
	}
	return ids, got.NotChecked
}

// A path: template whose second request is under a prefix (CVE-2020-36289: /secure/…, then /jira/secure/…) is not sent; a raw
// template whose second request is under one (CVE-2022-2314: GET /wp-content/…, then GET /wp-admin/admin-post.php) is not sent
// either; a template whose requests are all outside (CVE-2010-1870: /lui/, /hub/) is sent. The run says how many were left out.
func TestSkipPaths_ALaterRequestUnderAPrefixKeepsTheTemplateOut(t *testing.T) {
	t.Parallel()
	job := fullJobOf("CVE-2020-36289", "CVE-2022-2314", "CVE-2010-1870")
	ids, _ := sentIDs(t, true, nil, job)
	for _, id := range []string{"CVE-2020-36289", "CVE-2022-2314", "CVE-2010-1870"} {
		if !slices.Contains(ids, id) {
			t.Fatalf("with no paths to skip %s is not sent: %q", id, ids)
		}
	}
	ids, lines := sentIDs(t, true, []string{"/jira/", "/wp-admin/"}, job)
	for _, id := range []string{"CVE-2020-36289", "CVE-2022-2314"} {
		if slices.Contains(ids, id) {
			t.Errorf("%s was sent although one of its requests is under a path to skip", id)
		}
	}
	if !slices.Contains(ids, "CVE-2010-1870") {
		t.Errorf("CVE-2010-1870 (every request outside the paths to skip) was not sent: %q", ids)
	}
	if !slices.ContainsFunc(lines, func(l string) bool {
		return strings.Contains(l, "left out") && strings.Contains(l, "/jira/, /wp-admin/") && strings.Contains(l, "port 18443")
	}) {
		t.Errorf("no line says what the paths left out: %q", lines)
	}
}

// The read-only check of the box's own IP (KEV set, own_ip) holds the same rule: CVE-2021-40875 asks /files.md5, then
// /testrail/files.md5.
func TestSkipPaths_TheOwnIPCheckLeavesOutALaterRequestUnderAPrefix(t *testing.T) {
	t.Parallel()
	if ids, _ := sentIDs(t, false, nil, ownJob("CVE-2021-40875")); !slices.Contains(ids, "CVE-2021-40875") {
		t.Fatalf("with no paths to skip CVE-2021-40875 is not sent: %q", ids)
	}
	if ids, _ := sentIDs(t, false, []string{"/testrail"}, ownJob("CVE-2021-40875")); slices.Contains(ids, "CVE-2021-40875") {
		t.Fatal("CVE-2021-40875 was sent although its second request is under /testrail")
	}
	if ids, _ := sentIDs(t, false, []string{"/other"}, ownJob("CVE-2021-40875")); !slices.Contains(ids, "CVE-2021-40875") {
		t.Fatal("CVE-2021-40875 was left out for a path none of its requests is under")
	}
}

// Without web paths to skip, what nuclei is handed is exactly what it was before the paths were checked against every request:
// the requests of a full scan and of the own_ip check, hashed (the value was taken on the code before the change).
func TestSkipPaths_NoPathsToSkipChangesNothing(t *testing.T) {
	t.Parallel()
	run := func(full bool, job exposure.TemplateJob) []sensoractive.NucleiRequest {
		f := &templatesFake{gateOK: true, answer: func(r sensoractive.NucleiRequest) nucleiout.Outcome {
			var o nucleiout.Outcome
			for _, id := range r.Templates {
				o.Results = append(o.Results, nucleiout.Result{Template: id, Target: "8.8.8.8:18443", Matched: id == "wordpress-detect"})
			}
			return o
		}}
		a := f.scanner()
		st := exposure.ScanTarget{User: "u-admin"}
		if full {
			a.mode = (&modes{list: []exposure.ScanMode{modeAllGroups}}).now
			st = fullTarget(true)
		}
		if _, err := a.ScanTemplates(t.Context(), st, ownPublicIP, []exposure.TemplateJob{job}); err != nil {
			t.Fatal(err)
		}
		return f.reqs
	}
	reqs := append(run(true, fullJobOf("CVE-2020-36289", "CVE-2022-2314", "CVE-2010-1870", "CVE-2018-13379")),
		run(false, ownJob("CVE-2021-40875", "CVE-2018-13379", "CVE-2019-19781"))...)
	raw, err := json.Marshal(reqs)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != noSkipRequestsSHA256 {
		t.Fatalf("the nuclei requests without paths to skip changed: sha256 %s, was %s (%d requests)", got, noSkipRequestsSHA256, len(reqs))
	}
}

const noSkipRequestsSHA256 = "7db0fb2fb612f6777eaf459952da9b7a85d868b4f27edf2bee5b0f3aab5bfe11"
