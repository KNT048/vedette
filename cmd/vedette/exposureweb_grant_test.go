package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// authorizingZapHost is a fake host that also answers zap.authorize.
type authorizingZapHost struct {
	*fakeZapHost
	args   []api.ZapAuthorizeArgs
	actors []string
	auth   api.Run
	err    error
}

func (h *authorizingZapHost) ZapAuthorize(_ context.Context, args api.ZapAuthorizeArgs, _, actor string) (api.Run, error) {
	h.args, h.actors = append(h.args, args), append(h.actors, actor)
	return h.auth, h.err
}

// A person's press asks the host for its grant with the person's actor label and the box's IP; the grant goes back to the host with
// the pages that ask for the disruptive rules, never with the others.
func TestExposureWeb_APersonsPressGetsTheHostsGrantAndSendsIt(t *testing.T) {
	t.Parallel()
	const grant = "0123456789abcdef0123456789abcdef"
	ok := api.Run{Command: api.CmdZapAuthorize, Status: api.StatusSucceeded}
	ok.Result, _ = json.Marshal(api.ZapAuthorizeResult{Grant: grant})
	run := zapRun(t, api.StatusSucceeded, "", nil)
	run.Command = api.CmdZapActive
	run.Result, _ = json.Marshal(api.ZapActiveResult{ReportID: "0123456789abcdef0123456789abcdef", Size: 11})
	h := &authorizingZapHost{fakeZapHost: &fakeZapHost{run: run, report: []byte(`{"site":[]}`)}, auth: ok}
	w := exposureWebScan{host: h}
	g, err := w.GrantDisruptive(t.Context(), "admin@example.com", netip.MustParseAddr("93.184.216.34"))
	if err != nil || g != grant || len(h.args) != 1 || h.args[0].IP != "93.184.216.34" || h.actors[0] != "exposure:admin@example.com" {
		t.Fatalf("grant %q %v, args %+v, actors %q", g, err, h.args, h.actors)
	}
	h.auth = api.Run{Command: api.CmdZapAuthorize, Status: api.StatusRefused, Error: &api.RunError{Code: api.CodeZapGrantNotPerson, Message: "host text"}}
	if g, err := w.GrantDisruptive(t.Context(), "admin@example.com", netip.MustParseAddr("93.184.216.34")); err == nil || g != "" {
		t.Fatalf("a refused grant: %q %v", g, err)
	}
	h.err = errors.New("the host socket is gone")
	if g, err := w.GrantDisruptive(t.Context(), "admin@example.com", netip.MustParseAddr("93.184.216.34")); err == nil || g != "" {
		t.Fatalf("an unreachable host: %q %v", g, err)
	}
	h.err = nil
	if _, err := (exposureWebScan{host: &fakeZapHost{}}).GrantDisruptive(t.Context(), "admin@example.com", netip.MustParseAddr("93.184.216.34")); err == nil {
		t.Fatal("a host without zap.authorize gave a grant")
	}
	ipT := webIPTarget
	ipT.Mode, ipT.Grant = modeAllGroups, grant
	if _, err := w.Active(t.Context(), ipT, webIPPage); err != nil || !h.active[0].Disruptive || h.active[0].Grant != grant {
		t.Fatalf("a page with the disruptive rules: %+v %v", h.active, err)
	}
	ipT.Mode.Disruptive = false
	if _, err := w.Active(t.Context(), ipT, webIPPage); err != nil || h.active[1].Disruptive || h.active[1].Grant != "" {
		t.Fatalf("a page without them: %+v", h.active[1])
	}
}

// The host's refusal of the disruptive rules reaches exposure as a plain sentence, one for each of the host's codes.
func TestExposureWeb_TheHostsRefusalOfTheDisruptiveRulesIsSaid(t *testing.T) {
	t.Parallel()
	ipT := webIPTarget
	ipT.Mode, ipT.Grant = modeAllGroups, "0123456789abcdef0123456789abcdef"
	seen := map[string]bool{}
	for _, code := range []string{api.ZapRefusedGrantMissing, api.ZapRefusedGrantUnknown, api.ZapRefusedGrantExpired, api.ZapRefusedGrantSpent,
		api.ZapRefusedGrantMismatch, api.ZapRefusedGatewayShared, api.ZapRefusedGatewayUnreadable, "zap_something_new"} {
		run := zapRun(t, api.StatusSucceeded, "", nil)
		run.Command = api.CmdZapActive
		run.Result, _ = json.Marshal(api.ZapActiveResult{ReportID: "0123456789abcdef0123456789abcdef", Size: 11, DisruptiveRefused: code})
		w := exposureWebScan{host: &fakeZapHost{run: run, report: []byte(`{"site":[]}`)}}
		got, err := w.Active(t.Context(), ipT, webIPPage)
		if err != nil || got.DisruptiveRefused == "" || strings.Contains(got.DisruptiveRefused, "zap_grant") || seen[got.DisruptiveRefused] {
			t.Errorf("%s: %q %v", code, got.DisruptiveRefused, err)
		}
		seen[got.DisruptiveRefused] = true
	}
}

// A person whose e-mail is outside the host's actor alphabet (a "+" tag, a long address) still presses as a person: the grant and the
// zap.active runs of the scan carry the same person label, one the host accepts as a person's (exposure:<label>, never the bare
// "exposure" the host refuses a grant for), and two such people get two labels.
func TestExposureWeb_APersonOutsideTheActorAlphabetStillGetsAGrant(t *testing.T) {
	t.Parallel()
	hostActor := regexp.MustCompile(`^[a-zA-Z0-9_.@:-]{1,64}$`)
	const grant = "0123456789abcdef0123456789abcdef"
	ok := api.Run{Command: api.CmdZapAuthorize, Status: api.StatusSucceeded}
	ok.Result, _ = json.Marshal(api.ZapAuthorizeResult{Grant: grant})
	run := zapRun(t, api.StatusSucceeded, "", nil)
	run.Command = api.CmdZapActive
	run.Result, _ = json.Marshal(api.ZapActiveResult{ReportID: "0123456789abcdef0123456789abcdef", Size: 11})
	labels := map[string]string{}
	for _, user := range []string{"admin+scans@example.com", "a.very.long.mailbox.name.of.the.security.team@subdomain.example.com"} {
		h := &authorizingZapHost{fakeZapHost: &fakeZapHost{run: run, report: []byte(`{"site":[]}`)}, auth: ok}
		w := exposureWebScan{host: h}
		if _, err := w.GrantDisruptive(t.Context(), user, netip.MustParseAddr("93.184.216.34")); err != nil {
			t.Fatal(err)
		}
		ipT := webIPTarget
		ipT.User, ipT.Mode, ipT.Grant = user, modeAllGroups, grant
		if _, err := w.Active(t.Context(), ipT, webIPPage); err != nil {
			t.Fatal(err)
		}
		label := h.actors[0]
		who, isPerson := strings.CutPrefix(label, "exposure:")
		if !isPerson || who == "" || strings.EqualFold(who, "system") || !hostActor.MatchString(label) || h.actor != label {
			t.Fatalf("%s: grant asked as %q, its run labelled %q", user, label, h.actor)
		}
		labels[label] = user
	}
	if len(labels) != 2 {
		t.Fatalf("two people share one label: %q", labels)
	}
}

// Without the host's grant core never asks for the disruptive rules: a request with disruptive and no grant is how a core older than
// the grant asks, and the host answers it as a page that did not run every rule. The page runs without them and says why.
func TestExposureWeb_NoGrantMeansThePageAsksForNoDisruptiveRules(t *testing.T) {
	t.Parallel()
	run := zapRun(t, api.StatusSucceeded, "", nil)
	run.Command = api.CmdZapActive
	run.Result, _ = json.Marshal(api.ZapActiveResult{ReportID: "0123456789abcdef0123456789abcdef", Size: 11})
	h := &fakeZapHost{run: run, report: []byte(`{"site":[]}`)}
	ipT := webIPTarget
	ipT.Mode = modeAllGroups
	got, err := (exposureWebScan{host: h}).Active(t.Context(), ipT, webIPPage)
	if err != nil || len(h.active) != 1 || h.active[0].Disruptive || h.active[0].Grant != "" || got.DisruptiveRefused == "" {
		t.Fatalf("a page without a grant: sent %+v, refused %q, %v", h.active, got.DisruptiveRefused, err)
	}
}
