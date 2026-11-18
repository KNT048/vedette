package ops

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/host/api"
)

const typedTestIP = "9.9.9.9"

type typedFiles struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *typedFiles) Fetch(_ context.Context, rawURL string, _ netip.Addr) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.m[rawURL]; ok {
		return []byte(v), nil
	}
	return nil, errors.New("answered 404")
}

func typedWorld(t *testing.T, files map[string]string) *zapWorld {
	t.Helper()
	w := newZapWorld(t, Deps{FenceFetcher: &typedFiles{m: files}})
	w.o.fenceMu.Lock()
	w.o.fenceList[typedTestIP] = true // the host issued the IP's token
	w.o.fenceMu.Unlock()
	return w
}

func typedArgs(tok string) api.ExposureFenceCheckArgs {
	return api.ExposureFenceCheckArgs{Domain: typedTestIP, Name: typedTestIP, IP: typedTestIP, Token: tok, Typed: &api.ExposureTyped{Method: domainfence.MethodFile}}
}

// The host re-checks a typed IP itself: a proof core found is not taken on its word.
func TestExposureFenceCheck_TypedIP(t *testing.T) {
	t.Parallel()
	good := domainfence.Token(zapTestKey, typedTestIP)
	forged := domainfence.Token([]byte("ffffffffffffffffffffffffffffffff"), typedTestIP)
	served := map[string]string{"http://" + typedTestIP + domainfence.ProofPath: good}
	for name, c := range map[string]struct {
		files map[string]string
		a     api.ExposureFenceCheckArgs
		want  string
	}{
		"a proved IP":                     {served, typedArgs(good), ""},
		"a forged token in the job":       {map[string]string{"http://" + typedTestIP + domainfence.ProofPath: forged}, typedArgs(forged), api.CodeTokenForeign},
		"the file is gone":                {map[string]string{}, typedArgs(good), api.CodeTargetNotOwned},
		"the file holds another token":    {map[string]string{"http://" + typedTestIP + domainfence.ProofPath: forged}, typedArgs(good), api.CodeTargetNotOwned},
		"the token is on another address": {map[string]string{"http://9.9.9.8" + domainfence.ProofPath: good}, typedArgs(good), api.CodeTargetNotOwned},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := typedWorld(t, c.files)
			_, err := w.o.fenceCheck(t.Context(), nolog, c.a)
			if code := fenceCode(err); code != c.want {
				t.Fatalf("%v, want %q", err, c.want)
			}
		})
	}
	// an IP the host never issued a token for is refused like a foreign token, a private one never reaches the fence
	w := newZapWorld(t, Deps{FenceFetcher: &typedFiles{m: served}})
	if _, err := w.o.fenceCheck(t.Context(), nolog, typedArgs(good)); fenceCode(err) != api.CodeTokenForeign {
		t.Fatalf("an IP off the host's list: %v", err)
	}
	bad := typedArgs(good)
	bad.IP, bad.Domain, bad.Name = "10.0.0.1", "10.0.0.1", "10.0.0.1"
	if _, err := fenceJob(bad); err == nil {
		t.Fatal("a private IP was accepted")
	}
}

func TestExposureToken_IssuesForATypedIPAndNeverForAPrivateOne(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	if _, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: typedTestIP}); err != nil {
		t.Fatal(err)
	}
	if l, _ := w.o.loadFenceList(); !l[typedTestIP] {
		t.Fatal("the IP is not on the host's list")
	}
	for _, bad := range []string{"10.0.0.1", "9.9.9.09", "::1"} {
		if _, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: bad}); err == nil {
			t.Errorf("%s was given a token", bad)
		}
	}
}

func TestZapBaseline_TypedIPPageIsCheckedByTheHost(t *testing.T) {
	t.Parallel()
	good := domainfence.Token(zapTestKey, typedTestIP)
	page := func(tok string) api.ZapBaselineArgs {
		return api.ZapBaselineArgs{URL: "http://" + typedTestIP + "/", Host: typedTestIP, IP: typedTestIP, Port: 80, Kind: api.ZapKindIP, TXTToken: tok,
			Typed: &api.ExposureTyped{Method: domainfence.MethodFile}}
	}
	w := typedWorld(t, map[string]string{"http://" + typedTestIP + domainfence.ProofPath: good})
	p, err := zapArgs(page(good))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.o.zapOwned(t.Context(), nolog, p); err != nil {
		t.Fatalf("a proved IP: %v", err)
	}
	w2 := typedWorld(t, map[string]string{}) // the file is gone
	if err := w2.o.zapOwned(t.Context(), nolog, p); fenceCode(err) != api.CodeTargetNotOwned {
		t.Fatalf("no proof: %v", err)
	}
	forged := domainfence.Token([]byte("ffffffffffffffffffffffffffffffff"), typedTestIP)
	pf, err := zapArgs(page(forged))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.o.zapOwned(t.Context(), nolog, pf); fenceCode(err) != api.CodeTokenForeign {
		t.Fatalf("a forged token: %v", err)
	}
	if _, err := zapArgs(api.ZapBaselineArgs{URL: "http://" + typedTestIP + "/", Host: typedTestIP, IP: typedTestIP, Port: 80, Kind: api.ZapKindIP, Typed: page(good).Typed}); err == nil {
		t.Fatal("a typed IP page with no token was accepted")
	}
}
