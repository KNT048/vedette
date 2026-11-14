package ops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// zap.baseline (D-521): the argv, the egress rule and the flow of a run, against a fake podman and nft that never run anything.

const (
	zapTestIP  = "93.184.216.34"
	zapTestTok = "0123456789abcdef"
)

func zapIP(t *testing.T) netip.Addr { t.Helper(); return netip.MustParseAddr(zapTestIP) }

func TestZapArgs(t *testing.T) {
	t.Parallel()
	ip := func(m func(*api.ZapBaselineArgs)) api.ZapBaselineArgs {
		a := api.ZapBaselineArgs{URL: "https://" + zapTestIP + ":8443/", Host: zapTestIP, IP: zapTestIP, Port: 8443, Kind: api.ZapKindIP}
		if m != nil {
			m(&a)
		}
		return a
	}
	dom := func(m func(*api.ZapBaselineArgs)) api.ZapBaselineArgs {
		a := api.ZapBaselineArgs{URL: "https://www.example.com/", Host: "www.example.com", IP: zapTestIP, Port: 443, Kind: api.ZapKindDomain, Domain: "example.com", TXTToken: zapTestTok}
		if m != nil {
			m(&a)
		}
		return a
	}
	for name, a := range map[string]api.ZapBaselineArgs{
		"ip":             ip(nil),
		"ip on port 80":  ip(func(a *api.ZapBaselineArgs) { a.URL, a.Port = "http://"+zapTestIP+"/", 80 }),
		"domain":         dom(nil),
		"the domain too": dom(func(a *api.ZapBaselineArgs) { a.URL, a.Host = "https://example.com/", "example.com" }),
	} {
		if _, err := zapArgs(a); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		a     api.ZapBaselineArgs
		field string
	}{
		"private IP": {ip(func(a *api.ZapBaselineArgs) {
			a.IP, a.Host, a.URL = "192.168.1.10", "192.168.1.10", "https://192.168.1.10:8443/"
		}), "args.ip"},
		"CGNAT IP":            {ip(func(a *api.ZapBaselineArgs) { a.IP = "100.64.1.1" }), "args.ip"},
		"loopback":            {dom(func(a *api.ZapBaselineArgs) { a.IP = "127.0.0.1" }), "args.ip"},
		"IPv6":                {dom(func(a *api.ZapBaselineArgs) { a.IP = "2606:2800:220:1::1" }), "args.ip"},
		"port 0":              {ip(func(a *api.ZapBaselineArgs) { a.Port = 0 }), "args.port"},
		"port 70000":          {ip(func(a *api.ZapBaselineArgs) { a.Port = 70000 }), "args.port"},
		"URL port differs":    {ip(func(a *api.ZapBaselineArgs) { a.Port = 9443 }), "args.url"},
		"URL with a path":     {dom(func(a *api.ZapBaselineArgs) { a.URL = "https://www.example.com/admin" }), "args.url"},
		"URL with a query":    {dom(func(a *api.ZapBaselineArgs) { a.URL = "https://www.example.com/?a=1" }), "args.url"},
		"URL with a user":     {dom(func(a *api.ZapBaselineArgs) { a.URL = "https://u:p@www.example.com/" }), "args.url"},
		"default port spelt":  {dom(func(a *api.ZapBaselineArgs) { a.URL = "https://www.example.com:443/" }), "args.url"},
		"ftp":                 {dom(func(a *api.ZapBaselineArgs) { a.URL = "ftp://www.example.com/" }), "args.url"},
		"URL host differs":    {dom(func(a *api.ZapBaselineArgs) { a.URL = "https://evil.example.net/" }), "args.url"},
		"name of another":     {dom(func(a *api.ZapBaselineArgs) { a.URL, a.Host = "https://example.com.evil.net/", "example.com.evil.net" }), "args.host"},
		"suffix not a label":  {dom(func(a *api.ZapBaselineArgs) { a.URL, a.Host = "https://badexample.com/", "badexample.com" }), "args.host"},
		"ip with a name":      {ip(func(a *api.ZapBaselineArgs) { a.URL, a.Host = "https://www.example.com:8443/", "www.example.com" }), "args.host"},
		"ip with a domain":    {ip(func(a *api.ZapBaselineArgs) { a.Domain = "example.com" }), "args.domain"},
		"domain not a domain": {dom(func(a *api.ZapBaselineArgs) { a.Domain = "example" }), "args.domain"},
		"token not hex":       {dom(func(a *api.ZapBaselineArgs) { a.TXTToken = "$(reboot)" }), "args.txt_token"},
		"no token":            {dom(func(a *api.ZapBaselineArgs) { a.TXTToken = "" }), "args.txt_token"},
		"unknown kind":        {ip(func(a *api.ZapBaselineArgs) { a.Kind = "cidr" }), "args.kind"},
	} {
		_, err := zapArgs(tc.a)
		var ae *server.ArgsError
		if !errors.As(err, &ae) || len(ae.Details) != 1 || ae.Details[0].Field != tc.field {
			t.Errorf("%s: %v, want a refusal of %s", name, err, tc.field)
		}
	}
}

func TestZapRunArgvIsFixedAndValidated(t *testing.T) {
	t.Parallel()
	wrk := "/var/lib/vedette-host/zap/wrk"
	p, err := zapArgs(api.ZapBaselineArgs{URL: "https://www.example.com/", Host: "www.example.com", IP: zapTestIP, Port: 443, Kind: api.ZapKindDomain, Domain: "example.com", TXTToken: zapTestTok})
	if err != nil {
		t.Fatal(err)
	}
	got := p.runArgv(wrk)
	want := strings.Fields("--module /usr/lib/vedette/apparmor-containers.conf run --rm --pull=never --name vedette-zap --network vedette-zap --dns none" +
		" --add-host www.example.com:" + zapTestIP + " --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /home/zap:rw,size=256m,mode=0700,uid=1000,gid=1000" +
		" --volume /var/lib/vedette-host/zap/wrk:/zap/wrk:rw --user 1000:1000 --memory=1g --memory-swap=1g --pids-limit=256 --no-healthcheck " + zapImage +
		" zap-baseline.py -t https://www.example.com/ -m 1 -T 5 -J out.json -z")
	want = append(want, "-silent -Xmx512m -config spider.processform=false -config spider.postform=false -config spider.thread=1")
	if !slices.Equal(got, want) {
		t.Fatalf("argv\n%q\nwant\n%q", got, want)
	}
	if slices.Contains(got, "-a") || slices.Contains(got, "-u") || slices.Contains(got, "-j") {
		t.Fatal("an active scan, a config URL or the AJAX spider is in the argv")
	}
	if err := validatePodman(got); err != nil {
		t.Fatalf("the validator refuses the builder: %v", err)
	}
	ipPage, _ := zapArgs(api.ZapBaselineArgs{URL: "http://" + zapTestIP + ":8080/", Host: zapTestIP, IP: zapTestIP, Port: 8080, Kind: api.ZapKindIP})
	ipArgv := ipPage.runArgv(wrk)
	if slices.Contains(ipArgv, "--add-host") || validatePodman(ipArgv) != nil {
		t.Fatalf("the argv of an IP page: %q", ipArgv)
	}
	set := func(a []string, i int, v string) []string { a = slices.Clone(a); a[i] = v; return a }
	at := func(a []string, s string) int { return slices.Index(a, s) }
	for name, bad := range map[string][]string{
		"active scan":          append(slices.Clone(got), "-a"),
		"another URL":          set(got, at(got, "-t")+1, "https://evil.example.net/"),
		"a private add-host":   set(got, at(got, "--add-host")+1, "www.example.com:10.0.0.1"),
		"add-host not the URL": set(got, at(got, "--add-host")+1, "evil.example.net:"+zapTestIP),
		"a private IP URL":     set(ipArgv, at(ipArgv, "-t")+1, "http://10.0.0.1:8080/"),
		"no read-only":         set(got, at(got, "--read-only"), "--privileged"),
		"another network":      set(got, at(got, "--network")+1, "host"),
		"a dotdot work dir":    set(got, at(got, "--volume")+1, "/var/lib/../../etc:/zap/wrk:rw"),
		"the root mounted":     set(got, at(got, "--volume")+1, "/:/zap/wrk:rw"),
		"another image":        set(got, at(got, zapImage), "docker.io/library/debian:latest"),
		"options changed":      set(got, len(got)-1, "-config spider.postform=true"),
		"no AppArmor module":   set(got, 1, "/tmp/x.conf"),
	} {
		if validatePodman(bad) == nil {
			t.Errorf("%s: the validator accepts %q", name, bad)
		}
	}
	for _, a := range [][]string{zapImageExistsArgv(), zapPullArgv(), zapNetExistsArgv(), zapNetCreateArgv(), zapNetInspectArgv(), zapRmArgv()} {
		if err := validatePodman(a); err != nil {
			t.Errorf("%q: %v", a, err)
		}
	}
	for _, bad := range [][]string{{"rm", "--force", "vedette-core"}, {"network", "rm", "vedette-int"}, {"pull", "-q", "ghcr.io/zaproxy/zaproxy:stable"}} {
		if validatePodman(bad) == nil {
			t.Errorf("the validator accepts %q", bad)
		}
	}
}

func TestZapRulesetForOneAddressAndPort(t *testing.T) {
	t.Parallel()
	got, err := zapRuleset(zapIP(t), 8443)
	if err != nil {
		t.Fatal(err)
	}
	want := `table inet vedette_zap
delete table inet vedette_zap
table inet vedette_zap {
	chain fwd {
		type filter hook forward priority -10; policy accept;
		iifname "vedette-zap0" ip daddr 93.184.216.34 tcp dport 8443 accept
		iifname "vedette-zap0" drop
	}
	chain in {
		type filter hook input priority -10; policy accept;
		iifname "vedette-zap0" ip daddr 93.184.216.34 tcp dport 8443 accept
		iifname "vedette-zap0" drop
	}
}
`
	if got != want {
		t.Fatalf("ruleset\n%s\nwant\n%s", got, want)
	}
	for _, bad := range []struct {
		ip   string
		port int
	}{{"10.1.2.3", 80}, {"127.0.0.1", 80}, {zapTestIP, 0}, {zapTestIP, 65536}, {"2606:2800:220:1::1", 443}} {
		if _, err := zapRuleset(netip.MustParseAddr(bad.ip), bad.port); err == nil {
			t.Errorf("a rule for %s:%d", bad.ip, bad.port)
		}
	}
	for _, a := range [][]string{nftLoadArgv, nftListArgv, nftDeleteArgv} {
		if err := validateNft(a); err != nil {
			t.Errorf("%q: %v", a, err)
		}
	}
	for _, bad := range [][]string{{"flush", "ruleset"}, {"-f", "/etc/nftables.conf"}, {"delete", "table", "inet", "vedette_hp"}, {"list", "ruleset"}} {
		if validateNft(bad) == nil {
			t.Errorf("nft accepts %q", bad)
		}
	}
}

// zapNftListing is nft -j list table inet vedette_zap as nft 1.0.9 prints the table of zapRuleset (one line, abridged metainfo).
func zapNftListing(ip string, port int, extra string) string {
	rule := func(chain string, h int, last string) string {
		return fmt.Sprintf(`{"rule":{"family":"inet","table":"vedette_zap","chain":%q,"handle":%d,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"vedette-zap0"}},%s]}}`, chain, h, last)
	}
	accept := fmt.Sprintf(`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":%q}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":%d}},{"accept":null}`, ip, port)
	return `{"nftables":[{"metainfo":{"version":"1.0.9","release_name":"Old Doc Yak #3","json_schema_version":1}},` +
		`{"table":{"family":"inet","name":"vedette_zap","handle":7}},` +
		`{"chain":{"family":"inet","table":"vedette_zap","name":"fwd","handle":1,"type":"filter","hook":"forward","prio":-10,"policy":"accept"}},` +
		rule("fwd", 3, accept) + "," + rule("fwd", 4, `{"drop":null}`) + "," +
		`{"chain":{"family":"inet","table":"vedette_zap","name":"in","handle":2,"type":"filter","hook":"input","prio":-10,"policy":"accept"}},` +
		rule("in", 5, accept) + "," + rule("in", 6, `{"drop":null}`) + extra + `]}`
}

func TestZapRulesetLoadedReadsNftsListing(t *testing.T) {
	t.Parallel()
	ip := zapIP(t)
	if !zapRulesetLoaded([]byte(zapNftListing(zapTestIP, 443, "")), ip, 443) {
		t.Fatal("the listing of the loaded table is not recognised")
	}
	for name, out := range map[string]string{
		"another port":    zapNftListing(zapTestIP, 80, ""),
		"another address": zapNftListing("1.1.1.1", 443, ""),
		"a third rule":    zapNftListing(zapTestIP, 443, `,{"rule":{"family":"inet","table":"vedette_zap","chain":"fwd","handle":9,"expr":[{"accept":null}]}}`),
		"no input chain":  strings.Replace(zapNftListing(zapTestIP, 443, ""), `"hook":"input"`, `"hook":"output"`, 1),
		"not JSON":        "table inet vedette_zap {",
		"empty":           `{"nftables":[]}`,
	} {
		if zapRulesetLoaded([]byte(out), ip, 443) {
			t.Errorf("%s: accepted", name)
		}
	}
}

// zapWorld is a fake podman and nft for one Ops: every argv first passes the host runner's own validator.
type zapWorld struct {
	t     *testing.T
	o     *Ops
	state string

	mu         sync.Mutex
	calls      []string
	image      bool   // the image is on the box
	pullCode   int    // exit code of podman pull
	netThere   bool   // the network exists
	netInspect string // what podman network inspect prints
	nftOK      bool   // nft -j list prints the table of the last load
	loaded     string // the ruleset of the last nft -f -
	runCode    int
	report     []byte // what the run writes as out.json (nil: nothing)
	linkReport bool   // the run writes out.json as a symlink
	runGate    chan struct{}
	runStarted chan struct{}
}

const zapOurNet = `[{"name":"vedette-zap","id":"ab","driver":"bridge","network_interface":"vedette-zap0","subnets":[{"subnet":"10.89.3.0/24","gateway":"10.89.3.1"}],"ipv6_enabled":false,"internal":false,"dns_enabled":false}]`

func newZapWorld(t *testing.T, d Deps) *zapWorld {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	d.Root, d.ChainTop, d.ZapUID = base, base, os.Getuid()
	if d.ZapEgress == nil {
		d.ZapEgress = func(context.Context) (netip.Addr, error) { return netip.MustParseAddr(zapTestIP), nil }
	}
	if d.ZapTXT == nil {
		d.ZapTXT = func(context.Context, string) ([]string, error) {
			return []string{"v=spf1 -all", "vedette-verify=" + zapTestTok}, nil
		}
	}
	o, err := NewWithDeps(Config{StateDir: state, CoreUnit: "vedette-core.service", OwnerUID: os.Getuid()}, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	w := &zapWorld{t: t, o: o, state: state, image: true, netThere: true, netInspect: zapOurNet, nftOK: true, report: []byte(`{"site":[]}`)}
	o.zapExec = w.exec
	return w
}

func (w *zapWorld) exec(ctx context.Context, name string, stdin io.Reader, args ...string) (vexec.Result, int, error) {
	if _, ok := ctx.Deadline(); !ok {
		w.t.Errorf("%s %q runs without a deadline", name, args)
	}
	if err := ValidateHostArgv(w.state, "vedette-core.service", name, args); err != nil {
		w.t.Errorf("the host runner refuses %s %q: %v", name, args, err)
		return vexec.Result{}, -1, err
	}
	line := name + " " + strings.Join(args, " ")
	if name == binPodman && len(args) > 2 && args[2] == "run" {
		line = "podman run"
	}
	w.mu.Lock()
	w.calls = append(w.calls, line)
	w.mu.Unlock()
	switch {
	case name == binNft && slices.Equal(args, nftLoadArgv):
		b, _ := io.ReadAll(stdin)
		w.mu.Lock()
		w.loaded = string(b)
		w.mu.Unlock()
		return vexec.Result{}, 0, nil
	case name == binNft && slices.Equal(args, nftListArgv):
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.loaded == "" {
			return vexec.Result{}, 1, nil
		}
		if !w.nftOK {
			return vexec.Result{Stdout: []byte(zapNftListing("1.1.1.1", 1, ""))}, 0, nil
		}
		m := regexp.MustCompile(`ip daddr (\S+) tcp dport (\d+) accept`).FindStringSubmatch(w.loaded)
		var port int
		_, _ = fmt.Sscan(m[2], &port)
		return vexec.Result{Stdout: []byte(zapNftListing(m[1], port, ""))}, 0, nil
	case name == binNft && slices.Equal(args, nftDeleteArgv):
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.loaded == "" {
			return vexec.Result{}, 1, nil
		}
		w.loaded = ""
		return vexec.Result{}, 0, nil
	case slices.Equal(args, zapImageExistsArgv()):
		if w.image {
			return vexec.Result{}, 0, nil
		}
		return vexec.Result{}, 1, nil
	case slices.Equal(args, zapPullArgv()):
		w.mu.Lock()
		code := w.pullCode
		if code == 0 {
			w.image = true
		}
		w.mu.Unlock()
		return vexec.Result{}, code, nil
	case slices.Equal(args, zapNetExistsArgv()):
		if w.netThere {
			return vexec.Result{}, 0, nil
		}
		return vexec.Result{}, 1, nil
	case slices.Equal(args, zapNetCreateArgv()):
		w.netThere = true
		return vexec.Result{}, 0, nil
	case slices.Equal(args, zapNetInspectArgv()):
		return vexec.Result{Stdout: []byte(w.netInspect)}, 0, nil
	case slices.Equal(args, zapRmArgv()):
		return vexec.Result{}, 0, nil
	case line == "podman run":
		if w.runStarted != nil {
			w.runStarted <- struct{}{}
		}
		if w.runGate != nil {
			<-w.runGate
		}
		wrk, _ := strings.CutSuffix(args[slices.Index(args, "--volume")+1], ":/zap/wrk:rw")
		out := filepath.Join(wrk, zapReportName)
		switch {
		case w.linkReport:
			if err := os.Symlink("/etc/passwd", out); err != nil {
				w.t.Error(err)
			}
		case w.report != nil:
			if err := os.WriteFile(out, w.report, 0o600); err != nil {
				w.t.Error(err)
			}
		}
		return vexec.Result{}, w.runCode, nil
	}
	w.t.Errorf("unexpected call %s", line)
	return vexec.Result{}, -1, errors.New("unexpected")
}

func (w *zapWorld) Calls() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.calls)
}

func zapDomainPage(t *testing.T) zapPage {
	t.Helper()
	p, err := zapArgs(api.ZapBaselineArgs{URL: "https://www.example.com/", Host: "www.example.com", IP: zapTestIP, Port: 443, Kind: api.ZapKindDomain, Domain: "example.com", TXTToken: zapTestTok})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func zapIPPage(t *testing.T) zapPage {
	t.Helper()
	p, err := zapArgs(api.ZapBaselineArgs{URL: "http://" + zapTestIP + ":8080/", Host: zapTestIP, IP: zapTestIP, Port: 8080, Kind: api.ZapKindIP})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func nolog(string) {}

// the cleanup: container removed, rule deleted, work folder and marker gone.
func (w *zapWorld) cleanedUp(t *testing.T) {
	t.Helper()
	calls := w.Calls()
	rm := "podman " + strings.Join(zapRmArgv(), " ")
	last := -1
	for i, c := range calls {
		if c == rm {
			last = i
		}
	}
	del := slices.Index(calls[max(last, 0):], "nft delete table inet vedette_zap")
	if !slices.Contains(calls, rm) || last < slices.Index(calls, "podman run") || last < slices.Index(calls, "nft -f -") || del < 0 {
		t.Errorf("the run did not end with the removal of the container and the rule: %q", calls)
	}
	if w.loaded != "" {
		t.Error("the egress rule is still loaded")
	}
	for _, f := range []string{"wrk", "active"} {
		if _, err := os.Lstat(filepath.Join(w.o.zapDir(), f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("zap/%s is still there: %v", f, err)
		}
	}
}

func TestZapBaseline_ARunIsFencedAndCleanedUp(t *testing.T) {
	t.Parallel()
	for _, code := range []int{0, 1, 2} { // zap-baseline.py: no rule, a FAIL rule, a WARN rule; all three with a report are success
		w := newZapWorld(t, Deps{})
		w.netThere, w.runCode = false, code
		res, err := w.o.zapBaseline(t.Context(), nolog, zapDomainPage(t))
		if err != nil {
			t.Fatalf("exit %d: %v", code, err)
		}
		r, ok := res.(api.ZapBaselineResult)
		if !ok || r.ExitCode != code || r.Size != int64(len(w.report)) || !hexIDRE.MatchString(r.ReportID) {
			t.Fatalf("result %+v", res)
		}
		want := []string{
			"podman image exists " + zapImage,
			"podman rm --force --ignore --time 0 vedette-zap",
			"podman network exists vedette-zap",
			"podman network create --driver bridge --interface-name vedette-zap0 --disable-dns vedette-zap",
			"podman network inspect vedette-zap",
			"nft -f -",
			"nft -j list table inet vedette_zap",
			"podman run",
			"podman rm --force --ignore --time 0 vedette-zap",
			"nft delete table inet vedette_zap",
		}
		if got := w.Calls(); !slices.Equal(got, want) {
			t.Fatalf("exit %d: calls\n%q\nwant\n%q", code, got, want)
		}
		w.cleanedUp(t)
		f, err := w.o.zapReport(r.ReportID)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(f.Body)
		_ = f.Body.Close()
		if string(b) != string(w.report) || f.Type != "application/json" {
			t.Fatalf("the served report is %q", b)
		}
	}
}

func TestZapBaseline_AFailureStillCleansUp(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		set  func(*zapWorld)
		code string
	}{
		"exit 3":                      {func(w *zapWorld) { w.runCode = 3 }, api.CodeZapFailed},
		"out of memory":               {func(w *zapWorld) { w.runCode = 137 }, api.CodeZapFailed},
		"no report":                   {func(w *zapWorld) { w.report = nil }, api.CodeZapFailed},
		"the report is a symlink":     {func(w *zapWorld) { w.linkReport = true }, api.CodeZapFailed},
		"the report is too large":     {func(w *zapWorld) { w.report = make([]byte, api.MaxZapReport+1) }, api.CodeZapReportTooLarge},
		"the rule does not read back": {func(w *zapWorld) { w.nftOK = false }, api.CodeZapFenceFailed},
		"someone else's network": {func(w *zapWorld) {
			w.netInspect = strings.Replace(zapOurNet, `"dns_enabled":false`, `"dns_enabled":true`, 1)
		}, api.CodeZapFenceFailed},
	} {
		w := newZapWorld(t, Deps{})
		tc.set(w)
		_, err := w.o.zapBaseline(t.Context(), nolog, zapIPPage(t))
		var f *server.Failure
		if !errors.As(err, &f) || f.Code != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
			continue
		}
		if slices.Contains(w.Calls(), "podman run") && (tc.code == api.CodeZapFenceFailed) {
			t.Errorf("%s: ZAP ran without its fence", name)
		}
		w.cleanedUp(t)
		if ents, _ := os.ReadDir(w.o.zapDir()); len(ents) != 0 {
			t.Errorf("%s: zap/ keeps %v", name, ents)
		}
	}
}

func TestZapBaseline_TheHostChecksOwnershipBeforeAnythingIsSent(t *testing.T) {
	t.Parallel()
	other := func(context.Context) (netip.Addr, error) { return netip.MustParseAddr("1.1.1.1"), nil }
	down := func(context.Context) (netip.Addr, error) { return netip.Addr{}, errors.New("no answer") }
	noTXT := func(context.Context, string) ([]string, error) {
		return []string{"vedette-verify=ffffffffffffffff"}, nil
	}
	dnsDown := func(context.Context, string) ([]string, error) { return nil, errors.New("timeout") }
	for name, tc := range map[string]struct {
		d    Deps
		page func(*testing.T) zapPage
		code string
	}{
		"not the box's egress": {Deps{ZapEgress: other}, zapIPPage, api.CodeTargetNotOwned},
		"egress unknown":       {Deps{ZapEgress: down}, zapIPPage, api.CodeOwnershipUnchecked},
		"the token is gone":    {Deps{ZapTXT: noTXT}, zapDomainPage, api.CodeTargetNotOwned},
		"DNS did not answer":   {Deps{ZapTXT: dnsDown}, zapDomainPage, api.CodeOwnershipUnchecked},
	} {
		w := newZapWorld(t, tc.d)
		_, err := w.o.zapBaseline(t.Context(), nolog, tc.page(t))
		var ref *server.Refusal
		var f *server.Failure
		got := ""
		switch {
		case errors.As(err, &ref):
			got = ref.Code
		case errors.As(err, &f):
			got = f.Code
		}
		if got != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
		if calls := w.Calls(); !slices.Equal(calls, []string{"podman image exists " + zapImage}) {
			t.Errorf("%s: calls after a failed re-check: %q", name, calls)
		}
	}
}

func TestZapBaseline_OneAtATime(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	w.runGate, w.runStarted = make(chan struct{}), make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { _, err := w.o.zapBaseline(context.Background(), nolog, zapIPPage(t)); done <- err }()
	<-w.runStarted
	_, err := w.o.zapBaseline(t.Context(), nolog, zapDomainPage(t))
	var ref *server.Refusal
	if !errors.As(err, &ref) || ref.Code != api.CodeBusy || ref.Status != 409 {
		t.Fatalf("a second run while one runs: %v", err)
	}
	close(w.runGate)
	if err := <-done; err != nil {
		t.Fatalf("the first run: %v", err)
	}
	if _, err := w.o.zapBaseline(t.Context(), nolog, zapDomainPage(t)); err != nil {
		t.Fatalf("a run after the first ended: %v", err)
	}
}

func TestZapBaseline_AMissingImageIsPulledOnceAndSaidSo(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) { // synctest.Wait lets the download in the background end before the next call
		w := newZapWorld(t, Deps{})
		w.image, w.pullCode = false, 1
		refusal := func() string {
			t.Helper()
			_, err := w.o.zapBaseline(context.Background(), nolog, zapIPPage(t))
			var ref *server.Refusal
			if !errors.As(err, &ref) || ref.Status != 409 {
				t.Fatalf("%v, want a 409", err)
			}
			return ref.Code
		}
		if c := refusal(); c != api.CodeZapPulling {
			t.Fatalf("first call: %s", c)
		}
		synctest.Wait() // the download failed
		w.mu.Lock()
		w.pullCode = 0
		w.mu.Unlock()
		if c := refusal(); c != api.CodeZapPullFailed {
			t.Fatalf("after a failed download: %s", c)
		}
		synctest.Wait() // the second try worked
		if _, err := w.o.zapBaseline(context.Background(), nolog, zapIPPage(t)); err != nil {
			t.Fatalf("after the download: %v", err)
		}
		pulls := 0
		for _, c := range w.Calls() {
			if c == "podman "+strings.Join(zapPullArgv(), " ") {
				pulls++
			}
		}
		if pulls != 2 || !slices.Contains(w.Calls(), "podman run") {
			t.Fatalf("calls %q", w.Calls())
		}
	})
}

func TestZapBaseline_ADiskTooSmallIsNotPulledInto(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		w := newZapWorld(t, Deps{FreeBytes: func(string) (uint64, error) { return 1 << 30, nil }})
		w.image = false
		_, _ = w.o.zapBaseline(context.Background(), nolog, zapIPPage(t))
		synctest.Wait()
		w.o.zapMu.Lock()
		reason := w.o.zapPullErr
		w.o.zapMu.Unlock()
		if !strings.Contains(reason, "MiB free") || slices.Contains(w.Calls(), "podman "+strings.Join(zapPullArgv(), " ")) {
			t.Fatalf("reason %q, calls %q", reason, w.Calls())
		}
	})
}

func TestZapAtStart_ARunTheLastHostLeftIsCleanedUp(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	if err := privDir(w.o.zapDir(), os.Getuid()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"active", "0123456789abcdef0123456789abcdef.json"} {
		if err := os.WriteFile(filepath.Join(w.o.zapDir(), f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w.loaded = "table inet vedette_zap { }"
	w.o.zapAtStart(t.Context())
	w.cleanedUp(t)
	if _, err := w.o.zapReport("0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("a report of the last host is still served")
	}
	// No marker: a start touches neither podman nor nft.
	w2 := newZapWorld(t, Deps{})
	w2.o.zapAtStart(t.Context())
	if c := w2.Calls(); len(c) != 0 {
		t.Fatalf("a start without a marker called %q", c)
	}
}

func TestZapReport_UnknownIDs(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	for _, id := range []string{"0123456789abcdef0123456789abcdef", "../../etc/passwd", ""} {
		_, err := w.o.zapReport(id)
		var re *server.ReadError
		if !errors.As(err, &re) || re.Status != 404 || re.Code != api.CodeZapReportUnknown {
			t.Errorf("%q: %v", id, err)
		}
	}
}

// The image is named in three places: pins.env (with its tag, for people), the host's constant and install.sh --uninstall (D-521).
func TestZapPinsAgree(t *testing.T) {
	t.Parallel()
	pins, err := os.ReadFile("../../deploy/containers/pins.env")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ZAP_IMAGE=ghcr\.io/zaproxy/zaproxy:(2\.[0-9]+\.[0-9]+)@(sha256:[0-9a-f]{64})$`).FindSubmatch(pins)
	if m == nil {
		t.Fatal("pins.env has no ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:<2.x.y>@sha256:<64 hex>")
	}
	if want := "ghcr.io/zaproxy/zaproxy@" + string(m[2]); zapImage != want {
		t.Errorf("zapImage = %s, pins.env says %s", zapImage, want)
	}
	sh, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sh), "\nZAP_IMAGE="+zapImage+"\n") {
		t.Errorf("install.sh does not set ZAP_IMAGE=%s", zapImage)
	}
}
