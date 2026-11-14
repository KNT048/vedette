package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/egressip"
	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// zap.baseline (host-api §6.15, D-521, exposure INV-24 / D-562): ZAP's passive baseline scan of one page of a verified exposure
// target, in a one-shot container the host starts with a fixed argv. The fences, in the order a run takes them:
//
//  1. The arguments (Validate): the URL is exactly http(s)://Host[:Port]/ (no user, query or fragment), IP is a public IPv4 address
//     (egressip.IsPublicIPv4), Port 1-65535, Host is the IP itself (kind ip) or the verified domain or a name under it (kind domain).
//     Everything of one page up to the end of the run fits in zapPageLimit, inside exposure's 8 minutes.
//  2. One run at a time (busy otherwise), and the image is on the box: when it is not, the host starts its download by digest in the
//     background and refuses (zap_image_pulling): the ~1.2 GB download happens only for a box whose owner pressed Scan now (D-521).
//  3. The host's own re-check of ownership, right before the run: kind ip, the box leaves the Internet through IP now (core/egressip,
//     two of three services agree); kind domain, the domain still has its TXT record vedette-verify=<token> AND the page's name
//     resolves (A records, system resolver) to the IP ZAP is pinned to. Core asked the same moments before (exposure INV-13); the
//     host does not take core's word for the IP it opens the fence to.
//  4. The fence: the podman network vedette-zap (made by the host with zapLabel; bridge vedette-zap0, no DNS, no options, one IPv4
//     subnet, not internal) and the nft table inet vedette_zap, loaded in one transaction (its text checked against zapRuleset
//     before nft sees it) and read back, which drops everything that enters the host from that bridge (forward and input) except TCP to
//     IP:Port. The container gets no resolver (--dns none) and, for a domain, the one name pinned to IP (--add-host), so a redirect to
//     another host or port, a DNS lookup or a call home to zaproxy.org fails at the network layer.
//  5. The container: --rm, --read-only (tmpfs for ZAP's home, podman's own for /tmp and /run), --cap-drop ALL, no-new-privileges,
//     Vedette's AppArmor profile (D-458), 1 GiB without swap, 256 pids, the image's zap user, a JVM heap of 512 MiB, -silent (no
//     update check, no call home), spider 1 minute, passive rules 5 minutes, no form posted (the traditional runner, --autooff,
//     D-525), never -a (active scan), -j (AJAX spider) or -u.
//  6. After the run, on every path: the container is removed (only one that carries zapLabel) and must then be proven gone, and only
//     then is the nft table deleted (a ZAP that may still run keeps its fence); then the work directory and the marker zap/active go.
//     What cannot be proven gone keeps the table and the marker, is audited (zap_cleanup_incomplete), and is tried again by the next
//     run, which refuses until it is clean (zap_cleaning_up), and by the next host start.
//
// The report is read from the work directory (a bind mount, 0700, owned by the image's zap user; a symlink, a FIFO or a file over
// MaxZapReport is refused), kept as zap/<id>.json until the next run or host start, and served by GET /v1/zap/{id}/content. It is
// untrusted: exposure's ParseZAPReport reads it (D-562 (4)).

const (
	binNft = "nft"

	zapNetwork   = "vedette-zap"
	zapBridge    = "vedette-zap0" // the bridge podman makes for the network (--interface-name): the nft rules match it
	zapContainer = "vedette-zap"
	zapTable     = "vedette_zap"
	// zapLabel marks the network and the container the host makes: only a thing that carries it is the host's to check, use or
	// remove (here and in install.sh --uninstall); one of the same name without it is someone else's.
	zapLabel = "io.vedette.owner=vedette-host"

	// zapImage is ZAP_IMAGE of deploy/containers/pins.env without its tag (a test keeps them equal; install.sh --uninstall names it
	// too): ZAP 2.17.0 ("stable"), the digest of the multi-architecture index. Upstream does not sign it with our key: integrity is the
	// digest (D-521, an exception to D-57 (3)).
	zapImage = "ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"

	// zapUID is the zap user of the image (useradd -u 1000 in its Dockerfile): the container runs as it, and the work directory is its.
	zapUID = 1000

	zapWorkDir    = "/zap/wrk" //nolint:gosec // a path inside the ZAP container, not a credential
	zapReportName = "out.json"
	// zapTmpfs is ZAP's home: podman copies the image's /home/zap into it (tmpcopyup, its default), and it counts against --memory.
	zapTmpfs = "/home/zap:rw,size=256m,mode=0700,uid=1000,gid=1000"
	// zapCwd is the container's working directory: zap-baseline.py's traditional runner (--autooff) writes ZAP's output to zap.out
	// in the current directory (zap_common.start_zap), and the image's WORKDIR /zap is on the read-only root. ZAP's home is writable
	// and bounded (zapTmpfs), so it goes there (D-525).
	zapCwd = "/home/zap"
	// zapOptions are ZAP's own options (-z): -silent (no update check, no unsolicited request), a heap of half the container's memory
	// (zap.sh reads -Xmx from its arguments; without it it takes a quarter of the HOST's memory on cgroup v2, 1.75 GiB on the N100),
	// no form handled or posted by the spider and one spider thread, gentle on a fragile site (D-562 (1), exposure INV-24). The spider
	// options hold only because the run is --autooff (D-525): the traditional runner starts the spider through ZAP's API with these
	// options, while the Automation Framework runner (2.17.0's default) gives its spider job the job's own defaults (processForm and
	// postForm true, two threads per core), which replace them. The cap of 10 alerts per rule is zap-baseline.py's own (zap_tune).
	zapOptions = "-silent -Xmx512m -config spider.processform=false -config spider.postform=false -config spider.thread=1"

	// zapPageLimit bounds everything of one page up to the end of podman run, from the moment the run starts: the checks, the fence,
	// about a minute of JVM start, the spider's minute and at most five of passive rules. It stays inside exposure's 8 minutes
	// (WebScanTimeout) with room for the cleanup and core's 2-second polling, so exposure never gives up on a run the host still runs.
	zapPageLimit = 7 * time.Minute
	zapTimeout   = 9 * time.Minute // the command: the page's 7 minutes and the cleanup after it
	zapStepWait  = time.Minute     // one podman or nft call other than the run and the pull
	zapPullWait  = 45 * time.Minute
	// zapMinFree is the free space the pull needs under /var/lib/containers: the image unpacks to about 2 GB.
	zapMinFree = 4 << 30
	// zapNoRun is podman's own exit code when it could not start the container (125) and the codes of a shell that could not run the
	// entrypoint (126, 127): never a report.
	zapNoRun = 125
)

var (
	zapHostRE  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`) // a domain name, as exposure's domainRE
	zapTokenRE = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
	errZapArgv = errors.New("not one of the fixed zap command lines")
)

// zapPage is a validated zap.baseline request.
type zapPage struct {
	url    string
	host   string
	ip     netip.Addr
	port   int
	kind   string
	domain string
	token  string
}

// zapURL checks that raw is exactly http(s)://host[:port]/ as exposure writes it (the port only when it is not the scheme's own) and
// returns its host and port.
func zapURL(raw string) (host string, port int, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Opaque != "" {
		return "", 0, false
	}
	host = u.Hostname()
	def := map[string]int{"http": 80, "https": 443}[u.Scheme]
	port = def
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || n == def {
			return "", 0, false
		}
		port = n
	}
	want := u.Scheme + "://" + host + "/"
	if port != def {
		want = u.Scheme + "://" + host + ":" + strconv.Itoa(port) + "/"
	}
	if host == "" || raw != want || len(raw) > 300 {
		return "", 0, false
	}
	return host, port, true
}

// zapArgs validates the args at the edge (rules/security.md): every refusal names the field.
func zapArgs(a api.ZapBaselineArgs) (zapPage, error) {
	ip, err := netip.ParseAddr(a.IP)
	if err != nil || !ip.Is4() || !egressip.IsPublicIPv4(ip) {
		return zapPage{}, server.Invalid(fieldIP, "must be a public IPv4 address")
	}
	if a.Port < 1 || a.Port > 65535 {
		return zapPage{}, server.Invalid("port", "must be 1-65535")
	}
	host, port, ok := zapURL(a.URL)
	if !ok || host != a.Host || port != a.Port {
		return zapPage{}, server.Invalid("url", "must be http(s)://<host>[:<port>]/ with the host and port of the request")
	}
	p := zapPage{url: a.URL, host: a.Host, ip: ip, port: a.Port, kind: a.Kind}
	switch a.Kind {
	case api.ZapKindIP:
		if a.Host != ip.String() {
			return zapPage{}, server.Invalid("host", "must be the IP itself for an IP target")
		}
		if a.Domain != "" || a.TXTToken != "" {
			return zapPage{}, server.Invalid("domain", "is for a domain target only")
		}
	case api.ZapKindDomain:
		if len(a.Domain) > 253 || !zapHostRE.MatchString(a.Domain) {
			return zapPage{}, server.Invalid("domain", "must be a domain name")
		}
		if len(a.Host) > 253 || !zapHostRE.MatchString(a.Host) || (a.Host != a.Domain && !strings.HasSuffix(a.Host, "."+a.Domain)) {
			return zapPage{}, server.Invalid("host", "must be the domain or a name under it")
		}
		if !zapTokenRE.MatchString(a.TXTToken) {
			return zapPage{}, server.Invalid("txt_token", "must be the hex token of the domain")
		}
		p.domain, p.token = a.Domain, a.TXTToken
	default:
		return zapPage{}, server.Invalid("kind", "must be ip or domain")
	}
	return p, nil
}

// ---- argv (validatePodman and validateNft accept exactly these) ----

// The podman shapes of zap.baseline:
//
//	image exists <zapImage>
//	pull -q <zapImage>
//	network exists vedette-zap
//	network create --driver bridge --interface-name vedette-zap0 --disable-dns --label io.vedette.owner=vedette-host vedette-zap
//	network inspect vedette-zap
//	container exists vedette-zap
//	container inspect vedette-zap
//	rm --force --ignore --time 0 vedette-zap         (only after container inspect showed zapLabel)
//	--module <AppArmorConfModule> run … (zapRunArgv; validateZapRun: the work folder is exactly <state>/zap/wrk)

func zapImageExistsArgv() []string { return []string{"image", "exists", zapImage} }
func zapPullArgv() []string        { return []string{"pull", "-q", zapImage} }
func zapNetExistsArgv() []string   { return []string{"network", "exists", zapNetwork} }
func zapNetCreateArgv() []string {
	return []string{"network", "create", "--driver", "bridge", "--interface-name", zapBridge, "--disable-dns", "--label", zapLabel, zapNetwork}
}
func zapNetInspectArgv() []string { return []string{"network", "inspect", zapNetwork} }
func zapCtrExistsArgv() []string  { return []string{"container", "exists", zapContainer} }
func zapCtrInspectArgv() []string { return []string{"container", "inspect", zapContainer} }
func zapRmArgv() []string         { return []string{"rm", "--force", "--ignore", "--time", "0", zapContainer} }

// zapMountOpts are the options of the work folder's bind mount: the container writes its report there and nothing in it can be a
// device, a setuid binary or run.
const zapMountOpts = ":rw,nosuid,nodev,noexec"

// zapRunArgv is the one podman run. addHost is "<name>:<ip>" for a domain's page and "" for an IP's; wrk is the work directory.
// --autooff pins zap-baseline.py's traditional runner, where the -z spider options apply (D-525).
func zapRunArgv(pageURL, addHost, wrk string) []string {
	a := []string{"--module", AppArmorConfModule, "run", "--rm", "--pull=never", "--name", zapContainer, "--label", zapLabel, "--network", zapNetwork, "--dns", "none"}
	if addHost != "" {
		a = append(a, "--add-host", addHost)
	}
	return append(a, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", zapTmpfs,
		"--volume", wrk+":"+zapWorkDir+zapMountOpts, "--user", "1000:1000", "--memory=1g", "--memory-swap=1g", "--pids-limit=256", "--no-healthcheck",
		"--workdir", zapCwd,
		zapImage, "zap-baseline.py", "--autooff", "-t", pageURL, "-m", "1", "-T", "5", "-J", zapReportName, "-z", zapOptions)
}

func (p zapPage) runArgv(wrk string) []string {
	addHost := ""
	if p.kind == api.ZapKindDomain {
		addHost = p.host + ":" + p.ip.String()
	}
	return zapRunArgv(p.url, addHost, wrk)
}

// isZapRunArgv: the three values that vary each pass their own check (the work folder is exactly <stateDir>/zap/wrk), and the argv
// is then exactly what zapRunArgv builds of them.
func isZapRunArgv(stateDir string, a []string) bool {
	if len(a) < 4 || a[0] != "--module" || a[2] != "run" {
		return false
	}
	addHost := ""
	if i := slices.Index(a, "--add-host"); i > 0 && i+1 < len(a) {
		addHost = a[i+1]
		name, ip, ok := strings.Cut(addHost, ":")
		addr, err := netip.ParseAddr(ip)
		if !ok || len(name) > 253 || !zapHostRE.MatchString(name) || err != nil || !egressip.IsPublicIPv4(addr) || addr.String() != ip {
			return false
		}
	}
	i := slices.Index(a, "--volume")
	j := slices.Index(a, "-t")
	if i < 0 || i+1 >= len(a) || j < 0 || j+1 >= len(a) {
		return false
	}
	wrk, ok := strings.CutSuffix(a[i+1], ":"+zapWorkDir+zapMountOpts)
	if !ok || !validBuildDir(wrk) || wrk != filepath.Join(stateDir, "zap", "wrk") {
		return false
	}
	host, _, ok := zapURL(a[j+1])
	if !ok || (addHost == "" && !isIPv4Text(host)) || (addHost != "" && !strings.HasPrefix(addHost, host+":")) {
		return false
	}
	return slices.Equal(a, zapRunArgv(a[j+1], addHost, wrk))
}

func isIPv4Text(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4() && egressip.IsPublicIPv4(a) && a.String() == s
}

// isZapPodmanArgv says whether args is one of the fixed podman shapes of zap.baseline other than the run.
func isZapPodmanArgv(args []string) bool {
	for _, want := range [][]string{zapImageExistsArgv(), zapPullArgv(), zapNetExistsArgv(), zapNetCreateArgv(), zapNetInspectArgv(),
		zapCtrExistsArgv(), zapCtrInspectArgv(), zapRmArgv()} {
		if slices.Equal(args, want) {
			return true
		}
	}
	return false
}

// validatePodmanIn is the validator of the host runner's podman: the fixed shapes of validatePodman, and the run of zap.baseline
// with its work folder under this state directory.
func validatePodmanIn(stateDir string) func([]string) error {
	return func(args []string) error {
		if isZapRunArgv(stateDir, args) {
			return nil
		}
		return validatePodman(args)
	}
}

// The nft shapes: the ruleset from standard input (zapRuleset, built here from a netip.Addr and an int), its read-back, its removal.
var (
	nftLoadArgv   = []string{"-f", "-"}
	nftListArgv   = []string{"-j", "list", "table", "inet", zapTable}
	nftDeleteArgv = []string{"delete", "table", "inet", zapTable}
)

// validateNft sees the argv only: the ruleset nft -f - reads on standard input is checked by zapStep (zapRulesetOK), the one caller
// that gives nft a standard input (TestZapOnlyZapStepFeedsNft holds that).
func validateNft(args []string) error {
	if slices.Equal(args, nftLoadArgv) || slices.Equal(args, nftListArgv) || slices.Equal(args, nftDeleteArgv) {
		return nil
	}
	return errZapArgv
}

// The two base chains of the table. Not "fwd" or "in": both are words of nft's grammar, and nft 1.1 refuses them as chain names
// with a syntax error, so no fence could ever load (n38, the N100: "nft could not load the egress rule").
const (
	zapFwdChain = "zapfwd"
	zapInChain  = "zapin"
)

// zapRuleset is the nft transaction of one run: the table made empty if it was there (the "table; delete table" idiom keeps it one
// atomic load), then two base chains, forward and input, that drop everything entering the host from the bridge vedette-zap0 except
// TCP to ip:port. IPv6 from the bridge is dropped too (the family is inet). Replies to the container are not touched (they enter from
// another interface).
func zapRuleset(ip netip.Addr, port int) (string, error) {
	if !ip.Is4() || !egressip.IsPublicIPv4(ip) || port < 1 || port > 65535 {
		return "", errZapArgv
	}
	allow := fmt.Sprintf("\t\tiifname %q ip daddr %s tcp dport %d accept\n\t\tiifname %q drop\n", zapBridge, ip, port, zapBridge)
	return "table inet " + zapTable + "\ndelete table inet " + zapTable + "\ntable inet " + zapTable + " {\n" +
		"\tchain " + zapFwdChain + " {\n\t\ttype filter hook forward priority -10; policy accept;\n" + allow + "\t}\n" +
		"\tchain " + zapInChain + " {\n\t\ttype filter hook input priority -10; policy accept;\n" + allow + "\t}\n}\n", nil
}

var zapAllowRE = regexp.MustCompile(`(?m)^\t\tiifname "vedette-zap0" ip daddr ([0-9.]{7,15}) tcp dport ([0-9]{1,5}) accept$`)

// zapRulesetOK says whether text is exactly zapRuleset of some public IPv4 address and port: the only text nft -f - is given (the
// runner's validator sees the argv, not standard input, so zapStep checks it here).
func zapRulesetOK(text string) bool {
	m := zapAllowRE.FindStringSubmatch(text)
	if m == nil {
		return false
	}
	ip, err := netip.ParseAddr(m[1])
	port, perr := strconv.Atoi(m[2])
	if err != nil || perr != nil {
		return false
	}
	want, err := zapRuleset(ip, port)
	return err == nil && text == want
}

// zapRulesetLoaded checks nft's JSON listing of the table: chains zapfwd (hook forward) and zapin (hook input), each with exactly the two
// rules of zapRuleset: the accept of TCP to ip:port from the bridge, then the drop of the rest from the bridge.
func zapRulesetLoaded(out []byte, ip netip.Addr, port int) bool {
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Table string `json:"table"`
				Name  string `json:"name"`
				Hook  string `json:"hook"`
			} `json:"chain"`
			Rule *struct {
				Table string          `json:"table"`
				Chain string          `json:"chain"`
				Expr  json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if len(out) > 1<<20 || json.Unmarshal(out, &doc) != nil {
		return false
	}
	hooks := map[string]string{}
	rules := map[string][]string{}
	for _, it := range doc.Nftables {
		if c := it.Chain; c != nil && c.Table == zapTable {
			hooks[c.Name] = c.Hook
		}
		if r := it.Rule; r != nil && r.Table == zapTable {
			var b bytes.Buffer
			if json.Compact(&b, r.Expr) != nil {
				return false
			}
			rules[r.Chain] = append(rules[r.Chain], b.String())
		}
	}
	if len(hooks) != 2 || hooks[zapFwdChain] != "forward" || hooks[zapInChain] != "input" || len(rules) != 2 {
		return false
	}
	bridge := `"right":"` + zapBridge + `"`
	for _, c := range []string{zapFwdChain, zapInChain} {
		r := rules[c]
		if len(r) != 2 || !strings.Contains(r[0], bridge) || !strings.Contains(r[0], `"right":"`+ip.String()+`"`) ||
			!strings.Contains(r[0], `"right":`+strconv.Itoa(port)+`}`) || !strings.HasSuffix(r[0], `{"accept":null}]`) ||
			!strings.Contains(r[1], bridge) || !strings.HasSuffix(r[1], `{"drop":null}]`) || strings.Count(r[1], `"match"`) != 1 {
			return false
		}
	}
	return true
}

// ---- the command ----

func (o *Ops) cmdZapBaseline() server.Command {
	// Not a write command: a scan of up to 8 minutes must not hold the global lock that container.start, the decoys and updates
	// take. It touches only its own things (the network vedette-zap, the table inet vedette_zap, the container vedette-zap, zap/),
	// and keeps itself to one run at a time.
	return server.Define(server.Spec[api.ZapBaselineArgs]{
		Name: api.CmdZapBaseline, Write: false, Timeout: zapTimeout,
		Validate: func(a *api.ZapBaselineArgs) error { _, err := zapArgs(*a); return err },
		Run: func(ctx context.Context, rc *server.RunContext, a api.ZapBaselineArgs) (any, error) {
			p, err := zapArgs(a)
			if err != nil {
				return nil, err
			}
			return o.zapBaseline(ctx, rc.Log, p)
		},
	})
}

// zapExecFn runs one allowlisted binary (o.execIn; internal tests replace it).
type zapExecFn func(ctx context.Context, name string, stdin io.Reader, args ...string) (vexec.Result, int, error)

func (o *Ops) zx() zapExecFn {
	if o.zapExec != nil {
		return o.zapExec
	}
	return o.execIn
}

// zapStep runs one bounded call and reports its exit code (-1 with the error when it could not run). nft reads a ruleset from
// stdin only when it is exactly one zapRuleset.
func (o *Ops) zapStep(ctx context.Context, name string, stdin io.Reader, args ...string) (vexec.Result, int, error) {
	if stdin != nil {
		b, err := io.ReadAll(io.LimitReader(stdin, 4<<10))
		if err != nil || name != binNft || !zapRulesetOK(string(b)) {
			return vexec.Result{}, -1, errZapArgv
		}
		stdin = bytes.NewReader(b)
	}
	cctx, cancel := context.WithTimeout(ctx, zapStepWait)
	defer cancel()
	res, code, err := o.zx()(cctx, name, stdin, args...)
	if err != nil {
		return res, -1, err
	}
	return res, code, nil
}

func (o *Ops) zapDir() string { return o.stateFile("zap") }

func (o *Ops) zapBaseline(ctx context.Context, logf func(string), p zapPage) (any, error) {
	o.zapMu.Lock()
	if o.zapBusy {
		o.zapMu.Unlock()
		return nil, refuse409(api.CodeBusy, "A passive web scan is already running on this box.")
	}
	o.zapBusy = true
	o.zapMu.Unlock()
	defer func() {
		o.zapMu.Lock()
		o.zapBusy = false
		o.zapMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, zapPageLimit)
	defer cancel()

	if ref := o.zapImageReady(ctx); ref != nil {
		return nil, ref
	}
	if err := o.zapOwned(ctx, p); err != nil {
		return nil, err
	}
	if err := o.zapClearStale(ctx); err != nil {
		return nil, err
	}
	if err := privDir(o.zapDir(), o.cfg.OwnerUID); err != nil {
		return nil, fail(api.CodeZapFailed, "The host could not prepare its folder for the web scan.")
	}
	o.zapClearReports()
	// From here on the box holds things of this run: the marker says so to the next start if this process dies.
	if err := writeFileAtomic(filepath.Join(o.zapDir(), "active"), []byte(p.url+"\n"), 0o600); err != nil {
		return nil, fail(api.CodeZapFailed, "The host could not prepare its folder for the web scan.")
	}
	defer func() { _ = o.zapCleanup(context.WithoutCancel(ctx)) }()
	if err := o.zapFence(ctx, p); err != nil {
		return nil, err
	}
	// A work folder that cannot be made is the host's own disk, not the fence: zap_failed, so the page's line does not send the
	// operator to the network (review TUNE-3 L3).
	wrk := filepath.Join(o.zapDir(), "wrk")
	if err := os.Mkdir(wrk, 0o700); err != nil {
		return nil, fail(api.CodeZapFailed, "The host could not prepare the work folder of the web scan.")
	}
	if err := os.Chown(wrk, o.zapOwner(), o.zapOwner()); err != nil {
		return nil, fail(api.CodeZapFailed, "The host could not prepare the work folder of the web scan.")
	}
	logf("passive web scan of " + p.url + " pinned to " + p.ip.String() + ":" + strconv.Itoa(p.port) + " (ZAP baseline, spider 1 minute, passive rules)")
	_, code, err := o.zx()(ctx, binPodman, nil, p.runArgv(wrk)...)
	slow := ctx.Err() != nil
	switch {
	case slow:
		return nil, fail(api.CodeZapTimedOut, "ZAP did not finish within the host's time limit of 7 minutes for a page.")
	case err != nil:
		o.log.ErrorContext(ctx, "zap.baseline: podman run could not run", "error", err.Error())
		return nil, fail(api.CodeZapFailed, "The host could not start ZAP.")
	case code < 0 || code > 2:
		logf("ZAP ended with exit code " + strconv.Itoa(code))
		msg := "ZAP ended without a report (exit code " + strconv.Itoa(code) + ")."
		switch {
		case code == 3: // the traditional runner ends so when it cannot reach the page, finds no URL there, or cannot start (D-525)
			msg = "ZAP ended without a report (exit code 3): it could not reach the page from this box, found no page there, or could not start."
		case code == 137:
			msg = "ZAP was stopped, most likely because it reached the 1 GiB memory limit (exit code 137)."
		case code >= zapNoRun && code <= zapNoRun+2:
			msg = "Podman could not start the ZAP container (exit code " + strconv.Itoa(code) + ")."
		}
		return nil, fail(api.CodeZapFailed, msg)
	}
	id, size, ferr := o.zapKeepReport(wrk)
	if ferr != nil {
		return nil, ferr
	}
	logf("ZAP finished with exit code " + strconv.Itoa(code) + "; report " + strconv.FormatInt(size, 10) + " bytes")
	return api.ZapBaselineResult{ReportID: id, Size: size, ExitCode: code}, nil
}

// zapOwner is the uid the work directory is given to (Deps.ZapUID in tests, the image's zap user otherwise).
func (o *Ops) zapOwner() int {
	if o.d.ZapUID > 0 {
		return o.d.ZapUID
	}
	return zapUID
}

// zapImageReady refuses while the image is not on the box, and starts its download when none runs (D-521: pulled when first needed).
func (o *Ops) zapImageReady(ctx context.Context) error {
	_, code, err := o.zapStep(ctx, binPodman, nil, zapImageExistsArgv()...)
	if err == nil && code == 0 {
		return nil
	}
	if err != nil || code != 1 {
		return fail(api.CodeZapFailed, "The host could not ask podman whether the ZAP image is on this box.")
	}
	o.zapMu.Lock()
	defer o.zapMu.Unlock()
	if o.zapPulling {
		return refuse409(api.CodeZapPulling, "The ZAP image (about 1.2 GB) is being downloaded; the passive web scan runs once it is on this box.")
	}
	last := o.zapPullErr
	o.zapPulling, o.zapPullErr = true, ""
	go o.zapPull() //nolint:gosec,contextcheck // the download outlives this run on purpose: it runs on the process's own context (loopCtx), bounded to 45 minutes
	if last != "" {
		return refuse409(api.CodeZapPullFailed, "The last download of the ZAP image failed ("+last+"); the host is trying again now.")
	}
	return refuse409(api.CodeZapPulling, "The ZAP image (about 1.2 GB) is not on this box yet; the host started its download, and the passive web scan runs once it is there.")
}

// zapPull downloads the image by its digest (podman checks it) and checks the effect. It runs beside the command, on the process's
// own context, and audits its outcome.
func (o *Ops) zapPull() {
	o.mu.Lock()
	parent := o.loopCtx
	o.mu.Unlock()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, zapPullWait)
	defer cancel()
	reason := ""
	if free, err := o.d.FreeBytes(o.path("var/lib/containers")); err != nil {
		reason = "the free space under /var/lib/containers could not be read"
	} else if free < zapMinFree {
		reason = fmt.Sprintf("only %d MiB free under /var/lib/containers, %d MiB needed", free>>20, uint64(zapMinFree)>>20)
	} else if _, code, err := o.zx()(ctx, binPodman, nil, zapPullArgv()...); err != nil || code != 0 {
		reason = "podman pull failed: the box may not reach ghcr.io"
	} else if _, code, err := o.zapStep(ctx, binPodman, nil, zapImageExistsArgv()...); err != nil || code != 0 {
		reason = "the image is not there after the pull"
	}
	o.zapMu.Lock()
	o.zapPulling, o.zapPullErr = false, reason
	o.zapMu.Unlock()
	if reason != "" {
		o.log.ErrorContext(ctx, "zap.baseline: the ZAP image could not be pulled", "reason", reason)
		o.note(api.CmdZapBaseline, "zap_image_pull_failed", map[string]any{"image": zapImage, "reason": reason})
		return
	}
	o.note(api.CmdZapBaseline, "zap_image_pulled", map[string]any{"image": zapImage})
}

// zapOwned is the host's own re-check of ownership, right before the run.
func (o *Ops) zapOwned(ctx context.Context, p zapPage) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if p.kind == api.ZapKindIP {
		got, err := o.zapEgress(cctx)
		switch {
		case err != nil:
			return fail(api.CodeOwnershipUnchecked, "The host could not reach the public IP services to check that "+p.ip.String()+" is still this box's address, so nothing was sent.")
		case got != p.ip:
			return refuse412(api.CodeTargetNotOwned, "This box no longer reaches the Internet through "+p.ip.String()+", so its pages were not scanned.")
		}
		return nil
	}
	vals, err := o.zapTXT(cctx, p.domain)
	var nf interface{ NotFound() bool }
	if err != nil && (!errors.As(err, &nf) || !nf.NotFound()) {
		return fail(api.CodeOwnershipUnchecked, "The DNS lookup of "+p.domain+" failed, so its TXT record could not be checked and nothing was sent.")
	}
	if !slices.ContainsFunc(vals, func(v string) bool { return strings.TrimSpace(v) == "vedette-verify="+p.token }) { // exposure's txtRecord
		return refuse412(api.CodeTargetNotOwned, p.domain+" no longer has its vedette-verify TXT record, so its pages were not scanned.")
	}
	// The address the fence opens must be one the name points at now: core's word for it is not enough (review M1).
	// A name that now answers with other addresses (a moved record, a CDN's rotating subset) stops this page only (zap_name_moved).
	addrs, err := o.zapLookupIP(cctx, p.host)
	if err != nil && (!errors.As(err, &nf) || !nf.NotFound()) {
		return fail(api.CodeOwnershipUnchecked, "The DNS lookup of "+p.host+" failed, so the host could not check that it points at "+p.ip.String()+", and nothing was sent.")
	}
	if !slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == p.ip }) {
		return refuse412(api.CodeZapNameMoved, p.host+" no longer points at "+p.ip.String()+", so this page was not scanned.")
	}
	return nil
}

func (o *Ops) zapLookupIP(ctx context.Context, name string) ([]netip.Addr, error) {
	if o.d.ZapLookupIP != nil {
		return o.d.ZapLookupIP(ctx, name)
	}
	return lookupIPv4(ctx, name)
}

func (o *Ops) zapEgress(ctx context.Context) (netip.Addr, error) {
	if o.d.ZapEgress != nil {
		return o.d.ZapEgress(ctx)
	}
	pr, err := egressip.New(nil, nil, 0)
	if err != nil {
		return netip.Addr{}, err
	}
	return pr.Round(ctx)
}

func (o *Ops) zapTXT(ctx context.Context, name string) ([]string, error) {
	if o.d.ZapTXT != nil {
		return o.d.ZapTXT(ctx, name)
	}
	return lookupTXT(ctx, name)
}

// zapFence makes sure the network is the host's own and loads and reads back the egress rule of this page.
func (o *Ops) zapFence(ctx context.Context, p zapPage) error {
	refused := func(why string, res ...vexec.Result) error {
		attrs := []any{"reason", why}
		if len(res) > 0 { // what podman or nft printed (a read-back that differs is on stdout): the page sends the reader to the box log
			attrs = append(attrs, "stderr", clipText(strings.TrimSpace(string(res[0].Stderr)), 500), "stdout", clipText(strings.TrimSpace(string(res[0].Stdout)), 500))
		}
		o.log.ErrorContext(ctx, "zap.baseline: the network fence could not be set up", attrs...)
		return fail(api.CodeZapFenceFailed, "The host could not set up the network fence of the web scan ("+why+"), so ZAP was not started.")
	}
	res, code, err := o.zapStep(ctx, binPodman, nil, zapNetExistsArgv()...)
	switch {
	case err != nil || (code != 0 && code != 1):
		return refused("podman did not say whether the network vedette-zap exists", res)
	case code == 1:
		if res, code, err := o.zapStep(ctx, binPodman, nil, zapNetCreateArgv()...); err != nil || code != 0 {
			return refused("podman could not create the network vedette-zap", res)
		}
	}
	res, code, err = o.zapStep(ctx, binPodman, nil, zapNetInspectArgv()...)
	if err != nil || code != 0 || res.Truncated || !zapNetworkIsOurs(res.Stdout) {
		return refused("the network vedette-zap is not the one the host makes: label io.vedette.owner=vedette-host, bridge vedette-zap0, no DNS, no options, one IPv4 subnet, not internal", res)
	}
	rules, err := zapRuleset(p.ip, p.port)
	if err != nil {
		return refused("the address cannot be written as a rule")
	}
	if res, code, err := o.zapStep(ctx, binNft, strings.NewReader(rules), nftLoadArgv...); err != nil || code != 0 {
		return refused("nft could not load the egress rule", res)
	}
	res, code, err = o.zapStep(ctx, binNft, nil, nftListArgv...)
	if err != nil || code != 0 || res.Truncated || !zapRulesetLoaded(res.Stdout, p.ip, p.port) {
		return refused("the egress rule read back from nft is not the one loaded", res)
	}
	return nil
}

// zapNetworkIsOurs reads podman network inspect: exactly the network vedette-zap the host made (its label), a bridge named
// vedette-zap0 with no driver options (an "unmanaged" bridge on the LAN card, for one, would put ZAP on the LAN below the fence), no
// DNS, no IPv6, not internal, one IPv4 subnet.
func zapNetworkIsOurs(out []byte) bool {
	var nets []struct {
		Name      string            `json:"name"`
		Driver    string            `json:"driver"`
		Interface string            `json:"network_interface"`
		IPv6      bool              `json:"ipv6_enabled"`
		DNS       bool              `json:"dns_enabled"`
		Internal  bool              `json:"internal"`
		Labels    map[string]string `json:"labels"`
		Options   map[string]string `json:"options"`
		Subnets   []struct {
			Subnet string `json:"subnet"`
		} `json:"subnets"`
	}
	if json.Unmarshal(out, &nets) != nil || len(nets) != 1 {
		return false
	}
	n := nets[0]
	key, val, _ := strings.Cut(zapLabel, "=")
	if len(n.Subnets) != 1 {
		return false
	}
	sub, err := netip.ParsePrefix(n.Subnets[0].Subnet)
	return n.Name == zapNetwork && n.Driver == "bridge" && n.Interface == zapBridge && !n.DNS && !n.IPv6 && !n.Internal &&
		n.Labels[key] == val && len(n.Options) == 0 && err == nil && sub.Addr().Is4()
}

// zapContainerIsOurs reads podman container inspect of vedette-zap: ours says whether it carries zapLabel; ok is false when the
// answer cannot be read (then nothing is concluded from it).
func zapContainerIsOurs(out []byte) (ours, ok bool) {
	var ctrs []struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if len(out) > maxInspectOutput || json.Unmarshal(out, &ctrs) != nil || len(ctrs) != 1 {
		return false, false
	}
	key, val, _ := strings.Cut(zapLabel, "=")
	return ctrs[0].Config.Labels[key] == val, true
}

// zapContainerGone removes the container vedette-zap when it is the host's (zapLabel) and says whether no ZAP of the host can still
// run: gone is true only when podman says no container of that name exists after it, or the one there is someone else's (foreign,
// never removed). Every answer that cannot be read is "not gone".
func (o *Ops) zapContainerGone(ctx context.Context) (gone, foreign bool) {
	exists := func() (bool, bool) { // there, known
		_, code, err := o.zapStep(ctx, binPodman, nil, zapCtrExistsArgv()...)
		return err == nil && code == 0, err == nil && (code == 0 || code == 1)
	}
	there, known := exists()
	if !known {
		return false, false
	}
	if !there {
		return true, false
	}
	res, code, err := o.zapStep(ctx, binPodman, nil, zapCtrInspectArgv()...)
	if err != nil || code != 0 || res.Truncated {
		return false, false
	}
	ours, ok := zapContainerIsOurs(res.Stdout)
	switch {
	case !ok:
		return false, false
	case !ours:
		return true, true
	}
	if _, code, err := o.zapStep(ctx, binPodman, nil, zapRmArgv()...); err != nil || code != 0 {
		return false, false
	}
	there, known = exists()
	return known && !there, false
}

// zapClearStale is the start of a run: a container a run left (podman run killed at its limit, the host restarted) or a run whose
// cleanup did not finish is cleaned up now; until that works the run is refused, and a container of that name that is not the
// host's stops it.
func (o *Ops) zapClearStale(ctx context.Context) error {
	_, merr := os.Lstat(filepath.Join(o.zapDir(), "active"))
	gone, foreign := o.zapContainerGone(ctx)
	switch {
	case foreign:
		return fail(api.CodeZapFenceFailed, "A container named vedette-zap that is not Vedette's is on this box, so ZAP was not started.")
	case !gone:
		o.zapCleanupIncomplete(ctx, "the container of an earlier passive web scan could not be proven gone")
		return refuse409(api.CodeZapCleaningUp, "The host is still cleaning up an earlier passive web scan.")
	case merr == nil && !o.zapCleanup(ctx):
		return refuse409(api.CodeZapCleaningUp, "The host is still cleaning up an earlier passive web scan.")
	}
	return nil
}

func (o *Ops) zapCleanupIncomplete(ctx context.Context, why string) {
	o.log.ErrorContext(ctx, "zap.baseline: cleanup incomplete; the egress fence and the marker are kept", "reason", why)
	o.note(api.CmdZapBaseline, "zap_cleanup_incomplete", map[string]any{"reason": why})
}

// zapCleanup removes what a run leaves, on every path: the container (podman run was killed at its limit, or the host died, while
// it ran), then, only once no ZAP of the host can still run, the egress rule; then the work directory and the marker. When the
// container cannot be proven gone the rule and the marker stay (a fence that outlives its container harms nothing; a container that
// outlives its fence could reach anything), the step is audited, and the next run or host start tries again. It reports whether
// everything went.
func (o *Ops) zapCleanup(ctx context.Context) bool {
	if gone, _ := o.zapContainerGone(ctx); !gone {
		o.zapCleanupIncomplete(ctx, "the container vedette-zap could not be removed or proven gone")
		return false
	}
	if _, code, err := o.zapStep(ctx, binNft, nil, nftDeleteArgv...); err != nil || code != 0 {
		// nft exits 1 when the table is not there (a fence that never loaded): the listing says which
		if _, lc, lerr := o.zapStep(ctx, binNft, nil, nftListArgv...); lerr != nil || lc == 0 {
			o.zapCleanupIncomplete(ctx, "the nft table inet vedette_zap could not be deleted")
			return false
		}
	}
	if err := os.RemoveAll(filepath.Join(o.zapDir(), "wrk")); err != nil {
		o.zapCleanupIncomplete(ctx, "the work folder could not be removed")
		return false
	}
	_ = removeIfThere(filepath.Join(o.zapDir(), "active"))
	return true
}

// zapAtStart runs at host start: a run the previous process did not finish is cleaned up, and its reports go.
func (o *Ops) zapAtStart(ctx context.Context) {
	if _, err := os.Lstat(filepath.Join(o.zapDir(), "active")); err == nil {
		_ = o.zapCleanup(ctx)
	}
	o.zapClearReports()
}

// zapClearReports removes the reports of earlier runs (one is kept at most, until the next run or start).
func (o *Ops) zapClearReports() {
	ents, err := os.ReadDir(o.zapDir())
	if err != nil {
		return
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			_ = os.Remove(filepath.Join(o.zapDir(), e.Name()))
		}
	}
}

// zapKeepReport moves the report out of the work directory, which the container could write: a regular file only (never a link or
// a FIFO), at most MaxZapReport bytes, copied to zap/<id>.json (0600).
func (o *Ops) zapKeepReport(wrk string) (id string, size int64, err error) {
	f, st, err := openRegularNoFollow(filepath.Join(wrk, zapReportName))
	if err != nil {
		return "", 0, fail(api.CodeZapFailed, "ZAP ended without writing its report.")
	}
	defer func() { _ = f.Close() }()
	if st.Size() > api.MaxZapReport {
		return "", 0, fail(api.CodeZapReportTooLarge, fmt.Sprintf("ZAP's report is larger than %d MiB.", api.MaxZapReport>>20))
	}
	b, err := io.ReadAll(io.LimitReader(f, api.MaxZapReport+1))
	if err != nil {
		return "", 0, fail(api.CodeZapFailed, "The host could not read ZAP's report.")
	}
	if len(b) > api.MaxZapReport {
		return "", 0, fail(api.CodeZapReportTooLarge, fmt.Sprintf("ZAP's report is larger than %d MiB.", api.MaxZapReport>>20))
	}
	if id, err = randomHex(16); err != nil {
		return "", 0, fail(api.CodeZapFailed, "The host could not keep ZAP's report.")
	}
	if err := writeFileAtomic(filepath.Join(o.zapDir(), id+".json"), b, 0o600); err != nil {
		return "", 0, fail(api.CodeZapFailed, "The host could not keep ZAP's report.")
	}
	return id, int64(len(b)), nil
}

// zapReport serves GET /v1/zap/{id}/content.
func (o *Ops) zapReport(id string) (server.File, error) {
	if !hexIDRE.MatchString(id) {
		return server.File{}, server.NewReadError(404, api.CodeZapReportUnknown, "There is no such report.")
	}
	f, st, err := openRegularNoFollow(filepath.Join(o.zapDir(), id+".json"))
	if err != nil {
		return server.File{}, server.NewReadError(404, api.CodeZapReportUnknown, "There is no such report: the host keeps only the last one, until the next scan or start.")
	}
	return server.File{Body: f, Size: st.Size(), Name: "zap-report.json", Type: "application/json"}, nil
}
