package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/domainfence/proofat"
	"github.com/knt048/vedette/core/egressip"
	vexec "github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// zap.baseline (host-api §6.15, exposure INV-24): ZAP's passive baseline scan of one page of a verified exposure
// target, in a one-shot container the host starts with a fixed argv. The fences, in the order a run takes them:
//
//  1. The arguments (Validate): the URL is exactly http(s)://Host[:Port]/ (no user, query or fragment), IP is a public IPv4 address
//     (egressip.IsPublicIPv4), Port 1-65535, Host is the IP itself (kind ip) or the verified domain or a name under it (kind domain).
//     Everything of one page up to the end of the run fits in zapPageLimit, inside exposure's 8 minutes.
//  2. One run at a time (busy otherwise), and the image is on the box: when it is not, the host starts its download by digest in the
//     background and refuses (zap_image_pulling): the ~1.2 GB download happens only for a box whose owner pressed Scan now.
//  3. The host's own re-check of ownership, right before the run: kind ip, core's proof of the box's own IP holds (proven_at, the
//     latest sighting of IP as the box's egress, inside 90 days: egressip.ProofHolds; the box may go out through another line now),
//     else the box leaves the Internet through IP now (core/egressip, two of three services agree); kind domain, the domain still has its TXT record vedette-verify=<token> AND the page's name
//     resolves (A records, system resolver) to the IP ZAP is pinned to. Core asked the same moments before (exposure INV-13); the
//     host does not take core's word for the IP it opens the fence to.
//  4. The fence: the podman network vedette-zap (made by the host with zapLabel; bridge vedette-zap0, no DNS, no options, one IPv4
//     subnet, not internal) and the nft table inet vedette_zap, loaded in one transaction (its text checked against zapRuleset
//     before nft sees it) and read back, which drops everything that enters the host from that bridge (forward and input) except TCP to
//     IP:Port. The container gets no resolver (--dns none) and, for a domain, the one name pinned to IP (--add-host), so a redirect to
//     another host or port, a DNS lookup or a call home to zaproxy.org fails at the network layer.
//  5. The container: --rm, --read-only (tmpfs for ZAP's home, podman's own for /tmp and /run), --cap-drop ALL, no-new-privileges,
//     Vedette's AppArmor profile, 1 GiB without swap, 256 pids, the image's zap user, a JVM heap of 512 MiB, -silent (no
//     update check, no call home), spider 1 minute, passive rules 5 minutes, no form posted (the traditional runner, --autooff),
//     never -a (active scan), -j (AJAX spider) or -u.
//  6. After the run, on every path: the container is removed (only one that carries zapLabel) and must then be proven gone, and only
//     then is the nft table deleted (a ZAP that may still run keeps its fence); then the work directory and the marker zap/active go.
//     What cannot be proven gone keeps the table and the marker, is audited (zap_cleanup_incomplete), and is tried again by the next
//     run, which refuses until it is clean (zap_cleaning_up), and by the next host start.
//
// The report is read from the work directory (a bind mount, 0700, owned by the image's zap user; a symlink, a FIFO or a file over
// MaxZapReport is refused), kept as zap/<id>.json until the next run or host start, and served by GET /v1/zap/{id}/content. It is
// untrusted: exposure's ParseZAPReport reads it.

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
	// digest.
	zapImage = "ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"

	// zapUID is the zap user of the image (useradd -u 1000 in its Dockerfile): the container runs as it, and the work directory is its.
	zapUID = 1000

	zapWorkDir    = "/zap/wrk" //nolint:gosec // a path inside the ZAP container, not a credential
	zapReportName = "out.json"
	// zapTmpfs is ZAP's home: podman copies the image's /home/zap into it (tmpcopyup, its default, keeping the zap user's own files
	// its), and it counts against --memory. mode=1777 (sticky, like /tmp) lets the zap user write in it: podman refuses the tmpfs
	// options uid= and gid= ("unknown mount option", podman 5.7 on a test box: ZAP never started), and the tmpfs belongs to this
	// one container. Plain tmpfs options only, so every podman the installer supports accepts it.
	zapTmpfs = "/home/zap:rw,size=256m,mode=1777"
	// zapCwd is the container's working directory: zap-baseline.py's traditional runner (--autooff) writes ZAP's own log to zap.out
	// in the current directory (zap_common.start_zap), and the image's WORKDIR /zap is on the read-only root. It is the work
	// mount, so zap.out outlives the container and the host logs its last lines when ZAP fails (zaptmpfs review M: on the tmpfs
	// ZAP's own reason for a failed start was lost with the container).
	zapCwd = zapWorkDir
	// zapOptions are ZAP's own options (-z): -silent (no update check, no unsolicited request), a heap of half the container's memory
	// (zap.sh reads -Xmx from its arguments; without it it takes a quarter of the HOST's memory on cgroup v2, 1.75 GiB on a test box),
	// no form handled or posted by the spider and one spider thread, gentle on a fragile site (exposure INV-24). The spider
	// options hold only because the run is --autooff: the traditional runner starts the spider through ZAP's API with these
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
	url     string
	host    string
	ip      netip.Addr
	port    int
	kind    string
	domain  string
	token   string
	proofAt string // The parent name where the domain's own record sits; "" = on the domain
	// typed is the proof of an IP page's typed IP (kind ip); token is then its box-bound token. nil for the box's own IP.
	typed *api.ExposureTyped
	// provenAt is, for the box's own IP, the latest sighting of it as the box's egress that core's gate took it on (zero: none sent).
	provenAt time.Time
	// skip are the validated URL path prefixes ZAP never requests (api.ZapSettings.SkipPaths); nil: none.
	skip []string
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

// zapArgs validates the args at the edge: every refusal names the field.
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
	var paths []string
	if a.Settings != nil {
		paths = a.Settings.SkipPaths
	}
	skip, err := zapSkipPaths(paths)
	if err != nil {
		return zapPage{}, err
	}
	p := zapPage{url: a.URL, host: a.Host, ip: ip, port: a.Port, kind: a.Kind, skip: skip}
	if a.ProvenAt != "" && (a.Kind != api.ZapKindIP || a.Typed != nil) {
		return zapPage{}, server.Invalid("proven_at", "is for the box's own IP only (kind ip, not a typed IP)")
	}
	switch a.Kind {
	case api.ZapKindIP:
		if a.Host != ip.String() {
			return zapPage{}, server.Invalid("host", "must be the IP itself for an IP target")
		}
		if a.Typed != nil { // a typed public IP: the host checks its own proof, with the token bound to this box
			if a.Domain != "" || a.ProofAt != "" || !zapTokenRE.MatchString(a.TXTToken) {
				return zapPage{}, server.Invalid("txt_token", "must be the hex token of the typed IP, with no domain")
			}
			if err := (domainfence.Job{Domain: a.Host, Name: a.Host, IP: ip, Token: a.TXTToken, Typed: typedProof(a.Typed)}).Valid(); err != nil {
				return zapPage{}, server.Invalid("typed", err.Error())
			}
			p.token, p.typed = a.TXTToken, a.Typed
			break
		}
		if a.Domain != "" || a.TXTToken != "" {
			return zapPage{}, server.Invalid("domain", "is for a domain target only")
		}
		if a.ProvenAt != "" {
			at, err := time.Parse(time.RFC3339, a.ProvenAt)
			if err != nil {
				return zapPage{}, server.Invalid("proven_at", "must be an RFC 3339 time")
			}
			p.provenAt = at
		}
	case api.ZapKindDomain:
		if len(a.Domain) > 253 || !zapHostRE.MatchString(a.Domain) {
			return zapPage{}, server.Invalid("domain", "must be a domain name")
		}
		// The page's host is the domain or a name under it; with a proof name (ProofAt, a name above the domain where its token sits)
		// it may be any name under that name, the record covering them all (the same bound as domainfence.Job.Valid).
		bound := a.Domain
		if a.ProofAt != "" {
			bound = a.ProofAt
		}
		if len(a.Host) > 253 || !zapHostRE.MatchString(a.Host) || (a.Host != bound && !strings.HasSuffix(a.Host, "."+bound)) {
			return zapPage{}, server.Invalid("host", "must be the domain or a name under it (under the proof name when there is one)")
		}
		if !zapTokenRE.MatchString(a.TXTToken) {
			return zapPage{}, server.Invalid("txt_token", "must be the hex token of the domain")
		}
		if a.ProofAt != "" && (a.ProofAt == a.Domain || !proofat.Within(a.Domain, a.ProofAt) || !proofat.Within(a.Host, a.ProofAt)) { // the same bound as core
			return zapPage{}, server.Invalid("proof_at", "must be a parent name of the domain and of the page's host, down to its registered domain")
		}
		p.domain, p.token, p.proofAt = a.Domain, a.TXTToken, a.ProofAt
	default:
		return zapPage{}, server.Invalid("kind", "must be ip or domain")
	}
	return p, nil
}

// zapSkipPaths validates the web paths to skip (api.ZapSettings.SkipPaths): each a URL path prefix as written, never a pattern.
// "/" alone would leave out the page itself: refused, like a repeat.
func zapSkipPaths(paths []string) ([]string, error) {
	if len(paths) > api.ZapMaxSkipPaths {
		return nil, server.Invalid("settings.skip_paths", fmt.Sprintf("must hold at most %d paths", api.ZapMaxSkipPaths))
	}
	for i, p := range paths {
		if !zapSkipPathRE.MatchString(p) || len(p) > api.ZapMaxSkipPathLen || p == "/" || slices.Contains(paths[:i], p) {
			return nil, server.Invalid("settings.skip_paths", fmt.Sprintf("must be distinct URL path prefixes other than / alone, each starting with /, at most %d "+
				"characters of letters, digits and - . _ ~ %% ! & ' , ; = : @ /", api.ZapMaxSkipPathLen))
		}
	}
	if len(paths) == 0 {
		return nil, nil
	}
	return slices.Clone(paths), nil
}

// zapSkipPathRE is a path to skip: the characters of a URL path, never those of a pattern, a query or a fragment.
var zapSkipPathRE = regexp.MustCompile(`^/[A-Za-z0-9\-._~%!&',;=:@/]*$`)

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
// --autooff pins zap-baseline.py's traditional runner, where the -z spider options apply.
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
		if isZapRunArgv(stateDir, args) || isZapActiveArgv(stateDir, args) || isGreenbonePodmanArgv(args) { // OpenVAS: greenbone.go
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
// with a syntax error, so no fence could ever load (seen on a test box: "nft could not load the egress rule").
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
			return o.zapRun(ctx, rc.Log, p, zapPass{req: rc.RequestID})
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

// zapPass is what one run does: the passive baseline (zap.baseline), or the active scan (zap.active) with or without the disruptive
// rules.
type zapPass struct {
	active     bool
	disruptive bool
	req        string // the request id of the run (RunContext.RequestID): zap.stop names it
	actor      string // the run's actor label (RunContext.Actor): a grant holds only for runs of the actor it was minted for
	grant      string // the grant of zap.authorize that came with a run asking for the disruptive rules
	// noDoS, noChange and gentle are the deep-scan settings of an active run (api.ZapSettings): they only narrow its plan.
	noDoS, noChange, gentle bool
	// passive runs the page's passive pass in the same active run (api.ZapActiveArgs.Passive); tech are the technologies its active
	// scan leaves out (TechExclude).
	passive bool
	tech    []string
}

func (o *Ops) zapBaseline(ctx context.Context, logf func(string), p zapPage) (any, error) {
	return o.zapRun(ctx, logf, p, zapPass{})
}

// zapRun is one run of ZAP on one page, the passive baseline or the active scan: every fence below is the same for both.
func (o *Ops) zapRun(ctx context.Context, logf func(string), p zapPage, pass zapPass) (any, error) {
	limit, what := zapPageLimit, "passive web scan"
	switch {
	case pass.active && pass.passive:
		limit, what = zapCombinedPageLimit, "web scan"
	case pass.active:
		limit, what = zapActivePageLimit, "active web scan"
	}
	o.zapMu.Lock()
	if _, ok := o.zapStopped[pass.req]; ok && pass.req != "" { // zap.stop came before this run: it never starts
		delete(o.zapStopped, pass.req)
		o.zapMu.Unlock()
		return nil, refuse409(api.CodeZapStopped, "The "+what+" was stopped before it started; ZAP was not started.")
	}
	if o.zapBusy {
		o.zapMu.Unlock()
		return nil, refuse409(api.CodeBusy, "A web scan (ZAP) is already running on this box.")
	}
	ctx, stop := context.WithCancelCause(ctx)
	done := make(chan struct{})
	o.zapBusy, o.zapStop, o.zapDone, o.zapReq = true, func() { stop(errZapStopped) }, done, pass.req
	o.zapMu.Unlock()
	// Last: once the cleanup below is over, the run is no longer busy and zap.stop's wait ends.
	defer func() {
		o.zapMu.Lock()
		o.zapBusy, o.zapStop, o.zapDone, o.zapReq = false, nil, nil, ""
		o.zapMu.Unlock()
		stop(nil)
		close(done)
	}()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	if ref := o.zapImageReady(ctx); ref != nil {
		return nil, ref
	}
	if err := o.zapOwned(ctx, logf, p); err != nil {
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
	argv := p.runArgv(wrk)
	refused := ""
	if pass.active && pass.disruptive { // the host's own checks, right before the run (zapgrant.go): a refusal runs the page without them
		if refused = o.zapDisruptiveRefusal(p, pass); refused != "" {
			pass.disruptive = false
			logf("the disruptive rules do not run on " + p.url + ": " + zapRefusalText(refused))
		}
	}
	opts := zapActiveOpts{disruptive: pass.disruptive, noDoS: pass.noDoS, noChange: pass.noChange, gentle: pass.gentle, passive: pass.passive, tech: pass.tech}
	switch {
	case pass.active:
		// The plan is the host's own text, readable by the container's zap user (the folder is its; the file is root's, 0644).
		if err := os.WriteFile(filepath.Join(wrk, zapPlanName), []byte(zapPlanActive(p, opts)), 0o644); err != nil { //nolint:gosec // ZAP's user reads it in the container
			return nil, fail(api.CodeZapFailed, "The host could not write the plan of the active web scan.")
		}
		argv = p.activeArgv(wrk)
		rules := "the disruptive rules off"
		if pass.disruptive {
			rules = "the disruptive rules on (the box's own IP)"
		}
		threads, delay := zapPace(opts)
		if pass.passive {
			logf("passive and active web scan of " + p.url + " pinned to " + p.ip.String() + ":" + strconv.Itoa(p.port) + fmt.Sprintf(" in one ZAP run (spider %d minutes, depth %d; passive rules, their report; then active rules %d minutes at most, %d threads, %d ms between requests; %s%s)",
				zapSpiderMinutes, zapSpiderDepth, zapActiveMinutes, threads, delay, rules, zapSettingsNote(p, opts)))
			break
		}
		logf("active web scan of " + p.url + " pinned to " + p.ip.String() + ":" + strconv.Itoa(p.port) + fmt.Sprintf(" (ZAP active scan: spider %d minutes, depth %d; active rules %d minutes at most, %d threads, %d ms between requests; %s%s)",
			zapSpiderMinutes, zapSpiderDepth, zapActiveMinutes, threads, delay, rules, zapSettingsNote(p, opts)))
	case len(p.skip) > 0:
		// zap-baseline.py has no exclude: the passive pass runs as the host's own plan, with the paths to skip out of its context.
		if err := os.WriteFile(filepath.Join(wrk, zapPlanName), []byte(zapPassivePlan(p)), 0o644); err != nil { //nolint:gosec // ZAP's user reads it in the container
			return nil, fail(api.CodeZapFailed, "The host could not write the plan of the passive web scan.")
		}
		argv = p.activeArgv(wrk)
		logf("passive web scan of " + p.url + " pinned to " + p.ip.String() + ":" + strconv.Itoa(p.port) + " (ZAP passive plan, spider 1 minute, passive rules" + zapSettingsNote(p, opts) + ")")
	default:
		logf("passive web scan of " + p.url + " pinned to " + p.ip.String() + ":" + strconv.Itoa(p.port) + " (ZAP baseline, spider 1 minute, passive rules)")
	}
	res, code, err := o.zx()(ctx, binPodman, nil, argv...)
	stopped, slow := errors.Is(context.Cause(ctx), errZapStopped), ctx.Err() != nil
	// A run with its passive pass wrote the passive report before its active scan started: it is kept whatever the active part did,
	// unless the run was stopped (core gave up on the page, or the scan was stopped) or podman could not run at all (the page's limit
	// ends podman run with an error too).
	var passive *api.ZapActiveResult
	if pass.passive && !stopped && (err == nil || slow) {
		pid, psize, perr := o.zapKeepReportAs(wrk, zapPassiveReportName)
		if perr != nil {
			if !slow && code >= 0 && code <= 2 {
				return nil, perr // ZAP ended well, without its passive report: the run did not do what it was asked
			}
		} else {
			passive = &api.ZapActiveResult{PassiveReportID: pid, PassiveSize: psize, ExitCode: code, CutShort: true, DisruptiveRules: zapDisruptiveRuleIDs(),
				DisruptiveRefused: refused, SkippedRules: zapSkippedRules(p, opts), Rules: zapPlanRules(p, opts)}
		}
	}
	switch {
	case stopped:
		return nil, fail(api.CodeZapStopped, "The "+what+" was stopped; ZAP's container was removed.")
	case slow && passive != nil:
		logf(fmt.Sprintf("ZAP did not finish within the host's time limit of %d minutes for a page: the passive report is kept, the active scan's results are not known", int(limit/time.Minute)))
		passive.ActiveFailed = api.CodeZapTimedOut
		return *passive, nil
	case slow:
		return nil, fail(api.CodeZapTimedOut, fmt.Sprintf("ZAP did not finish within the host's time limit of %d minutes for a page.", int(limit/time.Minute)))
	case err != nil:
		o.log.ErrorContext(ctx, "zap: podman run could not run", "error", err.Error())
		return nil, fail(api.CodeZapFailed, "The host could not start ZAP.")
	case (code < 0 || code > 2) && passive != nil:
		logf("ZAP ended with exit code " + strconv.Itoa(code) + " after the passive report: the active scan's results are not known")
		o.log.ErrorContext(ctx, "zap: ZAP ended without the active report", "exit_code", code, "stderr", lastLines(res.Stderr, 10, 2000),
			"stdout", lastLines(res.Stdout, 10, 2000), "truncated", res.Truncated, "zap_out", zapOutTail(wrk))
		passive.ActiveFailed = api.CodeZapFailed
		return *passive, nil
	case code < 0 || code > 2:
		logf("ZAP ended with exit code " + strconv.Itoa(code))
		// the box log carries ZAP's (or podman's) own last words: the page sends the reader there (n39)
		o.log.ErrorContext(ctx, "zap: ZAP ended without a report", "exit_code", code, "stderr", lastLines(res.Stderr, 10, 2000),
			"stdout", lastLines(res.Stdout, 10, 2000), "truncated", res.Truncated, "zap_out", zapOutTail(wrk))
		msg := "ZAP ended without a report (exit code " + strconv.Itoa(code) + ")."
		switch {
		case code == 3 && !pass.active: // the traditional runner ends so when it cannot reach the page, finds no URL there, or cannot start
			msg = "ZAP ended without a report (exit code 3): it could not reach the page from this box, found no page there, or could not start."
		case code == 137:
			msg = "ZAP was stopped, most likely because it reached its memory limit (exit code 137)."
		case code >= zapNoRun && code <= zapNoRun+2:
			msg = "Podman could not start the ZAP container (exit code " + strconv.Itoa(code) + ")."
		}
		return nil, fail(api.CodeZapFailed, msg)
	}
	id, size, ferr := o.zapKeepReport(wrk)
	if ferr != nil && passive != nil { // the active report is missing or too large: the passive one stands
		logf("the active scan's report could not be kept: the passive report is kept")
		passive.ActiveFailed = api.CodeZapFailed
		var f *server.Failure
		if errors.As(ferr, &f) && f.Code == api.CodeZapReportTooLarge {
			passive.ActiveFailed = api.CodeZapReportTooLarge
		}
		return *passive, nil
	}
	if ferr != nil {
		return nil, ferr
	}
	logf("ZAP finished with exit code " + strconv.Itoa(code) + "; report " + strconv.FormatInt(size, 10) + " bytes")
	if pass.active {
		cut := zapCutShort(res.Stdout)
		if cut {
			logf(fmt.Sprintf("the active scan reached its limit of %d minutes: the report holds what it found until then", zapActiveMinutes))
		}
		if refused == api.ZapRefusedGrantMissing {
			// A request for the disruptive rules without a grant is how a core older than the grant asks (the host is updated first). Such
			// a core reads only cut_short to know that a page did not run every rule it asked for, and then closes no issue with it: so
			// the page is answered as one that did not, and that core can neither close an issue of a rule that never ran nor count the
			// page as attacked with the disruptive rules. A core that knows the grant never sends this request (it asks without
			// disruptive when it has no grant).
			cut = true
		}
		out := api.ZapActiveResult{ReportID: id, Size: size, ExitCode: code, CutShort: cut, DisruptiveRules: zapDisruptiveRuleIDs(), DisruptiveRefused: refused,
			SkippedRules: zapSkippedRules(p, opts)}
		if passive != nil {
			out.PassiveReportID, out.PassiveSize, out.Rules = passive.PassiveReportID, passive.PassiveSize, passive.Rules
		}
		return out, nil
	}
	return api.ZapBaselineResult{ReportID: id, Size: size, ExitCode: code}, nil
}

// zapOwner is the uid the work directory is given to (Deps.ZapUID in tests, the image's zap user otherwise).
func (o *Ops) zapOwner() int {
	if o.d.ZapUID > 0 {
		return o.d.ZapUID
	}
	return zapUID
}

// cmdZapPrepare is zap.prepare: the image's state, its download started when it is not on the box and none runs. Not a write command:
// it touches only the image, like the download zap.baseline starts.
func (o *Ops) cmdZapPrepare() server.Command {
	return server.Define(server.Spec[struct{}]{
		Name: api.CmdZapPrepare, Write: false, Timeout: zapPrepareTimeout,
		Run: func(ctx context.Context, rc *server.RunContext, _ struct{}) (any, error) {
			return o.zapPrepare(ctx, rc.Log)
		},
	})
}

// zapPrepareTimeout bounds zap.prepare: one podman image exists; the download itself runs beside it.
const zapPrepareTimeout = 2 * time.Minute

// zapPrepare answers the image's state and starts its download when it is missing and none runs.
func (o *Ops) zapPrepare(ctx context.Context, logf func(string)) (api.ZapPrepareResult, error) {
	_, code, err := o.zapStep(ctx, binPodman, nil, zapImageExistsArgv()...)
	if err == nil && code == 0 {
		logf("the ZAP image is on this box")
		return api.ZapPrepareResult{State: api.ZapImageReady}, nil
	}
	if err != nil || code != 1 {
		return api.ZapPrepareResult{}, fail(api.CodeZapFailed, "The host could not ask podman whether the ZAP image is on this box.")
	}
	o.zapMu.Lock()
	defer o.zapMu.Unlock()
	if o.zapPulling {
		logf("the ZAP image is being downloaded")
		return api.ZapPrepareResult{State: api.ZapImagePulling}, nil
	}
	last := o.zapPullErr
	o.zapPulling, o.zapPullErr = true, ""
	go o.zapPull() //nolint:gosec,contextcheck // the download outlives this command on purpose: it runs on the process's own context (loopCtx), bounded to 45 minutes
	logf("the ZAP image is not on this box: its download started")
	return api.ZapPrepareResult{State: api.ZapImagePulling, LastError: last}, nil
}

// zapImageReady refuses while the image is not on the box, and starts its download when none runs (pulled when first needed).
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
		return refuse409(api.CodeZapPulling, "The ZAP image (about 1.2 GB) is being downloaded; the web scan runs once it is on this box.")
	}
	last := o.zapPullErr
	o.zapPulling, o.zapPullErr = true, ""
	go o.zapPull() //nolint:gosec,contextcheck // the download outlives this run on purpose: it runs on the process's own context (loopCtx), bounded to 45 minutes
	if last != "" {
		return refuse409(api.CodeZapPullFailed, "The last download of the ZAP image failed ("+last+"); the host is trying again now.")
	}
	return refuse409(api.CodeZapPulling, "The ZAP image (about 1.2 GB) is not on this box yet; the host started its download, and the web scan runs once it is there.")
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
func (o *Ops) zapOwned(ctx context.Context, logf func(string), p zapPage) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if p.kind == api.ZapKindIP && p.typed != nil {
		return o.zapTypedOwned(cctx, logf, p)
	}
	if p.kind == api.ZapKindIP && !p.provenAt.IsZero() && egressip.ProofHolds(p.provenAt, o.d.Now()) {
		logf("own IP " + p.ip.String() + " proven by the box's sighting at " + p.provenAt.UTC().Format(time.RFC3339) + ", inside 90 days; the public IP services were not asked")
		return nil
	}
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
	// A page of a domain whose token is the box-bound one (a domain added since the fence) goes through the domain fence: the
	// host's list, the TXT record, the name's address. A domain verified before it keeps its own token for this passive scan, exactly as
	// in older releases (the old token keeps its scope; only the new domain_ip jobs need the box-bound one).
	bound := o.fence != nil && p.token == o.fence.Token(p.domain)
	switch {
	case !bound && p.proofAt != "": // review r1 M2 of #960: a record on a parent name proves a page only through the fence, never the legacy path
		return refuse412(api.CodeTokenForeign, p.domain+"'s token is not the one this box binds to it, so its record on "+p.proofAt+" cannot prove its pages, and they were not scanned.")
	case !bound:
		logf("legacy_token: " + p.domain + "'s token is not the box-bound one; checked the older way (TXT record and the name's address)")
		return o.zapOwnedLegacy(cctx, p)
	}
	res := o.fence.Check(cctx, domainfence.Job{Domain: p.domain, Name: p.host, IP: p.ip, Token: p.token, ProofAt: p.proofAt}, true)
	logf("domain fence of " + p.host + " (" + p.domain + ") at " + p.ip.String() + ", CNAME chain " + res.ChainText() + ": " + orYes(res.Reason))
	switch res.Reason {
	case "":
		return nil
	case domainfence.TokenForeign, domainfence.InvalidJob:
		return refuse412(api.CodeTokenForeign, "The host has not issued the token of "+p.domain+", so its pages were not scanned.")
	case domainfence.NotOwned:
		return refuse412(api.CodeTargetNotOwned, p.domain+" no longer has its vedette-verify TXT record, so its pages were not scanned.")
	case domainfence.NameMoved:
		return refuse412(api.CodeZapNameMoved, p.host+" no longer points at "+p.ip.String()+", so this page was not scanned.")
	case domainfence.Unchecked:
		return fail(api.CodeOwnershipUnchecked, "A DNS lookup of "+p.domain+" or "+p.host+" failed, so the host could not check them and nothing was sent.")
	}
	return refuse412(api.CodeTargetNotOwned, "The domain fence refused "+p.host+" ("+res.Reason+"), so this page was not scanned.")
}

// zapOwnedLegacy is the older check of a domain page: the domain still has its TXT record vedette-verify=<token> (domainfence.Owned)
// AND the page's name resolves (A records, system resolver) to the IP ZAP is pinned to. Core's word for the address is not enough
// (review M1): a name that now answers with other addresses stops this page only (zap_name_moved).
func (o *Ops) zapOwnedLegacy(ctx context.Context, p zapPage) error {
	// The one ownership rule of core/domainfence (on the domain or on _vedette-verify.<domain>, never through a CNAME or a
	// wildcard), with the token core sends for a domain verified before the fence.
	switch pr := domainfence.Owned(ctx, fenceResolver{o}, p.domain, p.token, domainfence.LookupTimeout); {
	case pr.Unchecked:
		return fail(api.CodeOwnershipUnchecked, "The DNS lookup of "+p.domain+" failed, so its TXT record could not be checked and nothing was sent.")
	case pr.At == "":
		return refuse412(api.CodeTargetNotOwned, p.domain+" no longer has its vedette-verify TXT record, so its pages were not scanned.")
	}
	addrs, err := o.zapLookupIP(ctx, p.host)
	if err != nil && !dnsNotFound(err) {
		return fail(api.CodeOwnershipUnchecked, "The DNS lookup of "+p.host+" failed, so the host could not check that it points at "+p.ip.String()+", and nothing was sent.")
	}
	if !slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == p.ip }) {
		return refuse412(api.CodeZapNameMoved, p.host+" no longer points at "+p.ip.String()+", so this page was not scanned.")
	}
	return nil
}

// dnsNotFound is the resolver's "no such name / no such record": an answer, not a failure.
func dnsNotFound(err error) bool {
	var de *net.DNSError
	var nf interface{ NotFound() bool }
	return errors.As(err, &de) && de.IsNotFound || errors.As(err, &nf) && nf.NotFound()
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
	return o.zapKeepReportAs(wrk, zapReportName)
}

// zapKeepReportAs keeps the report name of the work folder (out.json, or a run's passive.json) as zap/<id>.json.
func (o *Ops) zapKeepReportAs(wrk, name string) (id string, size int64, err error) {
	f, st, err := openRegularNoFollow(filepath.Join(wrk, name))
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

// lastLines is the last n lines of out, at most limit bytes of valid UTF-8: the tail of a tool's output for the box log.
func lastLines(out []byte, n, limit int) string {
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	s := strings.Join(lines, "\n")
	if len(s) > limit {
		s = s[len(s)-limit:]
	}
	return strings.ToValidUTF8(s, "")
}

// zapOutTail is the end of ZAP's own log (zap.out in the work folder, zapCwd) for the box log: at most its last 4 KiB, its last 15
// lines, "" when it is not a regular file (never followed through a link).
func zapOutTail(wrk string) string {
	f, st, err := openRegularNoFollow(filepath.Join(wrk, "zap.out"))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	const tail = 4 << 10
	off := max(st.Size()-tail, 0)
	b := make([]byte, tail)
	n, _ := f.ReadAt(b, off)
	return lastLines(b[:n], 15, tail)
}

// zapTypedOwned is the host's own re-check of a typed IP page: the fence (the box-bound token, the host's list, the IP's proof now).
func (o *Ops) zapTypedOwned(ctx context.Context, logf func(string), p zapPage) error {
	if o.fence == nil {
		return fail(api.CodeFenceUnavailable, "The host has no usable domain fence key; its log says why.")
	}
	res := o.fence.Check(ctx, domainfence.Job{Domain: p.host, Name: p.host, IP: p.ip, Token: p.token, Typed: typedProof(p.typed)}, true)
	logf("typed IP fence of " + p.ip.String() + " (" + p.typed.Method + "): " + orYes(res.Reason))
	switch res.Reason {
	case "":
		return nil
	case domainfence.TokenForeign, domainfence.InvalidJob:
		return refuse412(api.CodeTokenForeign, "The host has not issued the token of "+p.ip.String()+", so its pages were not scanned.")
	case domainfence.Unchecked:
		return fail(api.CodeOwnershipUnchecked, "The host could not check the proof of "+p.ip.String()+", so nothing was sent.")
	}
	return refuse412(api.CodeTargetNotOwned, "The proof of "+p.ip.String()+" (its token file or reverse DNS name) is not found now, so its pages were not scanned.")
}
