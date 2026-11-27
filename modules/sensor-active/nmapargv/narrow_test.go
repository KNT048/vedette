package nmapargv

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The deep-scan settings of a target narrow the full shapes: each group of checks it turns off leaves the shape's --script value,
// the ports it skips are never named to nmap, and the gentle speed is a second, slower --max-rate. Every narrowed line is one
// Validate accepts, and nothing else is; the lines of before (every group, no port skipped, FullRate) are unchanged.

// scriptSet is a --script value as a set.
func scriptSet(v string) map[string]bool {
	out := map[string]bool{}
	for _, s := range strings.Split(v, ",") {
		out[s] = true
	}
	return out
}

// scriptOf is the --script value of an argv ("" when there is none).
func scriptOf(args []string) string {
	if i := slices.Index(args, "--script"); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

var oneIP = []netip.Addr{netip.MustParseAddr("8.8.8.8")}

// Every script of the two full lists is in exactly one group or in the always-on base, held against nmap 7.95's own categories:
// the dos category and the crash checks are denial of service (whatever their category, a check that can crash or exhaust a service
// is), the brute category and the root-login check are password guessing, and the exploit-category scripts that send an attack
// payload (a command, script or SQL string, a path traversal, a backdoor's trigger) are the checks that may change data, with the
// same payloads sent by scripts outside that category. The disruptive line has no base: each of its scripts belongs to a group.
func TestGroupsCoverEveryScript(t *testing.T) {
	t.Parallel()
	nse := nse795(t)
	cats := map[string][]string{}
	for _, b := range nse {
		for s, c := range b {
			cats[s] = c
		}
	}
	all := slices.Concat(fullScripts, disruptiveExtra)
	for name, l := range map[string][]string{"dosScripts": dosScripts, "loginScripts": loginScripts, "changeScripts": changeScripts} {
		if !slices.IsSorted(l) || len(slices.Compact(slices.Clone(l))) != len(l) {
			t.Errorf("%s is not sorted and unique", name)
		}
		for _, s := range l {
			if !slices.Contains(all, s) {
				t.Errorf("%s: %s is in neither script list", name, s)
			}
		}
	}
	for _, s := range all {
		n := 0
		for _, l := range [][]string{dosScripts, loginScripts, changeScripts} {
			if slices.Contains(l, s) {
				n++
			}
		}
		if n > 1 {
			t.Errorf("%s is in %d groups", s, n)
		}
		c := cats[s]
		switch {
		case slices.Contains(c, "dos") && GroupOf(s) != GroupDoS:
			t.Errorf("%s is in the dos category but not denial of service", s)
		case slices.Contains(c, "brute") && GroupOf(s) != GroupLogins:
			t.Errorf("%s is in the brute category but not password guessing", s)
		case slices.Contains(c, "exploit") && !slices.Contains(c, "dos") && slices.Contains(fullScripts, s) && GroupOf(s) != GroupChange:
			if _, ok := exploitNoPayload[s]; !ok {
				t.Errorf("%s is in the exploit category of the full line and sends a payload, but is not a check that may change data", s)
			}
		}
	}
	for _, s := range disruptiveExtra {
		if GroupOf(s) == 0 {
			t.Errorf("disruptive %s is in no group: a group off would not remove it", s)
		}
	}
	for s, why := range disruptiveMoved {
		if strings.Contains(why, "crash") && GroupOf(s) != GroupDoS {
			t.Errorf("%s can crash a service but is not denial of service", s)
		}
	}
	for s := range exploitNoPayload {
		if GroupOf(s) != 0 || !slices.Contains(cats[s], "exploit") || !slices.Contains(fullScripts, s) {
			t.Errorf("%s: only an exploit-category script of the full line that stays in the base can be listed as sending no payload", s)
		}
	}
	for s, g := range map[string]Groups{
		"http-slowloris-check": GroupDoS, "http-slowloris": GroupDoS, "smb-vuln-ms08-067": GroupDoS, "smtp-vuln-cve2011-1720": GroupDoS,
		"mysql-vuln-cve2012-2122": GroupLogins, "ssh-brute": GroupLogins, "http-form-brute": GroupLogins,
		"http-sql-injection": GroupChange, "http-shellshock": GroupChange, "http-csrf": GroupChange, "http-dombased-xss": GroupChange,
		"http-phpself-xss": GroupChange, "qconn-exec": GroupChange, "distcc-cve2004-2687": GroupChange,
		"ftp-anon": 0, "realvnc-auth-bypass": 0, "http-title": 0, "ssl-heartbleed": 0, "http-enum": 0,
	} {
		if GroupOf(s) != g {
			t.Errorf("%s: group %d, want %d", s, GroupOf(s), g)
		}
	}
	count := func(l []string, g Groups) int {
		n := 0
		for _, s := range l {
			if GroupOf(s) == g {
				n++
			}
		}
		return n
	}
	if d, l, c := count(disruptiveExtra, GroupDoS), count(disruptiveExtra, GroupLogins), count(disruptiveExtra, GroupChange); d != 15 || l != 75 || c != 1 {
		t.Errorf("the disruptive line splits %d / %d / %d, want 15 denial of service, 75 password guessing, 1 data change", d, l, c)
	}
	if d, l, c := count(fullScripts, GroupDoS), count(fullScripts, GroupLogins), count(fullScripts, GroupChange); d != 1 || l != 0 || c != 30 {
		t.Errorf("the full line splits %d / %d / %d, want 1 denial of service, 0 password guessing, 30 data change", d, l, c)
	}
}

// The --script value of a full shape is the base and the scripts of the groups allowed, sorted: a group off leaves out each of its
// scripts and nothing else. Every group allowed is the value of before.
func TestScriptsFollowTheGroups(t *testing.T) {
	t.Parallel()
	if v, err := ScriptsOf(ExternalFull, Wide()); err != nil || v != FullScripts || v != strings.Join(fullScripts, ",") {
		t.Fatalf("every group allowed is not the full line of before: %v", err)
	}
	if v, err := ScriptsOf(ExternalDisruptive, Wide()); err != nil || v != DisruptiveScripts {
		t.Fatalf("every group allowed is not the disruptive line of before: %v", err)
	}
	for g := Groups(0); g <= AllGroups; g++ {
		for _, kind := range []Kind{ExternalFull, ExternalDisruptive} {
			list := fullScripts
			if kind == ExternalDisruptive {
				list = disruptiveExtra
			}
			v, err := ScriptsOf(kind, Narrow{Groups: g})
			if kind == ExternalDisruptive && g == 0 {
				if err == nil {
					t.Errorf("the disruptive line with no group allowed: %q", v)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s groups %d: %v", kind.Name(), g, err)
			}
			got := strings.Split(v, ",")
			if !slices.IsSorted(got) {
				t.Errorf("%s groups %d: the value is not sorted", kind.Name(), g)
			}
			var want []string
			for _, s := range list {
				if GroupOf(s) == 0 || g&GroupOf(s) != 0 {
					want = append(want, s)
				}
			}
			if !slices.Equal(got, want) {
				t.Errorf("%s groups %d: %d scripts, want %d", kind.Name(), g, len(got), len(want))
			}
		}
	}
	full := func(g Groups) map[string]bool {
		v, _ := ScriptsOf(ExternalFull, Narrow{Groups: g})
		return scriptSet(v)
	}
	dis := func(g Groups) map[string]bool {
		v, _ := ScriptsOf(ExternalDisruptive, Narrow{Groups: g})
		return scriptSet(v)
	}
	noDoS, noChange := full(AllGroups&^GroupDoS), full(AllGroups&^GroupChange)
	if noDoS["http-slowloris-check"] || !noDoS["http-shellshock"] || !noDoS["http-title"] {
		t.Error("denial of service off: http-slowloris-check stays, or another script went")
	}
	for _, s := range []string{"http-shellshock", "http-csrf", "http-dombased-xss", "http-phpself-xss", "qconn-exec", "distcc-cve2004-2687"} {
		if noChange[s] {
			t.Errorf("data change off: %s still runs in the full line (scheduled scans run it)", s)
		}
	}
	if !noChange["http-slowloris-check"] || !noChange["ftp-anon"] || !noChange["ssl-cert"] {
		t.Error("data change off took more than its own scripts")
	}
	if d := dis(GroupDoS); !d["http-slowloris"] || !d["smb-flood"] || d["ssh-brute"] || d["http-sql-injection"] {
		t.Errorf("the disruptive line of denial of service alone: %v", d)
	}
	if d := dis(GroupLogins | GroupChange); d["http-slowloris"] || d["smb-vuln-ms08-067"] || d["rdp-vuln-ms12-020"] || !d["ssh-brute"] || !d["http-sql-injection"] {
		t.Error("denial of service off: a crash or flood check stays in the disruptive line")
	}
	if d := dis(GroupDoS | GroupChange); d["ssh-brute"] || d["mysql-vuln-cve2012-2122"] || !d["http-sql-injection"] {
		t.Error("password guessing off: a login check stays in the disruptive line")
	}
	for s := range dis(GroupDoS | GroupLogins) {
		if s == "http-sql-injection" {
			t.Error("data change off: http-sql-injection stays in the disruptive line")
		}
	}
}

// Ports to skip: the full sweep and the External discovery name them in --exclude-ports, so nmap never sends to them (and -sV and
// the scripts run only on ports the sweep found open). The scripts that connect to ports learned from another service's answer
// (an RPC portmapper, the SQL Server Browser, a UPnP location, Conficker's computed ports) are left out of a line that skips ports.
func TestSkippedPortsAreNeverNamed(t *testing.T) {
	t.Parallel()
	skip := []int{22, 8080}
	for _, tc := range []struct {
		kind Kind
		rate int
		at   string // the flag --exclude-ports follows
	}{{ExternalFull, FullRate, "-p-"}, {ExternalFull, GentleRate, "-p-"}, {External, ExternalRate, "--top-ports"}} {
		args, err := BuildNarrow(tc.kind, tc.rate, nil, Narrow{Groups: AllGroups, SkipPorts: skip}, oneIP)
		if err != nil {
			t.Fatalf("%s at %d: %v", tc.kind.Name(), tc.rate, err)
		}
		i := slices.Index(args, "--exclude-ports")
		at := slices.Index(args, tc.at)
		if i < 0 || args[i+1] != "22,8080" || (tc.at == "-p-" && i != at+1) || (tc.at == "--top-ports" && i != at+2) {
			t.Fatalf("%s: %q", tc.kind.Name(), args)
		}
		if err := Validate(args); err != nil {
			t.Fatalf("%s: Validate refuses what BuildNarrow made: %v", tc.kind.Name(), err)
		}
		k, rate, _, n, targets, err := ParseNarrow(args)
		if err != nil || k != tc.kind || rate != tc.rate || !slices.Equal(n.SkipPorts, skip) || len(targets) != 1 {
			t.Fatalf("%s: ParseNarrow %v %d %+v %v", tc.kind.Name(), k, rate, n, err)
		}
		if tc.kind == ExternalFull {
			set := scriptSet(scriptOf(args))
			for s := range followScripts {
				if set[s] {
					t.Errorf("%s connects to ports learned from another service, but runs in a line that skips ports", s)
				}
			}
			if !set["http-title"] || !set["ssl-cert"] {
				t.Error("skipping ports took more than the scripts that follow learned ports")
			}
		}
	}
	// without ports to skip, the lines are those of before
	for _, s := range []string{"nfs-showmount", "p2p-conficker", "ms-sql-info"} {
		if !scriptSet(FullScripts)[s] {
			t.Errorf("%s left the full line of before", s)
		}
		if _, ok := followScripts[s]; !ok {
			t.Errorf("%s is not listed as following learned ports", s)
		}
	}
	// the disruptive line names its ports itself: a skipped port there is refused, never sent
	if _, err := BuildNarrow(ExternalDisruptive, FullRate, []int{80, 443}, Narrow{Groups: AllGroups, SkipPorts: []int{443}}, oneIP); err == nil {
		t.Error("a disruptive line with ports to skip was built")
	}
	// the External -sV batches leave the skipped ports out of every batch, the fixed lists' too
	batches, err := ExternalBatchesSkipping([]int{22, 80, 443, 8080, 9999, 31337}, skip)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range batches {
		for _, p := range b {
			if slices.Contains(skip, p) {
				t.Fatalf("batch %v names skipped port %d", b, p)
			}
		}
	}
	if flat := slices.Concat(batches...); !slices.Contains(flat, 443) || !slices.Contains(flat, 31337) || !slices.Contains(flat, 9999) {
		t.Fatalf("the batches lost a port that is not skipped: %v", flat)
	}
	if b, _ := ExternalBatchesSkipping([]int{80}, nil); !slices.EqualFunc(b, mustBatches(t, []int{80}), slices.Equal) {
		t.Error("no port to skip changed the batches")
	}
}

func mustBatches(t *testing.T, open []int) [][]int {
	t.Helper()
	b, err := ExternalBatches(open)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Gentle: the full shapes also run at GentleRate. The full sweep then leaves out --version-all (-sV stops at nmap's default
// intensity), which pays for the slower port scan: the worst case still fits FullHostTimeout, so every bound around it holds.
func TestGentleFullShapes(t *testing.T) {
	t.Parallel()
	full, err := BuildNarrow(ExternalFull, GentleRate, nil, Wide(), oneIP)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.Index(full, "--max-rate"); full[i+1] != strconv.Itoa(GentleRate) || slices.Contains(full, "--version-all") {
		t.Fatalf("gentle full line: %q", full)
	}
	if i := slices.Index(full, "--host-timeout"); full[i+1] != fullHostTimeout {
		t.Fatalf("gentle full line's host timeout: %q", full[i+1])
	}
	dis, err := BuildNarrow(ExternalDisruptive, GentleRate, []int{22, 443}, Narrow{Groups: GroupLogins}, oneIP)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.Index(dis, "--max-rate"); dis[i+1] != strconv.Itoa(GentleRate) {
		t.Fatalf("gentle disruptive line: %q", dis)
	}
	for _, a := range [][]string{full, dis} {
		if err := Validate(a); err != nil {
			t.Fatalf("Validate refuses a gentle line: %v", err)
		}
	}
	if GentleRate >= FullRate || GentleRate < 1 {
		t.Fatalf("GentleRate %d is not slower than FullRate %d", GentleRate, FullRate)
	}
	// the arithmetic of FullHostTimeout at GentleRate: every port dropped with two retransmissions, then -sV at the default intensity
	// (30 probes, 156 s of waits for a port that holds them all, 20 ports at a time over commonports' 40 believable ports), then the
	// scripts in parallel, each at most fullScriptTimeout
	sweep := time.Duration(3*65535/GentleRate) * time.Second
	sv := 2 * 156 * time.Second
	scripts, _ := time.ParseDuration(fullScriptTimeout)
	if sweep+sv+scripts > FullHostTimeout {
		t.Fatalf("a gentle full run's worst case %s does not fit FullHostTimeout %s", sweep+sv+scripts, FullHostTimeout)
	}
}

// Validate takes a narrowed line only when it is exactly what BuildNarrow makes of some settings, and fails closed on anything else.
func TestNarrowedLinesValidateAndNothingElse(t *testing.T) {
	t.Parallel()
	for g := Groups(0); g <= AllGroups; g++ {
		for _, rate := range []int{FullRate, GentleRate} {
			for _, skip := range [][]int{nil, {25}, {1, 2, 65535}} {
				n := Narrow{Groups: g, SkipPorts: skip}
				args, err := BuildNarrow(ExternalFull, rate, nil, n, oneIP)
				if err != nil {
					t.Fatal(err)
				}
				if err := Validate(args); err != nil {
					t.Fatalf("groups %d rate %d skip %v: %v", g, rate, skip, err)
				}
				k, r, _, back, _, err := ParseNarrow(args)
				again, _ := BuildNarrow(k, r, nil, back, oneIP)
				if err != nil || !slices.Equal(again, args) {
					t.Fatalf("groups %d rate %d skip %v: ParseNarrow does not give the line back: %+v %v", g, rate, skip, back, err)
				}
				if g != 0 {
					dis, err := BuildNarrow(ExternalDisruptive, rate, []int{21, 445}, Narrow{Groups: g}, oneIP)
					if err != nil || Validate(dis) != nil {
						t.Fatalf("disruptive groups %d rate %d: %v", g, rate, err)
					}
					if _, _, _, back, _, err := ParseNarrow(dis); err != nil || ScriptsOfMust(t, ExternalDisruptive, back) != scriptOf(dis) {
						t.Fatalf("disruptive groups %d: ParseNarrow %+v %v", g, back, err)
					}
				}
			}
		}
	}
	full, _ := BuildNarrow(ExternalFull, FullRate, nil, Narrow{Groups: GroupLogins, SkipPorts: []int{22}}, oneIP)
	si, ei := slices.Index(full, "--script"), slices.Index(full, "--exclude-ports")
	mut := func(f func(a []string) []string) []string { return f(slices.Clone(full)) }
	bad := map[string][]string{
		"a base script dropped":            mut(func(a []string) []string { a[si+1] = strings.Replace(a[si+1], "http-title,", "", 1); return a }),
		"a script of no group added":       mut(func(a []string) []string { a[si+1] += ",http-slowloris"; return a }),
		"learned-port scripts with a skip": mut(func(a []string) []string { a[si+1] = FullScripts; return a }),
		"unsorted ports":                   mut(func(a []string) []string { a[ei+1] = "80,22"; return a }),
		"a repeated port":                  mut(func(a []string) []string { a[ei+1] = "22,22"; return a }),
		"port 0":                           mut(func(a []string) []string { a[ei+1] = "0,22"; return a }),
		"port 65536":                       mut(func(a []string) []string { a[ei+1] = "22,65536"; return a }),
		"a range":                          mut(func(a []string) []string { a[ei+1] = "1-1000"; return a }),
		"an empty list":                    mut(func(a []string) []string { a[ei+1] = ""; return a }),
		"a leading zero":                   mut(func(a []string) []string { a[ei+1] = "022"; return a }),
		"--exclude-ports twice":            mut(func(a []string) []string { return slices.Insert(a, ei, "--exclude-ports", "80") }),
		"--exclude-ports before -p-": mut(func(a []string) []string {
			a = slices.Delete(a, ei, ei+2)
			return slices.Insert(a, slices.Index(a, "-p-"), "--exclude-ports", "22")
		}),
		"another rate":              mut(func(a []string) []string { a[slices.Index(a, "--max-rate")+1] = "200"; return a }),
		"gentle with --version-all": mut(func(a []string) []string { a[slices.Index(a, "--max-rate")+1] = strconv.Itoa(GentleRate); return a }),
		"normal speed without --version": mut(func(a []string) []string {
			return slices.DeleteFunc(a, func(s string) bool { return s == "--version-all" })
		}),
	}
	many := make([]string, MaxSkipPorts+1)
	for i := range many {
		many[i] = strconv.Itoa(i + 1)
	}
	bad["too many ports"] = mut(func(a []string) []string { a[ei+1] = strings.Join(many, ","); return a })
	for name, a := range bad {
		if err := Validate(a); err == nil {
			t.Errorf("%s: Validate accepted %q", name, a)
		}
	}
	// the LAN shapes take no settings
	if _, err := BuildNarrow(Normal, 100, nil, Narrow{Groups: AllGroups, SkipPorts: []int{22}}, addrs(t, "192.168.1.2")); err == nil {
		t.Error("a LAN line skipped ports")
	}
	if _, err := BuildNarrow(ExternalDisruptive, FullRate, []int{80}, Narrow{}, oneIP); err == nil {
		t.Error("a disruptive line with no group allowed was built")
	}
	if _, err := BuildNarrow(External, GentleRate+1, nil, Wide(), oneIP); err == nil {
		t.Error("the External shape took another rate")
	}
	if _, err := BuildNarrow(ExternalFull, FullRate, nil, Narrow{Groups: AllGroups + 1}, oneIP); err == nil {
		t.Error("an unknown group was taken")
	}
}

func ScriptsOfMust(t *testing.T, k Kind, n Narrow) string {
	t.Helper()
	v, err := ScriptsOf(k, n)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The lines of before are unchanged and still validate; a caller that does not know the settings (ParseFor, Parse) refuses a
// narrowed line instead of dropping its narrowing on the way to the worker.
func TestOldShapesStillValidate(t *testing.T) {
	t.Parallel()
	full, err := Build(ExternalFull, FullRate, oneIP)
	if err != nil {
		t.Fatal(err)
	}
	if scriptOf(full) != strings.Join(fullScripts, ",") || !slices.Contains(full, "--version-all") || slices.Contains(full, "--exclude-ports") {
		t.Fatalf("the full line changed: %q", full)
	}
	dis, err := BuildFor(ExternalDisruptive, FullRate, []int{22, 80}, oneIP)
	if err != nil || scriptOf(dis) != DisruptiveScripts {
		t.Fatalf("the disruptive line changed: %q %v", dis, err)
	}
	ext, err := Build(External, ExternalRate, oneIP)
	if err != nil || slices.Contains(ext, "--exclude-ports") {
		t.Fatalf("the External discovery changed: %q %v", ext, err)
	}
	for _, a := range [][]string{full, dis, ext} {
		if err := Validate(a); err != nil {
			t.Fatalf("an old line no longer validates: %v", err)
		}
		if _, _, _, _, err := ParseFor(a); err != nil {
			t.Fatalf("ParseFor refuses an old line: %v", err)
		}
		if _, _, _, n, _, err := ParseNarrow(a); err != nil || n.Groups != AllGroups || len(n.SkipPorts) != 0 {
			t.Fatalf("an old line parses as narrowed: %+v %v", n, err)
		}
	}
	for name, n := range map[string]Narrow{"a group off": {Groups: GroupLogins | GroupChange}, "a port skipped": {Groups: AllGroups, SkipPorts: []int{22}}} {
		a, err := BuildNarrow(ExternalFull, FullRate, nil, n, oneIP)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := ParseFor(a); err == nil {
			t.Errorf("%s: ParseFor took a narrowed line and would drop its narrowing", name)
		}
		if _, _, _, err := Parse(a); err == nil {
			t.Errorf("%s: Parse took a narrowed line", name)
		}
	}
	// gentle is the job's own rate: ParseFor gives it back, and a worker that does not know it refuses the rate
	gentle, _ := BuildNarrow(ExternalFull, GentleRate, nil, Wide(), oneIP)
	if _, rate, _, _, err := ParseFor(gentle); err != nil || rate != GentleRate {
		t.Errorf("ParseFor of a gentle full line: rate %d, %v", rate, err)
	}
}
