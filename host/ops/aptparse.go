package ops

import (
	"bufio"
	"bytes"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// The parsers in this file read the output of apt. That output is data: a mirror, a package
// description or a hostile repository influences it, so every field is checked against a strict
// pattern before it is kept, sizes are bounded, and anything odd is skipped, never guessed.

const (
	maxSimLine     = 4 << 10
	maxUpgrades    = 5000
	maxOrigins     = 8
	maxMirrors     = 20
	maxConfigLines = 20000
)

var (
	versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)
	originRE  = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,40}:[A-Za-z0-9._+-]{0,40}/[A-Za-z0-9._+-]{1,60}$`)
	hostRE    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
)

// Upgrade is one package a simulated upgrade would replace by a newer version.
type Upgrade struct {
	Name     string
	From     string
	To       string
	Origin   string // the security origin when there is one, else the first
	Security bool   // some origin of the new version is a *-security suite
}

// Simulation is what ParseSimulation understood of "apt-get -s dist-upgrade".
type Simulation struct {
	Upgrades  []Upgrade // packages already installed, sorted by name
	NewDeps   int       // packages that would be newly installed (dependencies)
	Removals  int       // packages that would be removed (an install never does this: --no-remove)
	Truncated bool      // more than maxUpgrades lines: the rest was ignored
}

// ParseSimulation reads the "Inst" and "Remv" lines of a simulated upgrade:
//
//	Inst libc6 [2.39-0ubuntu8.2] (2.39-0ubuntu8.3 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
//
// An upgrade has the installed version in the first brackets; a package without them is a new
// dependency. A line that does not parse is skipped. It never fails and never panics.
func ParseSimulation(out []byte) Simulation {
	var sim Simulation
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), maxSimLine)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Remv "):
			sim.Removals++
		case strings.HasPrefix(line, "Inst "):
			u, upgrade, ok := parseInst(strings.TrimPrefix(line, "Inst "))
			switch {
			case !ok:
			case !upgrade:
				sim.NewDeps++
			case len(sim.Upgrades) >= maxUpgrades:
				sim.Truncated = true
			default:
				sim.Upgrades = append(sim.Upgrades, u)
			}
		}
	}
	// A line longer than maxSimLine stops the scanner: what was read so far is kept, and the
	// caller learns that the tail is missing.
	if sc.Err() != nil {
		sim.Truncated = true
	}
	slices.SortFunc(sim.Upgrades, func(a, b Upgrade) int { return strings.Compare(a.Name, b.Name) })
	sim.Upgrades = slices.CompactFunc(sim.Upgrades, func(a, b Upgrade) bool { return a.Name == b.Name })
	return sim
}

func parseInst(s string) (u Upgrade, upgrade, ok bool) {
	name, rest, found := strings.Cut(s, " ")
	if !found || !pkgNameRE.MatchString(name) {
		return u, false, false
	}
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return u, false, false
		}
		u.From = rest[1:end]
		upgrade = true
		rest = strings.TrimPrefix(rest[end+1:], " ")
		if !versionRE.MatchString(u.From) {
			return u, false, false
		}
	}
	if !strings.HasPrefix(rest, "(") {
		return u, false, false
	}
	closing := strings.LastIndexByte(rest, ')')
	if closing < 0 {
		return u, false, false
	}
	// "(to origin, origin [arch])" possibly followed by " []" or " [reasons]" after the parenthesis.
	inner := stripTrailingBrackets(rest[1:closing])
	to, origins, _ := strings.Cut(inner, " ")
	if !versionRE.MatchString(to) {
		return u, false, false
	}
	u.Name, u.To = name, to
	seen := 0
	for _, o := range strings.Split(origins, ", ") {
		o = strings.TrimSpace(o)
		if !originRE.MatchString(o) {
			continue
		}
		if isSecurityOrigin(o) {
			u.Security = true
			if !isSecurityOrigin(u.Origin) {
				u.Origin = o
			}
		}
		if u.Origin == "" {
			u.Origin = o
		}
		if seen++; seen >= maxOrigins {
			break
		}
	}
	return u, upgrade, true
}

// stripTrailingBrackets removes trailing " [arch]" groups and spaces. It works from the end, so a
// line made of thousands of brackets costs linear time (a regexp loop here was quadratic).
func stripTrailingBrackets(s string) string {
	for {
		s = strings.TrimRight(s, " \t")
		if !strings.HasSuffix(s, "]") {
			return s
		}
		i := strings.LastIndexByte(s, '[')
		if i < 0 {
			return s
		}
		s = s[:i]
	}
}

// isSecurityOrigin is true for "Label:version/suite" whose suite ends in "-security"
// (noble-security, stable-security, trixie-security, noble-apps-security of Ubuntu ESM).
func isSecurityOrigin(o string) bool {
	i := strings.LastIndexByte(o, '/')
	return i >= 0 && strings.HasSuffix(o[i+1:], "-security")
}

var updateLineRE = regexp.MustCompile(`^(?:Get|Hit|Ign|Err):\d+ (\S+)`)

// ParseUpdateHosts lists the mirror host names that "apt-get update" printed
// ("Get:1 http://archive.ubuntu.com/ubuntu noble InRelease [126 kB]"), sorted, at most maxMirrors.
func ParseUpdateHosts(out []byte) []string {
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), maxSimLine)
	for sc.Scan() {
		m := updateLineRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		u, err := url.Parse(m[1])
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if h := strings.ToLower(u.Hostname()); hostRE.MatchString(h) {
			seen[h] = true
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	if len(hosts) > maxMirrors {
		hosts = hosts[:maxMirrors]
	}
	return hosts
}

// AutoConfig is what "apt-config dump" says about unattended security updates.
type AutoConfig struct {
	Periodic       string   // APT::Periodic::Unattended-Upgrade ("" when absent)
	AllowedOrigins []string // Unattended-Upgrade::Allowed-Origins entries
	OriginsPattern []string // Unattended-Upgrade::Origins-Pattern entries
}

var configLineRE = regexp.MustCompile(`^([A-Za-z0-9:_.-]+)\s+"((?:[^"\\]|\\.)*)";$`)

// ParseAptConfig reads the lines of "apt-config dump" it needs. Everything else is ignored.
func ParseAptConfig(out []byte) AutoConfig {
	var c AutoConfig
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), maxSimLine)
	for n := 0; sc.Scan() && n < maxConfigLines; n++ {
		m := configLineRE.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		val := m[2]
		if len(val) > 300 {
			continue
		}
		switch m[1] {
		case "APT::Periodic::Unattended-Upgrade":
			c.Periodic = val
		case "Unattended-Upgrade::Allowed-Origins::":
			c.AllowedOrigins = append(c.AllowedOrigins, val)
		case "Unattended-Upgrade::Origins-Pattern::":
			c.OriginsPattern = append(c.OriginsPattern, val)
		}
	}
	return c
}

// Enabled reports whether unattended upgrades are on (the periodic switch is a positive number).
func (c AutoConfig) Enabled() bool { return c.Periodic != "" && c.Periodic != "0" }

// SecurityOnly reports whether every allowed origin names a security pocket and there is at least one.
func (c AutoConfig) SecurityOnly() bool {
	all := slices.Concat(c.AllowedOrigins, c.OriginsPattern)
	if len(all) == 0 {
		return false
	}
	for _, o := range all {
		if !strings.Contains(strings.ToLower(o), "security") {
			return false
		}
	}
	return true
}

// parseRebootPkgs reads /var/run/reboot-required.pkgs: package names, one per line.
func parseRebootPkgs(data []byte) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if pkgNameRE.MatchString(line) {
			seen[line] = true
		}
		if len(seen) >= 50 {
			break
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}
