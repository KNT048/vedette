package nmapargv

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// The deep-scan settings of a target narrow the external shapes; they never widen one. A shape built with every group allowed, no
// port to skip and at FullRate is exactly the shape of before (Wide), so a worker that does not know the settings runs only those,
// and refuses a narrowed or gentle line (its Validate does not know it): fail closed.
//
//   - Groups: each group of checks off leaves its scripts out of the --script value of ExternalFull and ExternalDisruptive (the
//     value is the base and the allowed groups' scripts, sorted; scripts.go says which script is in which group). Scheduled scans
//     run ExternalFull, so a group off removes its scripts there too.
//   - SkipPorts: ExternalFull and External's discovery name them in --exclude-ports, so nmap sends nothing to them, and ExternalFull
//     then also leaves out followScripts (they reach ports learned from another service). ExternalDisruptive and the External -sV
//     batches name their own ports (-p): the caller leaves the skipped ones out (ExternalBatchesSkipping), and a disruptive line
//     with ports to skip is refused.
//   - Gentle is the job's rate: the two full shapes also run at GentleRate, where ExternalFull drops --version-all (see GentleRate).

// Groups is a set of the groups of checks a target's deep-scan settings can turn off.
type Groups uint8

// The groups.
const (
	GroupDoS    Groups = 1 << iota // denial of service: checks that can exhaust or crash a service
	GroupLogins                    // password guessing and default logins
	GroupChange                    // exploit checks that may change data
	// AllGroups is every group: the shapes of before.
	AllGroups = GroupDoS | GroupLogins | GroupChange
)

// MaxSkipPorts is the most ports a target's settings skip (exposure's own limit).
const MaxSkipPorts = 64

// GentleRate is the --max-rate of the full shapes at the gentle speed: a third of FullRate. The port scan of ExternalFull then takes
// up to 33 minutes when every port is dropped (3 × 65535 probes, see the arithmetic above FullRate); the gentle line leaves out
// --version-all, so -sV tries nmap's default 30 probes on a port it cannot name instead of 104 (at most about 5 minutes for 40 such
// ports, 20 at a time, instead of 18), and the worst case with the scripts (each at most fullScriptTimeout) stays inside
// FullHostTimeout: every bound around the step holds unchanged. ExternalDisruptive names at most commonports.MaxBelievableOpen ports,
// so its port scan is short at either rate and its host timeout is the same. -sV and the scripts time themselves: the rate slows
// the port scan only.
const GentleRate = 100

// flagExcludePorts names ports nmap never scans (nmap 7.00 and later), with -p- and with --top-ports alike.
const flagExcludePorts = "--exclude-ports"

// Narrow is how a target's deep-scan settings narrow a shape: the groups allowed and the ports to skip (ascending, distinct,
// 1..65535, at most MaxSkipPorts).
type Narrow struct {
	Groups    Groups
	SkipPorts []int
}

// Wide is no narrowing: every group, no port skipped.
func Wide() Narrow { return Narrow{Groups: AllGroups} }

// wide says n narrows nothing.
func (n Narrow) wide() bool { return n.Groups == AllGroups && len(n.SkipPorts) == 0 }

// ScriptsOf is the --script value of a full shape under n: the shape's base and the scripts of the groups n allows, sorted, without
// followScripts when n skips ports. A disruptive line with nothing left is an error: the step does not run.
func ScriptsOf(kind Kind, n Narrow) (string, error) {
	if n.Groups&^AllGroups != 0 {
		return "", fmt.Errorf("nmapargv: unknown groups %d", n.Groups)
	}
	var list []string
	switch kind {
	case ExternalFull:
		list = fullScripts
	case ExternalDisruptive:
		list = disruptiveExtra
	default:
		return "", fmt.Errorf("nmapargv: the %s shape has no script groups", kind.Name())
	}
	var out []string
	for _, s := range list {
		if g := GroupOf(s); g != 0 && n.Groups&g == 0 {
			continue
		}
		if _, follows := followScripts[s]; follows && len(n.SkipPorts) > 0 {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("nmapargv: the settings leave no script of the %s shape", kind.Name())
	}
	slices.Sort(out)
	return strings.Join(out, ","), nil
}

// skipList checks the ports to skip and writes them as an --exclude-ports value ("" for none).
func skipList(ports []int) (string, error) {
	if len(ports) == 0 {
		return "", nil
	}
	if len(ports) > MaxSkipPorts {
		return "", fmt.Errorf("nmapargv: at most %d ports to skip, got %d", MaxSkipPorts, len(ports))
	}
	return portList(ports)
}

// FlagsNarrow is FlagsFor of a shape narrowed by a target's deep-scan settings: ExternalFull and ExternalDisruptive take the groups,
// ExternalFull and External's discovery the ports to skip; every other shape takes none (a LAN line skipping ports is an error).
// Wide() gives FlagsFor's line exactly.
func FlagsNarrow(kind Kind, rate int, ports []int, n Narrow) ([]string, error) {
	if n.Groups&^AllGroups != 0 {
		return nil, fmt.Errorf("nmapargv: unknown groups %d", n.Groups)
	}
	skip, err := skipList(n.SkipPorts)
	if err != nil {
		return nil, err
	}
	switch kind {
	case ExternalFull:
		if len(ports) != 0 {
			return nil, fmt.Errorf("nmapargv: the %s shape takes no port list", kind.Name())
		}
		return fullFlags(rate, n, skip)
	case ExternalDisruptive:
		if skip != "" {
			return nil, fmt.Errorf("nmapargv: the %s shape names its ports itself: leave the skipped ones out of them", kind.Name())
		}
		return disruptiveFlags(rate, ports, n)
	case External:
		f, err := FlagsFor(kind, rate, ports)
		if err != nil || skip == "" {
			return f, err
		}
		return append(f, flagExcludePorts, skip), nil
	}
	if skip != "" {
		return nil, fmt.Errorf("nmapargv: the %s shape takes no ports to skip", kind.Name())
	}
	return FlagsFor(kind, rate, ports)
}

// BuildNarrow is BuildFor of a shape narrowed by a target's deep-scan settings (FlagsNarrow).
func BuildNarrow(kind Kind, rate int, ports []int, n Narrow, targets []netip.Addr) ([]string, error) {
	if kind == PortVersions && len(targets) != 1 {
		return nil, fmt.Errorf("nmapargv: a port_versions run takes exactly one target, got %d", len(targets))
	}
	valid, err := targetRule(kind, len(targets))
	if err != nil {
		return nil, err
	}
	args, err := FlagsNarrow(kind, rate, ports, n)
	if err != nil {
		return nil, err
	}
	args = append(args, flagStats, StatsEvery, flagXML, "-")
	for _, t := range targets {
		if !valid(t) {
			return nil, fmt.Errorf("nmapargv: target %q is not allowed in the %s shape", t, kind.Name())
		}
		args = append(args, t.String())
	}
	return args, nil
}

// ParseNarrow is ParseFor with the deep-scan settings the line was built with. For ExternalFull the groups are the widest ones
// that give the same line (password guessing has no script there, so it reads as allowed); building again from what it returns
// gives the same line.
func ParseNarrow(args []string) (Kind, int, []int, Narrow, []netip.Addr, error) {
	if err := Validate(args); err != nil {
		return 0, 0, nil, Narrow{}, nil, err
	}
	i := slices.Index(args, flagXML)
	k, rate, ports, n, ok := shapeOf(args[:i-2])
	if !ok {
		return 0, 0, nil, Narrow{}, nil, errors.New("nmapargv: argv matches no shape") // unreachable after Validate
	}
	targets := make([]netip.Addr, 0, len(args)-i-2)
	for _, t := range args[i+2:] {
		targets = append(targets, netip.MustParseAddr(t)) // Validate proved each is canonical
	}
	return k, rate, ports, n, targets, nil
}

// excludeOf reads the --exclude-ports of flags: nil when there is none; false when it is there twice, last, or not a list of plain
// decimal ports (whether it is ascending and in range is the rebuild's to say).
func excludeOf(flags []string) ([]int, bool) {
	i := slices.Index(flags, flagExcludePorts)
	if i < 0 {
		return nil, true
	}
	if i+1 >= len(flags) || slices.Contains(flags[i+1:], flagExcludePorts) || len(flags[i+1]) > 6*MaxSkipPorts {
		return nil, false
	}
	var out []int
	for _, f := range strings.Split(flags[i+1], ",") {
		n, ok := atoi5(f)
		if !ok {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// narrowsOf are the settings shapeOf tries for a kind with the ports to skip read from the line: the groups from the widest down
// for ExternalFull, every group for the others.
func narrowsOf(kind Kind, skip []int) []Narrow {
	if kind != ExternalFull {
		return []Narrow{{Groups: AllGroups, SkipPorts: skip}}
	}
	out := make([]Narrow, 0, AllGroups+1)
	for g := AllGroups; ; g-- {
		out = append(out, Narrow{Groups: g, SkipPorts: skip})
		if g == 0 {
			return out
		}
	}
}

// ExternalBatchesSkipping is ExternalBatches with the ports a target's settings skip left out of every batch, the fixed lists' too.
func ExternalBatchesSkipping(open, skip []int) ([][]int, error) {
	if len(skip) > MaxSkipPorts {
		return nil, fmt.Errorf("nmapargv: at most %d ports to skip, got %d", MaxSkipPorts, len(skip))
	}
	for _, p := range skip {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("nmapargv: port %d is outside 1..65535", p)
		}
	}
	return externalBatches(open, func(p int) bool { return !slices.Contains(skip, p) })
}

// groupNames are the groups as the sensor link names them.
var groupNames = []struct {
	g    Groups
	name string
}{{GroupDoS, "dos"}, {GroupLogins, "logins"}, {GroupChange, "change"}}

// Names are the groups of g as the sensor link names them, in a fixed order; never nil (no group is an empty list).
func (g Groups) Names() []string {
	out := []string{}
	for _, n := range groupNames {
		if g&n.g != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// GroupsOf reads groups named as Names writes them; an unknown or repeated name is an error.
func GroupsOf(names []string) (Groups, error) {
	var g Groups
	for _, s := range names {
		var one Groups
		for _, n := range groupNames {
			if n.name == s {
				one = n.g
			}
		}
		if one == 0 || g&one != 0 {
			return 0, fmt.Errorf("nmapargv: group %.20q is unknown or repeated", s)
		}
		g |= one
	}
	return g, nil
}
