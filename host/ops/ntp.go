package ops

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/knt048/vedette/host/api"
)

// NTP (D-106). Vedette owns chrony's sources: the host writes only vedette.sources in the
// directory chrony.conf names with "sourcedir" (the installer sets that up and leaves no distro
// pool), asks chrony to reload them, and checks with "chronyc -N -c sources" that they are there.
// Changing NTP never waits for confirmation (D-100 (5)): it is not what the admin reaches the box by.

const (
	chronyDir         = "etc/chrony/sources.d"
	chronySourcesName = "vedette.sources"
	ntpHeader         = "# Written by vedette-host. Do not edit: the host rewrites this file.\n"
	defaultNTPPool    = "pool.ntp.org"
	maxSourcesFile    = 8 << 10
)

// validNTPServer: an IPv4 unicast address (through netip, never a string) or a name by the
// repository name regex. A name made only of digits and dots is refused: it would be an address
// that failed to parse, not a name (and chrony would send it to the resolver).
func validNTPServer(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Is4() && unicast4(a)
	}
	if !dnsNameRE.MatchString(s) {
		return false
	}
	return strings.Trim(s, "0123456789.") != ""
}

// checkNTPList validates the NTP argument of net.apply: at most four distinct servers.
func checkNTPList(ntp []string) error {
	if len(ntp) > api.MaxNTPServers {
		return bad("ntp", "holds at most 4 servers")
	}
	seen := map[string]bool{}
	for _, s := range ntp {
		if !validNTPServer(s) {
			return bad("ntp", "must be IPv4 addresses or names made of letters, digits, '.', '_' and '-'")
		}
		k := strings.ToLower(s)
		if seen[k] {
			return bad("ntp", "lists a server twice")
		}
		seen[k] = true
	}
	return nil
}

// renderSources is the text of vedette.sources for validated servers: the default pool when none.
func renderSources(servers []string) []byte {
	var b bytes.Buffer
	b.WriteString(ntpHeader)
	if len(servers) == 0 {
		b.WriteString("pool " + defaultNTPPool + " iburst\n")
	}
	for _, s := range servers {
		b.WriteString("server " + s + " iburst\n")
	}
	return b.Bytes()
}

// parseSources reads back a file the host wrote: only the exact bytes renderSources gives.
func parseSources(b []byte) ([]string, bool) {
	if len(b) > maxSourcesFile {
		return nil, false
	}
	var servers []string
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if name, ok := strings.CutPrefix(line, "server "); ok {
			if name, ok = strings.CutSuffix(name, " iburst"); ok {
				servers = append(servers, name)
			}
		}
	}
	if len(servers) > api.MaxNTPServers || checkNTPList(servers) != nil || !bytes.Equal(renderSources(servers), b) {
		return nil, false
	}
	return servers, true
}

// readNTP is the servers vedette.sources holds, [] for the default pool or a file that is not the host's.
func (o *Ops) readNTP() []string {
	b, st := o.readNoFollowIn(chronyDir, chronySourcesName, maxSourcesFile)
	if st != fileOK {
		return []string{}
	}
	servers, ok := parseSources(b)
	if !ok || servers == nil {
		return []string{}
	}
	return servers
}

// ntpUnchanged reports whether vedette.sources already holds what servers asks for.
func (o *Ops) ntpUnchanged(servers []string) bool {
	b, st := o.readNoFollowIn(chronyDir, chronySourcesName, maxSourcesFile)
	return st == fileOK && bytes.Equal(b, renderSources(servers))
}

var errNTPNotApplied = errors.New("chrony does not list the sources")

// applyNTP writes vedette.sources, reloads chrony and checks the effect. When any step fails the
// previous file is put back (or removed when there was none) and chrony reloaded again; the error
// is then errNTPNotApplied or the write error.
func (o *Ops) applyNTP(ctx context.Context, servers []string) error {
	old, st := o.readNoFollowIn(chronyDir, chronySourcesName, maxSourcesFile)
	if st == fileBroken {
		return errors.New("ops: vedette.sources is not a plain file")
	}
	if err := o.writeIn(chronyDir, chronySourcesName, renderSources(servers), 0o644); err != nil {
		return err
	}
	err := o.reloadAndCheckNTP(ctx, servers)
	if err == nil {
		return nil
	}
	if st == fileOK {
		_ = o.writeIn(chronyDir, chronySourcesName, old, 0o644)
	} else {
		_ = o.removeIn(chronyDir, chronySourcesName)
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), netStepTimeout)
	defer cancel()
	_, _, _ = o.exec(rctx, binChronyc, "reload", "sources")
	return err
}

func (o *Ops) reloadAndCheckNTP(ctx context.Context, servers []string) error {
	if _, code, err := o.exec(ctx, binChronyc, "reload", "sources"); err != nil || code != 0 {
		return errNTPNotApplied
	}
	return o.waitFor(ctx, func() bool { return o.ntpListed(ctx, servers) }, errNTPNotApplied)
}

// ntpListed runs "chronyc -N -c sources" and reports whether every configured server is listed
// (for the default pool: whether any source is, since the pool's members have names of their own).
func (o *Ops) ntpListed(ctx context.Context, servers []string) bool {
	res, code, err := o.exec(ctx, binChronyc, chronycSources...)
	if err != nil || code != 0 {
		return false
	}
	return sourcesListed(res.Stdout, servers)
}

func sourcesListed(out []byte, servers []string) bool {
	names := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(strings.TrimSpace(line), ",")
		if len(f) >= 3 && (f[0] == "^" || f[0] == "=") {
			names[strings.ToLower(f[2])] = true
		}
	}
	if len(servers) == 0 {
		return len(names) > 0
	}
	for _, s := range servers {
		if !names[strings.ToLower(s)] {
			return false
		}
	}
	return true
}
