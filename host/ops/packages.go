package ops

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// GET /v1/state/packages (D-470, INV-9): the box's own package list for the inventory. One fixed dpkg-query, no shell, no
// argument from the request; the structure is parsed fail-closed: a line without exactly 5 fields, a status dpkg does not
// have, too many lines, no installed package, a cut output or a failed exit and the whole read fails (core keeps what it
// had). An installed package whose own fields break dpkg's rules is left out, counted and logged (parsePackages). A
// package half-way through an install or removal (apt running, or an interrupted run) makes the list no snapshot of the
// box: 409 packages_changing, which core reads as "keep the list, read again next time".

// argsDpkgQueryList is the one dpkg-query of the package list: tab-separated name, version, architecture, source
// package and status, one package per line (dpkg-query reads the \t and \n escapes of the format itself).
var argsDpkgQueryList = []string{"-W", `-f=${Package}\t${Version}\t${Architecture}\t${source:Package}\t${db:Status-Status}\n`}

// maxPackagesOutput bounds dpkg-query's output: MaxPackages lines of at most about 400 bytes.
const maxPackagesOutput = 8 << 20

var (
	// debPkgNameRE is Debian policy 5.6.1 (dpkg enforces it): lower case, digits, + - ., at least two characters,
	// starting alphanumeric ("g++" ends with "+", so this is not apt's pkgNameRE).
	debPkgNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}$`)
	// debVersionRE is a Debian version as dpkg stores it: [epoch:]upstream[-revision] in its own characters.
	debVersionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:-]{0,127}$`)
	debArchRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// dpkgStatuses are the values of ${db:Status-Status} (dpkg-query(1), dpkg's lib/dpkg/pkg-namevalue.c); onDisk are the
// ones whose files are installed (a package waiting on triggers is fully unpacked and configured); changing are the
// states dpkg leaves a package in while it unpacks, configures or removes it.
var (
	dpkgStatuses = []string{"not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed"}
	onDisk       = []string{"installed", "triggers-awaited", "triggers-pending"}
	changing     = []string{"half-installed", "unpacked", "half-configured"}
)

// errPackagesChanging is parsePackages' answer when a package is half-way through dpkg: the list is no reliable picture of
// the box, so it is not sent at all (core keeps the last good one).
var errPackagesChanging = errors.New("dpkg is installing or removing packages")

func (o *Ops) readPackages(ctx context.Context) (any, error) {
	res, code, err := o.exec(ctx, binDpkgQuery, argsDpkgQueryList...)
	switch {
	case err != nil:
		return nil, fmt.Errorf("dpkg-query: %w", err)
	case code != 0:
		return nil, fmt.Errorf("dpkg-query exited %d", code)
	case res.Truncated:
		return nil, errors.New("dpkg-query printed more than the bound")
	}
	list, dropped, err := parsePackages(res.Stdout)
	if errors.Is(err, errPackagesChanging) {
		return nil, server.NewReadError(http.StatusConflict, api.CodePackagesChanging, "dpkg is installing or removing packages; read the list again later.")
	}
	if err != nil {
		return nil, err
	}
	if dropped > 0 {
		o.log.WarnContext(ctx, "packages: installed packages with a name, version or architecture outside dpkg's rules were left out", "dropped", dropped, "listed", len(list))
	}
	return api.PackagesState{Packages: list}, nil
}

// parsePackages reads argsDpkgQueryList's output. The structure fails closed (a line without exactly 5 fields, an unknown
// status, no installed package, too many): then it returns no list at all. A package in a changing state gives
// errPackagesChanging (after the structure of every line has been checked). One installed package whose name, version,
// architecture or source does not pass dpkg's rules (an old third-party package, a very long version) is left out and
// counted in dropped, so it cannot hide the rest of the box; its text is never used.
func parsePackages(out []byte) (list []api.Package, dropped int, err error) {
	list = []api.Package{}
	inFlux := false
	lines := bytes.Split(out, []byte("\n"))
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	if len(lines) > api.MaxPackages*2 { // installed or not: dpkg's database itself is bounded too
		return nil, 0, errors.New("dpkg-query listed too many packages")
	}
	for i, l := range lines {
		f := bytes.Split(l, []byte("\t"))
		if len(f) != 5 {
			return nil, 0, fmt.Errorf("dpkg-query line %d has %d fields", i+1, len(f))
		}
		name, version, arch, source, status := string(f[0]), string(f[1]), string(f[2]), string(f[3]), string(f[4])
		if !slices.Contains(dpkgStatuses, status) {
			return nil, 0, fmt.Errorf("dpkg-query line %d has an unknown status", i+1)
		}
		if slices.Contains(changing, status) {
			inFlux = true
		}
		if !slices.Contains(onDisk, status) {
			continue
		}
		if !debPkgNameRE.MatchString(name) || !debVersionRE.MatchString(version) || !debArchRE.MatchString(arch) ||
			(source != "" && !debPkgNameRE.MatchString(source)) {
			dropped++
			continue
		}
		list = append(list, api.Package{Name: name, Version: version, Arch: arch, Source: source})
	}
	switch {
	case inFlux:
		return nil, 0, errPackagesChanging
	case len(list) == 0:
		return nil, 0, errors.New("dpkg-query listed no installed package")
	case len(list) > api.MaxPackages:
		return nil, 0, errors.New("dpkg-query listed too many packages")
	}
	slices.SortFunc(list, func(a, b api.Package) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Arch, b.Arch)) })
	return list, dropped, nil
}
