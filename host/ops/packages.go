package ops

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/knt048/vedette/host/api"
)

// GET /v1/state/packages (D-470, INV-9): the box's own package list for the inventory. One fixed dpkg-query, no shell, no
// argument from the request; the output is parsed fail-closed: one line that is not a package, a status dpkg does not
// have, too many lines or a cut output and the whole read fails (core keeps what it had).

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

// dpkgStatuses are the values of ${db:Status-Status}; onDisk are the ones whose files are installed.
var (
	dpkgStatuses = []string{"not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaiting", "triggers-pending", "installed"}
	onDisk       = []string{"installed", "triggers-awaiting", "triggers-pending"}
)

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
	list, err := parsePackages(res.Stdout)
	if err != nil {
		return nil, err
	}
	return api.PackagesState{Packages: list}, nil
}

// parsePackages reads argsDpkgQueryList's output. It never returns a partial list.
func parsePackages(out []byte) ([]api.Package, error) {
	list := []api.Package{}
	lines := bytes.Split(out, []byte("\n"))
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	if len(lines) > api.MaxPackages*2 { // installed or not: dpkg's database itself is bounded too
		return nil, errors.New("dpkg-query listed too many packages")
	}
	for i, l := range lines {
		f := bytes.Split(l, []byte("\t"))
		if len(f) != 5 {
			return nil, fmt.Errorf("dpkg-query line %d has %d fields", i+1, len(f))
		}
		name, version, arch, source, status := string(f[0]), string(f[1]), string(f[2]), string(f[3]), string(f[4])
		if !slices.Contains(dpkgStatuses, status) {
			return nil, fmt.Errorf("dpkg-query line %d has an unknown status", i+1)
		}
		if !slices.Contains(onDisk, status) {
			continue
		}
		if !debPkgNameRE.MatchString(name) || !debVersionRE.MatchString(version) || !debArchRE.MatchString(arch) ||
			(source != "" && !debPkgNameRE.MatchString(source)) {
			return nil, fmt.Errorf("dpkg-query line %d is not a package", i+1)
		}
		list = append(list, api.Package{Name: name, Version: version, Arch: arch, Source: source})
	}
	switch {
	case len(list) == 0:
		return nil, errors.New("dpkg-query listed no installed package")
	case len(list) > api.MaxPackages:
		return nil, errors.New("dpkg-query listed too many packages")
	}
	slices.SortFunc(list, func(a, b api.Package) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Arch, b.Arch)) })
	return list, nil
}
