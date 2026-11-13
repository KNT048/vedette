package api

// GET /v1/state/packages (docs/specs/host-api.md section 5, D-470): the Debian packages installed on the box, read with
// one fixed dpkg-query. Read-only, no lock, no audit line, like the other state reads. A host older than D-470 answers
// 404 unknown_command; core then reports no packages for the box (the device page says so).

// Package is one installed package as dpkg lists it. Version is the full Debian version (epoch and revision kept);
// Source is the source package (dpkg prints the package's own name when it has no Source field).
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Source  string `json:"source"`
}

// PackagesState is the body of GET /v1/state/packages: the packages whose files are on the box (dpkg status installed,
// triggers-awaiting or triggers-pending), sorted by name and architecture. Never empty: a dpkg-query that lists no
// installed package is an error, so core never empties the box's list on a bad read.
type PackagesState struct {
	Packages []Package `json:"packages"`
}

// MaxPackages bounds the list: a longer one is refused (500), not cut, so core never stores half a box.
const MaxPackages = 20000
