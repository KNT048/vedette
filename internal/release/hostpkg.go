package release

import "regexp"

// hostPackageRE is the one file-name rule of a host package (host-api 6.14, D-316): the release asset, host.files[].name, the
// package install.sh keeps and the host's kept copies. The version is in SemVer form (never Debian's "~"), with a
// prerelease that has no "-" inside and no build metadata, so that the Debian version is the SemVer one with its first "-"
// turned into "~" (D-155 (1)) and nothing is ambiguous. install.sh host_version_ok is the same rule in sh.
var hostPackageRE = regexp.MustCompile(`^vedette-host_((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.]{1,32})?)_(amd64|arm64)\.deb$`)

// HostPackageName is vedette-host_<version>_<arch>.deb.
func HostPackageName(version, arch string) string {
	return "vedette-host_" + version + "_" + arch + ".deb"
}

// ParseHostPackageName is the validator of that name: its version and architecture, or false.
func ParseHostPackageName(name string) (version, arch string, ok bool) {
	m := hostPackageRE.FindStringSubmatch(name)
	if m == nil || !validVersion(m[1]) {
		return "", "", false
	}
	return m[1], m[6], true
}
