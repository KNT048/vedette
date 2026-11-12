package opstest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/knt048/vedette/host/api"
)

// The fake world of host.self_update (D-316, plan slice 2): the kept package of the running version,
// core's downloaded file, a manifest with a host part, and the answers of dpkg-query, dpkg-deb,
// systemctl is-active and the simulated apt install. Slice 2a covers Check and Run up to the park; the
// applier, the fake systemd-run and the restart markers come with slice 2b.

// HostPackage is the bytes of a fake vedette-host .deb of version (only its hash matters to the host).
func HostPackage(version string) []byte { return []byte("!<arch>\nvedette-host " + version + "\n") }

// SHA is the lowercase hex SHA-256 of b.
func SHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// KeepPackage writes <state>/selfupdate/packages/vedette-host_<version>_amd64.deb (0600), as install.sh does.
func (m *Machine) KeepPackage(version string, content []byte) string {
	m.t.Helper()
	dir := filepath.Join(m.State, "selfupdate", "packages")
	m.must(os.MkdirAll(dir, 0o700))
	p := filepath.Join(dir, "vedette-host_"+version+"_amd64.deb")
	m.must(os.WriteFile(p, content, 0o600))
	return p
}

// CorePackage writes core's download <core_data>/host-packages/<id>.deb (0600, core's owner) and returns the id.
func (m *Machine) CorePackage(content []byte) string {
	m.t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	m.must(err)
	id := hex.EncodeToString(b)
	dir := filepath.Join(m.CoreData, "host-packages")
	m.must(os.MkdirAll(dir, 0o700))
	m.must(os.WriteFile(filepath.Join(dir, id+".deb"), content, 0o600))
	return id
}

// CorePackagePath is the path of core's download.
func (m *Machine) CorePackagePath(id string) string {
	return filepath.Join(m.CoreData, "host-packages", id+".deb")
}

// HostInstalled makes dpkg-query say vedette-host <version> (SemVer; printed in the Debian form) has status.
func (m *Machine) HostInstalled(version, status string) {
	m.RuleText("dpkg-query", "vedette-host", strings.Replace(version, "-", "~", 1)+"|"+status, 0, "", "")
}

// DebFields makes dpkg-deb --field print the three fields of the staged file.
func (m *Machine) DebFields(pkg, debVersion, arch string) {
	m.RuleText("dpkg-deb", "/selfupdate/staged/", "Package: "+pkg+"\nVersion: "+debVersion+"\nArchitecture: "+arch+"\n", 0, "", "")
}

// KeptDebFields makes dpkg-deb --field of the kept package of version (SemVer) print its true fields.
func (m *Machine) KeptDebFields(version string) {
	m.RuleText("dpkg-deb", "/packages/vedette-host_"+version+"_amd64.deb",
		"Package: vedette-host\nVersion: "+strings.Replace(version, "-", "~", 1)+"\nArchitecture: amd64\n", 0, "", "")
}

// ApplierUnit makes systemctl is-active vedette-host-upgrade.service print state (exit 0 for active, 3 otherwise).
func (m *Machine) ApplierUnit(state string) {
	code := 3
	if state == "active" || state == "activating" {
		code = 0
	}
	m.RuleText("systemctl", "is-active vedette-host-upgrade.service", state+"\n", code, "", "")
}

// SimInstall makes the simulated apt install of the staged file print text and exit with code.
func (m *Machine) SimInstall(text string, code int) {
	m.RuleText("apt-get", "-s -q -o Debug::NoLocking=1 --no-remove --no-install-recommends install", text, code, "", "")
}

// SimInstallOK is the simulation of an install of vedette-host <debVersion> over <debFrom> with one new dependency.
func SimInstallOK(debFrom, debVersion string) string {
	return "Reading package lists...\nInst conntrack (1:1.4.8-1 Ubuntu:24.04/noble [amd64])\nInst vedette-host [" + debFrom + "] (" + debVersion + " local-deb [amd64])\n" +
		"Conf conntrack (1:1.4.8-1 Ubuntu:24.04/noble [amd64])\nConf vedette-host (" + debVersion + " local-deb [amd64])\n"
}

// HostFile is one host.files[] entry of a manifest.
type HostFile struct {
	Name   string
	SHA256 string
	Size   int64
}

// HostFileOf is the amd64 entry of a package's bytes.
func HostFileOf(version string, content []byte) HostFile {
	return HostFile{Name: "vedette-host_" + version + "_amd64.deb", SHA256: SHA(content), Size: int64(len(content))}
}

// HostManifestDoc is ManifestDoc of version with a host part (hostVersion and its files); no images.
func (r *Release) HostManifestDoc(version, hostVersion string, files ...HostFile) Doc {
	d := r.ManifestDoc(version, Img{Service: api.ServiceCore, Digest: "sha256:" + strings.Repeat("a", 64), Size: 1000})
	var fs []any
	for _, f := range files {
		fs = append(fs, Doc{"name": f.Name, "sha256": f.SHA256, "size": f.Size})
	}
	d["host"] = Doc{"version": hostVersion, "files": fs}
	return d
}

// SelfUpdateArgs builds the host.self_update args for raw documents signed by the active key.
func (r *Release) SelfUpdateArgs(version string, indexRaw, manifestRaw []byte, pkg string) api.HostSelfUpdateArgs {
	b := base64.StdEncoding.EncodeToString
	return api.HostSelfUpdateArgs{
		Version: version, Index: b(indexRaw), IndexSig: b(r.Sign(indexRaw)), Manifest: b(manifestRaw), ManifestSig: b(r.Sign(manifestRaw)), Package: pkg,
	}
}
