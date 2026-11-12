package ops

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// support is the static table of supported releases and their end dates (D-57 (1): Ubuntu
// 24.04 and 26.04 LTS, Debian 13). Dates are the end of standard security support and of the
// extended program (Ubuntu Pro ESM, Debian LTS). A new release means a new host version (spec 6.1).
// Exact days from distro-info-data 2026.10.12 (/usr/share/distro-info/{ubuntu,debian}.csv, the data Ubuntu's and Debian's own tools
// read: columns eol-server/eol-esm and eol/eol-lts), checked 2026-11-11; they agree with https://ubuntu.com/about/release-cycle (months
// only) and https://www.debian.org/releases/trixie/. Extend the table by hand when a release appears.
type support struct {
	End      string
	Extended string
}

var supportTable = map[string]support{
	"ubuntu/24.04": {End: "2029-05-31", Extended: "2034-04-25"},
	"ubuntu/26.04": {End: "2031-05-29", Extended: "2036-04-23"},
	"debian/13":    {End: "2028-08-09", Extended: "2030-06-30"},
}

// platform is the distribution the host runs on.
type platform struct {
	Distro  string
	Release string
	Name    string
	Support support
}

var osValueRE = regexp.MustCompile(`^[A-Za-z0-9 ._()/+-]{1,80}$`)

// parseOSReleaseFields reads ID, VERSION_ID and PRETTY_NAME of os-release text.
func parseOSReleaseFields(data []byte) (id, version, pretty string) {
	if len(data) > 64<<10 {
		data = data[:64<<10]
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 0; sc.Scan() && n < 2000; n++ {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if !osValueRE.MatchString(v) {
			continue
		}
		switch strings.TrimSpace(k) {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		case "PRETTY_NAME":
			pretty = v
		}
	}
	return id, version, pretty
}

// platform reads os-release and looks the release up in the table; an unsupported distribution or
// release is a refusal (not_appliance): the appliance runs on the table's releases only.
func (o *Ops) platform() (platform, error) {
	f, err := os.Open(o.path("etc/os-release"))
	if err != nil {
		return platform{}, refuse412("not_appliance", "This machine does not say which operating system it runs, so it is not treated as an appliance.")
	}
	defer func() { _ = f.Close() }()
	data, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	id, ver, pretty := parseOSReleaseFields(data)
	sup, ok := supportTable[id+"/"+ver]
	if !ok {
		return platform{}, refuse412("not_appliance", "This operating system release is not one the appliance supports (Ubuntu 24.04, Ubuntu 26.04, Debian 13).")
	}
	if pretty == "" {
		pretty = id + " " + ver
	}
	return platform{Distro: id, Release: ver, Name: pretty, Support: sup}, nil
}

// readTrimmed reads a small file under the root and returns its first line.
func (o *Ops) readSmall(rel string, limit int64) ([]byte, error) {
	f, err := os.Open(o.path(rel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// kernelRelease is /proc/sys/kernel/osrelease, "unknown" when it is absent or odd.
func (o *Ops) kernelRelease() string {
	b, err := o.readSmall("proc/sys/kernel/osrelease", 256)
	if s := strings.TrimSpace(string(b)); err == nil && tokenRE.MatchString(s) {
		return s
	}
	return "unknown"
}

// bootedAt is now minus /proc/uptime; the zero time when it cannot be read.
func (o *Ops) bootedAt() time.Time {
	b, err := o.readSmall("proc/uptime", 256)
	if err != nil {
		return time.Time{}
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	secs, err := strconv.ParseFloat(first, 64)
	if err != nil || secs < 0 || secs > 1e9 {
		return time.Time{}
	}
	return o.d.Now().Add(-time.Duration(secs * float64(time.Second))).UTC().Truncate(time.Second)
}

var bootIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// bootID is the kernel's random id of this boot ("" when unreadable).
func (o *Ops) bootID() string {
	b, err := o.readSmall("proc/sys/kernel/random/boot_id", 128)
	if s := strings.TrimSpace(string(b)); err == nil && bootIDRE.MatchString(s) {
		return s
	}
	return ""
}

// rebootInfo reads /var/run/reboot-required and its .pkgs list.
func (o *Ops) rebootInfo() (required bool, reasons []string) {
	if _, err := os.Stat(o.path("var/run/reboot-required")); err != nil {
		return false, []string{}
	}
	b, _ := o.readSmall("var/run/reboot-required.pkgs", 64<<10)
	r := parseRebootPkgs(b)
	if r == nil {
		r = []string{}
	}
	return true, r
}
