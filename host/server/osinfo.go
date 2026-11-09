package server

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
)

const maxOSReleaseBytes = 64 << 10

var osTokenRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// ParseOSRelease reads ID and VERSION_ID from the text of /etc/os-release. The file is data that
// root's tools write but the parser treats as untrusted: it returns only short, plain tokens
// ("ubuntu", "24.04"), "unknown" for anything missing or odd, and never fails.
func ParseOSRelease(data []byte) (distro, release string) {
	distro, release = "unknown", "unknown"
	if len(data) > maxOSReleaseBytes {
		data = data[:maxOSReleaseBytes]
	}
	for i, line := range bytes.Split(data, []byte("\n")) {
		if i > 2000 {
			break
		}
		k, v, ok := strings.Cut(strings.TrimSpace(string(line)), "=")
		if !ok {
			continue
		}
		v = unquote(strings.TrimSpace(v))
		if !osTokenRE.MatchString(v) {
			continue
		}
		switch strings.TrimSpace(k) {
		case "ID":
			distro = v
		case "VERSION_ID":
			release = v
		}
	}
	return distro, release
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

func readOSRelease(path string) (distro, release string) {
	f, err := os.Open(path) //nolint:gosec // path is fixed by Options, /etc/os-release by default
	if err != nil {
		return "unknown", "unknown"
	}
	defer func() { _ = f.Close() }()
	data, _ := io.ReadAll(io.LimitReader(f, maxOSReleaseBytes))
	return ParseOSRelease(data)
}
