package worker_test

import (
	"testing"

	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// SP-6 L2: the version is read from the first non-empty line of `nmap --version`.
func TestVersionIsReadFromTheFirstNonEmptyLine(t *testing.T) {
	t.Parallel()
	for out, want := range map[string]string{
		"Nmap version 7.95 ( https://nmap.org )\nPlatform: x\n": "7.95",
		"\nNmap version 7.95 ( https://nmap.org )\n":            "7.95",
		"\n\n  \nNmap version 7.94SVN ( https://nmap.org )\n":   "7.94SVN",
		"\r\nNmap version 7.95 ( https://nmap.org )\r\n":        "7.95",
		"":     "",
		"\n\n": "",
		"hello\nNmap version 7.95 ( https://nmap.org )\n": "",
		"\nNmap version 7.95$(id) ( https://nmap.org )\n": "",
		"Nmap version ( https://nmap.org )\n":             "",
	} {
		if got := worker.VersionOf([]byte(out)); got != want {
			t.Errorf("%q: %q, want %q", out, got, want)
		}
	}
}
