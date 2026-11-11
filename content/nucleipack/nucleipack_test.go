package nucleipack

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// keyValues reads KEY=VALUE (pins.env) or "key: value" (index.source) lines.
func keyValues(t *testing.T, path, sep string) map[string]string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // a fixed path of this repository
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, sep); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The committed copy is the one `make scan-pack` writes for the image: the same source (nuclei-templates version and
// archive sha256) and the same pack version as deploy/containers/pins.env, and an index whose sha256 is its own label.
// Otherwise core and the image drift and every job is refused as pack_mismatch (D-133 (4)).
func TestTheCommittedIndexIsThePinnedPack(t *testing.T) {
	t.Parallel()
	pins := keyValues(t, "../../deploy/containers/pins.env", "=")
	src := keyValues(t, "index.source", ":")
	for k, pin := range map[string]string{
		"nuclei_templates_version": "NUCLEI_TEMPLATES_VERSION",
		"nuclei_templates_sha256":  "NUCLEI_TEMPLATES_SHA256",
		"scan_pack_version":        "SCAN_PACK_VERSION",
	} {
		if pins[pin] == "" || src[k] != pins[pin] {
			t.Errorf("index.source %s = %q, pins.env %s = %q: run `make scan-pack` and commit content/nucleipack", k, src[k], pin, pins[pin])
		}
	}
	ix, err := Index()
	if err != nil {
		t.Fatal(err)
	}
	if ix.Version != pins["SCAN_PACK_VERSION"] {
		t.Errorf("index version %s, pins.env SCAN_PACK_VERSION %s", ix.Version, pins["SCAN_PACK_VERSION"])
	}
	// the label of scripts/scanpack: sha256 of the version line, then "path<TAB>sha256" per template sorted by path
	lines := make([]string, 0, len(ix.Templates))
	for _, tpl := range ix.Templates {
		lines = append(lines, tpl.Path+"\t"+tpl.SHA256+"\n")
	}
	sort.Strings(lines)
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\n", ix.Version)
	for _, l := range lines {
		_, _ = h.Write([]byte(l))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != ix.SHA256 {
		t.Errorf("the index sha256 %s is not its label %s: the file was edited by hand", ix.SHA256, got)
	}
}
