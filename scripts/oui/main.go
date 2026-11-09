// Command oui builds content/oui/oui.tsv.gz, the table that turns the first bits of a MAC address into the
// name of the company the IEEE registered them to (D-83). It downloads runZero's mac-tracker file
// (MIT; rebuilt twice a day from the IEEE registries oui, mam, oui36, iab and cid), keeps the latest
// organisation of every /24, /28 and /36 prefix, drops pointer and "private" entries, and writes the table
// in a fixed order. Run it with `make oui`; the result is committed, the product never downloads it.
//
// The same input always gives the same TSV; the source file's SHA-256 is recorded in oui.source so a change of
// the table is traceable to a change of the source. Network: only raw.githubusercontent.com, 60 s limit.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultURL = "https://raw.githubusercontent.com/runZeroInc/mac-tracker/main/data/macs.json"
	allowHost  = "raw.githubusercontent.com"
	maxBody    = 64 << 20 // the file is about 17 MB
	maxVendor  = 200
)

var keyRE = regexp.MustCompile(`^[0-9a-f]{12}/(24|28|36)$`)

// entry is the part of one history record this tool reads; the history of a prefix is oldest first.
type entry struct {
	Type string `json:"t"`
	Org  string `json:"o"`
}

type row struct {
	bits   int
	prefix string
	vendor string
}

func main() {
	srcURL := flag.String("url", defaultURL, "source file (https, raw.githubusercontent.com only)")
	in := flag.String("in", "", "read this local macs.json instead of downloading (tests, offline rebuilds)")
	out := flag.String("out", "content/oui/oui.tsv.gz", "table to write")
	flag.Parse()
	if err := run(*srcURL, *in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "oui:", err)
		os.Exit(1)
	}
}

func run(srcURL, in, out string) error {
	var raw []byte
	var err error
	if in != "" {
		raw, err = os.ReadFile(in) //nolint:gosec // a developer tool: the path is the operator's argument
	} else {
		raw, err = download(srcURL)
	}
	if err != nil {
		return err
	}
	rows, skipped, err := build(raw)
	if err != nil {
		return err
	}
	if len(rows) < 50000 {
		return fmt.Errorf("only %d prefixes: the source looks broken, refusing to replace the table", len(rows))
	}
	table, err := encode(rows)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	note := fmt.Sprintf("source: %s\nsource_sha256: %s\nprefixes: %d\nskipped: %d (deleted, IEEE pointer entries, private, other lengths)\n",
		srcURL, hex.EncodeToString(sum[:]), len(rows), skipped)
	if in != "" {
		note = strings.Replace(note, "source: "+srcURL, "source: "+defaultURL, 1)
	}
	if err := writeIfChanged(out, table); err != nil {
		return err
	}
	if err := writeIfChanged(strings.TrimSuffix(out, ".tsv.gz")+".source", []byte(note)); err != nil {
		return err
	}
	fmt.Printf("oui: %d prefixes (%d skipped) -> %s\n", len(rows), skipped, out)
	return nil
}

func download(raw string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() != allowHost {
		return nil, fmt.Errorf("source must be an https URL on %s", allowHost)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if len(body) > maxBody {
		return nil, errors.New("download: file larger than the limit")
	}
	return body, nil
}

// build keeps the latest organisation per prefix.
func build(raw []byte) (rows []row, skipped int, err error) {
	var src map[string][]entry
	if err := json.Unmarshal(raw, &src); err != nil {
		return nil, 0, fmt.Errorf("source is not the expected JSON: %w", err)
	}
	for key, hist := range src {
		if !keyRE.MatchString(key) || len(hist) == 0 {
			skipped++
			continue
		}
		last := hist[len(hist)-1]
		vendor := clean(last.Org)
		if last.Type == "delete" || vendor == "" || pointer(vendor) {
			skipped++
			continue
		}
		bits := 24
		switch key[13:] {
		case "28":
			bits = 28
		case "36":
			bits = 36
		}
		rows = append(rows, row{bits: bits, prefix: key[:bits/4], vendor: vendor})
	}
	slices.SortFunc(rows, func(a, b row) int {
		if a.bits != b.bits {
			return a.bits - b.bits
		}
		return strings.Compare(a.prefix, b.prefix)
	})
	return rows, skipped, nil
}

// clean makes a vendor name one printable line of at most maxVendor bytes.
func clean(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxVendor {
		s = s[:maxVendor]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
}

// pointer reports entries that only say "look in another registry" or carry no vendor.
func pointer(v string) bool {
	l := strings.ToLower(v)
	return strings.Contains(l, "ieee registration authority") || strings.Contains(l, "please see") || l == "private"
}

func encode(rows []row) ([]byte, error) {
	var tsv bytes.Buffer
	for _, r := range rows {
		fmt.Fprintf(&tsv, "%s\t%d\t%s\n", r.prefix, r.bits, r.vendor)
	}
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(tsv.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return gz.Bytes(), nil
}

// writeIfChanged writes through a temporary file and leaves an identical file alone (idempotent).
func writeIfChanged(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) { //nolint:gosec // the path is the operator's argument
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".oui-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { //nolint:gosec // a committed, world-readable data file
		return err
	}
	return os.Rename(tmp.Name(), path)
}
