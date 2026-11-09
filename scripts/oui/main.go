// Command oui builds content/oui/oui.tsv.gz, the table that turns the first bits of a MAC address into the
// name of the company the IEEE registered them to (D-83). It downloads runZero's mac-tracker file
// (MIT; rebuilt twice a day from the IEEE registries oui, mam, oui36, iab and cid), keeps the latest
// organisation of every /24, /28 and /36 prefix, drops pointer and "private" entries, and writes the table
// in a fixed order. Run it with `make oui`; the result is committed, the product never downloads it.
//
// The source is pinned: the file of one commit of mac-tracker, whose SHA-256 is recorded below; a download that
// does not hash to it is refused. `-ref main` only looks at what the newest commit would be (it asks the GitHub API
// for the commit id, downloads the file and prints the two constants to review and copy; it writes nothing).
// The same input always gives the same bytes (the gzip header carries no time). oui.source records the commit,
// the file's SHA-256 and the counts. Network, for a maintainer only: raw.githubusercontent.com (and api.github.com
// for `-ref main`), 60 s limit each.
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
	"unicode"
	"unicode/utf8"
)

const (
	// pinnedCommit is the commit of runZeroInc/mac-tracker the table is built from, pinnedSHA256 the SHA-256 of its
	// data/macs.json. Change both together, after looking at `go run ./scripts/oui -ref main`.
	pinnedCommit = "05af1197de5f8604957ceb8c9ef374fffbbfd95f" // 2026-11-07; bump with `-ref main`, then set both values
	pinnedSHA256 = "8dc5fbd67026d8e9049ee637bb5881e07e761999c2c4bf59077368d0e6bfd12b"

	rawURL    = "https://raw.githubusercontent.com/runZeroInc/mac-tracker/%s/data/macs.json"
	refAPI    = "https://api.github.com/repos/runZeroInc/mac-tracker/commits/main"
	allowHost = "raw.githubusercontent.com"
	apiHost   = "api.github.com"
	maxBody   = 64 << 20 // the file is about 17 MB
	maxVendor = 200
)

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// recorded is the SHA-256 the maintainers recorded for a commit; a commit that is not here cannot be built from.
var recorded = map[string]string{pinnedCommit: pinnedSHA256}

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
	in := flag.String("in", "", "read this local macs.json instead of downloading (tests, offline rebuilds); its path is recorded as the source")
	ref := flag.String("ref", "", `"main": show the newest commit's id and SHA-256 to pin, write nothing; empty: the pinned commit`)
	out := flag.String("out", "content/oui/oui.tsv.gz", "table to write")
	flag.Parse()
	if err := run(*in, *ref, *out); err != nil {
		fmt.Fprintln(os.Stderr, "oui:", err)
		os.Exit(1)
	}
}

func run(in, ref, out string) error {
	switch ref {
	case "":
	case "main":
		return showNewest()
	default:
		return errors.New(`-ref accepts only "main"`)
	}
	var raw []byte
	var err error
	source, commit := in, "local file"
	if in != "" {
		raw, err = os.ReadFile(in) //nolint:gosec // a developer tool: the path is the operator's argument
	} else {
		source, commit = fmt.Sprintf(rawURL, pinnedCommit), pinnedCommit
		raw, err = fetchPinned(pinnedCommit)
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
	var n [3]int
	for _, r := range rows {
		n[(r.bits-20)/8]++ // 24, 28, 36 -> 0, 1, 2
	}
	note := fmt.Sprintf("source: %s\nsource_commit: %s\nsource_sha256: %s\nprefixes: %d (%d of 24 bits, %d of 28, %d of 36)\nskipped: %d (deleted, IEEE pointer entries, private, other lengths)\n",
		source, commit, hex.EncodeToString(sum[:]), len(rows), n[0], n[1], n[2], skipped)
	if err := writeIfChanged(out, table); err != nil {
		return err
	}
	if err := writeIfChanged(strings.TrimSuffix(out, ".tsv.gz")+".source", []byte(note)); err != nil {
		return err
	}
	fmt.Printf("oui: %d prefixes (%d skipped) -> %s\n", len(rows), skipped, out)
	return nil
}

// fetchPinned downloads the file of a commit and refuses it unless it hashes to the value recorded for that commit.
func fetchPinned(commit string) ([]byte, error) {
	want, ok := recorded[commit]
	if !commitRE.MatchString(commit) || !ok || want == "" {
		return nil, errors.New("no pinned commit: run `go run ./scripts/oui -ref main`, review, and set pinnedCommit and pinnedSHA256")
	}
	raw, err := download(fmt.Sprintf(rawURL, commit))
	if err != nil {
		return nil, err
	}
	return raw, verify(commit, raw, want)
}

// verify refuses a file whose SHA-256 is not the recorded one.
func verify(commit string, raw []byte, want string) error {
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("commit %s: the downloaded file hashes to %x, the recorded value is %s: refusing it", commit, got, want)
	}
	return nil
}

// showNewest asks the GitHub API which commit main is at, downloads that commit's file and prints what to pin.
func showNewest() error {
	body, err := get(refAPI, apiHost, 1<<20)
	if err != nil {
		return err
	}
	var c struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &c); err != nil || !commitRE.MatchString(c.SHA) {
		return errors.New("the GitHub API did not return a commit id")
	}
	raw, err := download(fmt.Sprintf(rawURL, c.SHA))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	fmt.Printf("newest commit of main: %s\nSHA-256 of its data/macs.json: %s\nTo build from it set pinnedCommit and pinnedSHA256 in scripts/oui/main.go to these, then run `make oui`.\n", c.SHA, hex.EncodeToString(sum[:]))
	return nil
}

func download(raw string) ([]byte, error) { return get(raw, allowHost, maxBody) }

// get fetches an https URL on one host, without following redirects, within 60 s and limit bytes.
func get(raw, host string, limit int) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() != host {
		return nil, fmt.Errorf("source must be an https URL on %s", host)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if len(body) > limit {
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
		if c := strings.Compare(a.prefix, b.prefix); c != 0 {
			return c
		}
		return strings.Compare(a.vendor, b.vendor)
	})
	// Two keys can name one prefix (the digits after the prefix are not read): the same vendor twice is one row, two
	// vendors for one prefix is a source we cannot choose from.
	out := rows[:0]
	for _, r := range rows {
		if n := len(out); n > 0 && out[n-1].bits == r.bits && out[n-1].prefix == r.prefix {
			if out[n-1].vendor != r.vendor {
				return nil, 0, fmt.Errorf("prefix %s/%d is claimed by %q and %q", r.prefix, r.bits, out[n-1].vendor, r.vendor)
			}
			skipped++
			continue
		}
		out = append(out, r)
	}
	return out, skipped, nil
}

// clean makes a vendor name one printable line of at most maxVendor bytes: control characters (C0, DEL, C1) and
// invisible format characters (Unicode Cf: bidirectional marks, zero-width, soft hyphen, tags) are dropped, any run
// of white space becomes one space, and the ends are trimmed.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || (r >= 0xe0000 && r <= 0xe007f) {
			if unicode.IsSpace(r) { // \t, \n, the C1 NEL are separators, not noise
				return ' '
			}
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxVendor {
		s = s[:maxVendor]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s = strings.TrimSpace(s)
	}
	return s
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
	zw.Header = gzip.Header{OS: 255} // no name, no time, OS "unknown": the same rows always give the same bytes
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
