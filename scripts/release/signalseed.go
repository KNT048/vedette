package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/feeds"
)

// signal-seed builds the seed of exploitation claims the release ships (content/signals/seed.json): the previous seed, plus what
// Vedette's own decoders read now from the sources that keep no history, through the box's own code (feeds.SeedFromFeed,
// SeedFromAndroidPage, SeedFromCSAF): Chrome Releases (paged back through its feed), Rapid7's and Google Threat Intelligence's blog
// feeds, Android's monthly bulletins, and, from files the maintainer gives, Cisco and Fortinet CSAF documents older than their feeds
// reach. A claim a document read now no longer makes leaves the seed; nothing is added by hand. It reads public feeds only, half a
// second apart, and sends nothing but the requests.

// seedSites are the addresses the generator reads (the built-in feeds' own).
type seedSites struct {
	chrome, rapid7, gti, android string
}

var defaultSeedSites = seedSites{
	chrome:  "https://chromereleases.googleblog.com/feeds/posts/default?redirect=false",
	rapid7:  "https://www.rapid7.com/rss.xml",
	gti:     "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/",
	android: "https://source.android.com/docs/security/bulletin/",
}

// seedRun is one run of the generator.
type seedRun struct {
	client  *http.Client
	sites   seedSites
	pause   time.Duration
	now     time.Time
	chrome  int // Chrome Releases posts read, newest first
	months  int // Android bulletins read, this month and the ones before
	cisco   string
	fortine string
	out     io.Writer
	asked   int
}

// seedMaxBody bounds one answer (Chrome's 150 posts are about 3 MB).
const seedMaxBody = 32 << 20

func cmdSignalSeed(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlags("signal-seed")
	prev := fs.String("prev", "content/signals/seed.json", "the previous seed")
	out := fs.String("out", "content/signals/seed.json", "where the new seed is written")
	chrome := fs.Int("chrome-posts", 1000, "Chrome Releases posts read, newest first (more than a year)")
	months := fs.Int("android-months", 13, "Android bulletins read, this month and the ones before")
	cisco := fs.String("csaf-cisco", "", "Cisco CSAF documents, one per line (.jsonl or .jsonl.gz): advisories older than Cisco's feed")
	fortinet := fs.String("csaf-fortinet", "", "Fortinet CSAF documents, one per line (.jsonl or .jsonl.gz)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	r := seedRun{client: &http.Client{Timeout: 2 * time.Minute}, sites: defaultSeedSites, pause: 500 * time.Millisecond, now: time.Now().UTC(),
		chrome: *chrome, months: *months, cisco: *cisco, fortine: *fortinet, out: stdout}
	return r.build(ctx, *prev, *out)
}

// build reads the previous seed and every source, and writes the merged seed.
func (r *seedRun) build(ctx context.Context, prevPath, outPath string) error {
	raw, err := readSmall(prevPath, 64<<20)
	if err != nil {
		return err
	}
	prev, err := feeds.ParseSeed(raw)
	if err != nil {
		return err
	}
	var reads []feeds.SeedRead
	for _, step := range []func(context.Context) ([]feeds.SeedRead, error){r.chromeReads, r.blogReads, r.androidReads, r.csafReads} {
		got, err := step(ctx)
		if err != nil {
			return err
		}
		reads = append(reads, got...)
	}
	next := feeds.MergeSeed(prev, reads)
	if _, err := feeds.ParseSeed(next.JSON()); err != nil { // the box reads it with the same check
		return err
	}
	if err := os.WriteFile(outPath, next.JSON(), 0o644); err != nil { //nolint:gosec // a file of the repository
		return err
	}
	count := func(s feeds.Seed) map[string]int {
		m := map[string]int{}
		for _, c := range s.Claims {
			m[c.Source]++
		}
		return m
	}
	was, now := count(prev), count(next)
	for _, src := range []string{"chrome-releases", "android-bulletin", "rapid7-blog", "gti-blog", "cisco-psirt", "fortinet-psirt"} {
		say(r.out, "%-17s %4d claims (was %d)", src, now[src], was[src])
	}
	say(r.out, "wrote %s: %d claims", outPath, len(next.Claims))
	return nil
}

// get asks one address, half a second after the last request, and returns its body; a 404 is (nil, nil).
func (r *seedRun) get(ctx context.Context, u string) ([]byte, error) {
	if r.asked++; r.asked > 1 && r.pause > 0 {
		t := time.NewTimer(r.pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Vedette-release (exploitation claims seed)")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, nil
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, seedMaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	if len(b) > seedMaxBody {
		return nil, fmt.Errorf("%s: larger than %d MB", u, seedMaxBody>>20)
	}
	return b, nil
}

// chromeReads pages back through Chrome Releases' feed, up to 150 posts a request (Blogger may answer fewer: the next page starts
// after the posts it gave), until r.chrome posts or a page without posts.
func (r *seedRun) chromeReads(ctx context.Context) ([]feeds.SeedRead, error) {
	var out []feeds.SeedRead
	for start := 1; start <= r.chrome; {
		u, err := url.Parse(r.sites.chrome)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("max-results", "150")
		q.Set("start-index", fmt.Sprint(start))
		u.RawQuery = q.Encode()
		body, err := r.get(ctx, u.String())
		if err != nil {
			return nil, err
		}
		got, err := feeds.SeedFromFeed(ctx, "chrome-releases", body)
		if err != nil {
			return nil, fmt.Errorf("chrome releases: %w", err)
		}
		if len(got) == 0 {
			break
		}
		start += len(got)
		out = append(out, got...)
	}
	return out, nil
}

// blogReads reads the two research blogs' feeds.
func (r *seedRun) blogReads(ctx context.Context) ([]feeds.SeedRead, error) {
	var out []feeds.SeedRead
	for _, b := range []struct{ source, url string }{{"rapid7-blog", r.sites.rapid7}, {"gti-blog", r.sites.gti}} {
		body, err := r.get(ctx, b.url)
		if err != nil {
			return nil, err
		}
		if body == nil {
			return nil, fmt.Errorf("%s: the feed is gone", b.url)
		}
		got, err := feeds.SeedFromFeed(ctx, b.source, body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.source, err)
		}
		out = append(out, got...)
	}
	return out, nil
}

// androidReads reads the bulletin of each of r.months months (under its year's folder, else the older address).
func (r *seedRun) androidReads(ctx context.Context) ([]feeds.SeedRead, error) {
	base, err := url.Parse(r.sites.android)
	if err != nil {
		return nil, err
	}
	this := time.Date(r.now.Year(), r.now.Month(), 1, 0, 0, 0, 0, time.UTC)
	var out []feeds.SeedRead
	for m := range r.months {
		month := this.AddDate(0, -m, 0)
		day := month.Format(time.DateOnly)
		for _, path := range []string{fmt.Sprintf("%d/%s", month.Year(), day), day} {
			u := base.ResolveReference(&url.URL{Path: path}).String()
			page, err := r.get(ctx, u)
			if err != nil {
				return nil, err
			}
			if page == nil {
				continue
			}
			got, err := feeds.SeedFromAndroidPage(ctx, u, page, month)
			if err != nil {
				return nil, fmt.Errorf("android %s: %w", day, err)
			}
			out = append(out, got)
			break
		}
	}
	return out, nil
}

// csafReads reads the CSAF documents of the files given, one document per line.
func (r *seedRun) csafReads(ctx context.Context) ([]feeds.SeedRead, error) {
	var out []feeds.SeedRead
	for _, f := range []struct{ source, path string }{{"cisco-psirt", r.cisco}, {"fortinet-psirt", r.fortine}} {
		if f.path == "" {
			continue
		}
		lines, err := jsonLines(f.path)
		if err != nil {
			return nil, err
		}
		for i, l := range lines {
			got, err := feeds.SeedFromCSAF(ctx, f.source, l)
			if err != nil {
				return nil, fmt.Errorf("%s line %d: %w", f.path, i+1, err)
			}
			out = append(out, got)
		}
	}
	return out, nil
}

// jsonLines is the non-empty lines of a file, gunzipped when it ends in .gz.
func jsonLines(path string) ([][]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a file the maintainer names
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rd io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		z, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		defer func() { _ = z.Close() }()
		rd = z
	}
	sc := bufio.NewScanner(rd)
	sc.Buffer(nil, 8<<20)
	var out [][]byte
	for sc.Scan() {
		if l := bytes.TrimSpace(sc.Bytes()); len(l) > 0 {
			out = append(out, bytes.Clone(l))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, errors.New(path + ": no documents")
	}
	return out, nil
}
