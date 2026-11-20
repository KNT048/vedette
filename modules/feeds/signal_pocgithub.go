package feeds

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// PoC-in-GitHub (nomi-sec, CC0): an index of the GitHub repositories that claim a proof of concept for a CVE, one JSON file per CVE
// (YYYY/CVE-….json) listing each repository's name, owner, creation time and star count. The box downloads the whole repository as
// one tar.gz archive and reads those files only; the repositories themselves are never fetched.
//
// Many such repositories are fakes or carry malware, so a CVE's claim qualifies only by the quality rule: a repository with at least
// pocStars stars when seen, a repository by a known author (content/catalog/exploit-authors.json), or repositories by at least
// pocAuthors different accounts. A CVE that does not qualify keeps its row with qualifies = 0, so the date of the first claim stays.

const (
	pocMaxFiles    = 100_000   // CVE files of one archive (about 11,900 in November 2026)
	pocMaxFile     = 8 << 20   // one CVE file (the largest, CVE-2021-44228, is well under 1 MB)
	pocMaxUnpacked = 512 << 20 // every file of the archive together (71 MB in November 2026)
	pocMaxRepos    = 20_000    // repositories listed in one CVE file
)

// pocFileRE is a CVE file of the archive: the archive's top folder, a year folder, then the CVE id.
var pocFileRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[0-9]{4}/(CVE-[0-9]{4}-[0-9]{4,7})\.json$`)

// githubLoginRE and githubRepoRE are a GitHub account name and a repository name.
var (
	githubLoginRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	githubRepoRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

type pocRepo struct {
	FullName  string `json:"full_name"`
	HTMLURL   string `json:"html_url"`
	Fork      bool   `json:"fork"`
	CreatedAt string `json:"created_at"`
	Stars     int    `json:"stargazers_count"`
	Owner     struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// exploitAuthors is the known authors of exploit-authors.json, lower case.
var exploitAuthors = sync.OnceValue(func() map[string]bool {
	var f struct {
		Logins []string `json:"logins"`
	}
	if err := json.Unmarshal(catalogdata.ExploitAuthors, &f); err != nil {
		panic(fmt.Sprintf("feeds: content/catalog/exploit-authors.json: %v", err)) // embedded at build time; TestExploitAuthors reads it
	}
	out := make(map[string]bool, len(f.Logins))
	for _, l := range f.Logins {
		out[strings.ToLower(l)] = true
	}
	return out
})

// ParsePoCInGitHub reads the PoC-in-GitHub repository as a tar.gz archive. Files other than the CVE files are skipped unread. A CVE
// file must be a JSON array of repositories; a repository that is a fork, or whose name, address or creation time is not well formed,
// is left out, and a file left with none gives no signal. A file that is not such an array, or too large, is rejected; an archive
// past the limits fails (fail-closed).
func ParsePoCInGitHub(r io.Reader) (publicIndex, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return publicIndex{}, fail(ErrBadSample, "The PoC-in-GitHub archive is not a gzip file.")
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	tl := newTally()
	byCVE := map[string]publicSignal{}
	var (
		files    int
		unpacked int64
	)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return publicIndex{}, fail(ErrBadSample, "The PoC-in-GitHub archive could not be read.")
		}
		m := pocFileRE.FindStringSubmatch(h.Name)
		if m == nil || h.Typeflag != tar.TypeReg {
			continue
		}
		if files++; files > pocMaxFiles {
			return publicIndex{}, fail(ErrBadSample, "The PoC-in-GitHub archive has more than %s CVE files.", grouped(pocMaxFiles))
		}
		if h.Size > pocMaxFile {
			tl.reject(files, "%s: the file is too large", m[1])
			continue
		}
		if unpacked += h.Size; unpacked > pocMaxUnpacked {
			return publicIndex{}, fail(ErrTooLarge, "The PoC-in-GitHub archive unpacks to more than %d MB.", pocMaxUnpacked>>20)
		}
		body, err := io.ReadAll(io.LimitReader(tr, pocMaxFile+1))
		if err != nil {
			return publicIndex{}, fail(ErrBadSample, "The PoC-in-GitHub archive could not be read.")
		}
		g, ok, why := pocSignal(m[1], body)
		if why != "" {
			tl.reject(files, "%s: "+why, m[1])
			continue
		}
		if !ok {
			continue
		}
		tl.Accepted++
		if old, seen := byCVE[g.CVE]; !seen || g.Date.Before(old.Date) {
			byCVE[g.CVE] = g
		}
	}
	out := publicIndex{Signals: make([]publicSignal, 0, len(byCVE)), Stats: tl.stats()}
	for _, g := range byCVE {
		out.Signals = append(out.Signals, g)
	}
	sort.Slice(out.Signals, func(i, j int) bool { return out.Signals[i].CVE < out.Signals[j].CVE })
	return out, nil
}

// pocSignal reads one CVE file: the signal (ok false when no repository is left), or why the file is rejected.
func pocSignal(cve string, body []byte) (publicSignal, bool, string) {
	if len(body) > pocMaxFile {
		return publicSignal{}, false, "the file is too large"
	}
	var all []pocRepo
	if err := json.Unmarshal(body, &all); err != nil {
		return publicSignal{}, false, "the file is not a list of repositories"
	}
	if len(all) > pocMaxRepos {
		return publicSignal{}, false, "the file lists too many repositories"
	}
	type repo struct {
		login, url string
		created    time.Time
		stars      int
	}
	repos := make([]repo, 0, len(all))
	for _, x := range all {
		login, name, found := strings.Cut(x.FullName, "/")
		if x.Fork || !found || !githubLoginRE.MatchString(login) || !githubRepoRE.MatchString(name) || name == "." || name == ".." ||
			!strings.EqualFold(login, x.Owner.Login) || x.HTMLURL != "https://github.com/"+x.FullName || x.Stars < 0 {
			continue
		}
		created, err := time.Parse(time.RFC3339, x.CreatedAt)
		if err != nil {
			continue
		}
		repos = append(repos, repo{login: strings.ToLower(login), url: x.HTMLURL, created: created.UTC(), stars: x.Stars})
	}
	if len(repos) == 0 {
		return publicSignal{}, false, ""
	}
	sort.SliceStable(repos, func(i, j int) bool {
		if !repos[i].created.Equal(repos[j].created) {
			return repos[i].created.Before(repos[j].created)
		}
		return repos[i].url < repos[j].url
	})
	g := publicSignal{CVE: cve, Date: repos[0].created}
	var (
		owners          = map[string]bool{}
		by              string
		top             = repos[0]
		known, starsDay time.Time
	)
	authors := exploitAuthors()
	for _, x := range repos {
		if !owners[x.login] {
			owners[x.login] = true
			if len(owners) == pocAuthors {
				g.Rule = x.created
			}
		}
		if authors[x.login] && known.IsZero() {
			known, by = x.created, x.login
			top = x
		}
		if x.stars >= pocStars && starsDay.IsZero() {
			starsDay = x.created
		}
		if by == "" && x.stars > top.stars {
			top = x
		}
	}
	g.Rule = earliest(g.Rule, known)
	g.Stars = starsDay
	g.Qualifies = !g.Rule.IsZero() || !g.Stars.IsZero()
	g.URL = top.url
	stars := 0
	for _, x := range repos {
		stars = max(stars, x.stars)
	}
	detail := map[string]any{"repos": len(repos), "authors": len(owners), "stars": stars}
	if by != "" {
		detail["by"] = by
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return publicSignal{}, false, "the file could not be read"
	}
	g.Detail = string(b)
	return g, true, ""
}

// heldPoC: the feed counts every CVE with a claimed proof of concept; what matters is how many pass the quality rule.
func heldPoC(ctx context.Context, tx *sql.Tx) (string, error) {
	var all, kept int
	if err := counts(ctx, tx, `SELECT count(*), count(*) FILTER (WHERE qualifies = 1) FROM feeds_signal WHERE source = ? AND kind = ?`,
		[]any{pocGitHubFeedID, SignalPublicExploit}, &all, &kept); err != nil {
		return "", err
	}
	if all == 0 {
		return "", nil
	}
	return fmt.Sprintf("%s of %s pass the quality rule (%d stars, a known author or %d authors).", grouped(kept), cves(all, "claimed"), pocStars, pocAuthors), nil
}
