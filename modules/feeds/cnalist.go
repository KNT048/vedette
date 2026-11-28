package feeds

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/knt048/vedette/core/productid"
)

// The CVE Program's list of CNAs (CNAsList.json, the list cve.org shows as its partners): per CNA its short name (a CVE record's
// assignerShortName), its organization name, its scope in words and its types (Vendor, Open Source, Researcher, CERT, Bug Bounty
// Provider, Hosted Service, ...). ownCNA reads it to tell that a record's CNA is the organization that makes the product, where its
// short name alone does not say so ("zz" of "Zenith Widgets, Inc."). Nothing about a vendor or a CNA is written down by hand.

// cnaMaxShort and cnaMaxOrg bound an entry's short name and organization name (the list's longest: 30 and 88 bytes).
const (
	cnaMaxShort = 64
	cnaMaxOrg   = 200
)

// cnaRow is what is kept of a CNA of the list (feeds_cna): its short name in lower case, its organization name as the list writes it,
// and whether it may be the vendor of what it assigns (cnaMayBeVendor).
type cnaRow struct {
	Short, Org string
	Vendor     bool
}

// orgNamesVendor says one form of a CNA's organization name (cnaOrgForms) is the vendor's name.
func orgNamesVendor(org, vendor string) bool {
	if org == "" {
		return false
	}
	forms := orgFormsOf(org)
	for _, v := range []string{productid.Norm(vendor), productid.NormVendor(vendor)} {
		if v != "" && slices.Contains(forms, v) {
			return true
		}
	}
	return false
}

// orgForms keeps cnaOrgForms of each organization read: a few hundred names, asked once per range row.
var orgForms sync.Map

func orgFormsOf(org string) []string {
	if f, ok := orgForms.Load(org); ok {
		return f.([]string)
	}
	f := cnaOrgForms(org)
	orgForms.Store(org, f)
	return f
}

// rawCNA is the part of a list entry that is read.
type rawCNA struct {
	ShortName        string `json:"shortName"`
	OrganizationName string `json:"organizationName"`
	Scope            string `json:"scope"`
	CNA              struct {
		Type []string `json:"type"`
	} `json:"CNA"`
}

// parseCNAList reads the list, at most maxBytes. It is refused whole when it is longer, is not one JSON array, or holds no usable
// entry; an entry without a short name or organization, or with one over its bound, is passed over, and so is a short name two
// entries share whatever its case (it does not say which organization a record's assigner is). The rows come sorted by short name.
func parseCNAList(r io.Reader, maxBytes int64) ([]cnaRow, error) {
	lr := &io.LimitedReader{R: r, N: maxBytes + 1}
	dec := json.NewDecoder(lr)
	var raw []rawCNA
	if err := dec.Decode(&raw); err != nil {
		if lr.N <= 0 {
			return nil, fmt.Errorf("feeds: CNA list over %d bytes", maxBytes)
		}
		return nil, fmt.Errorf("feeds: CNA list: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("feeds: CNA list: more than one JSON value")
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("feeds: CNA list over %d bytes", maxBytes)
	}
	byShort := map[string]cnaRow{}
	shared := map[string]bool{}
	for _, c := range raw {
		short, org := strings.ToLower(strings.TrimSpace(c.ShortName)), strings.TrimSpace(c.OrganizationName)
		if short == "" || org == "" || len(short) > cnaMaxShort || len(org) > cnaMaxOrg || !utf8.ValidString(short+org) {
			continue
		}
		if _, dup := byShort[short]; dup || shared[short] {
			delete(byShort, short)
			shared[short] = true
			continue
		}
		byShort[short] = cnaRow{Short: short, Org: org, Vendor: cnaMayBeVendor(c.CNA.Type, c.Scope)}
	}
	if len(byShort) == 0 {
		return nil, errors.New("feeds: CNA list holds no usable entry")
	}
	out := make([]cnaRow, 0, len(byShort))
	for _, k := range slices.Sorted(maps.Keys(byShort)) {
		out = append(out, byShort[k])
	}
	return out, nil
}

// cnaCoordinator is a scope that defines itself against other CNAs' scopes: "vulnerabilities discovered by X that are not in another
// CNA's scope", "unless covered by the scope of another CNA", "outside the scope of another CNA", "not covered by a more specific CNA".
// The list words this in many ways; whatever the words, a CNA of such a scope may assign for products of others, so its name equal to
// an entry's vendor is not taken as its own word on its products. A vendor whose scope only mentions other CNAs loses nothing but the
// list's help: its short name rules still stand.
var cnaCoordinator = regexp.MustCompile(`(?i)\b(?:another|any\s+other|other|a\s+more\s+specific)\s+cnas?\b`)

// cnaMayBeVendor says a CNA may be the vendor of what it assigns: the list types it as a vendor or an open-source project, and its
// scope does not define itself against other CNAs' scopes (cnaCoordinator). A researcher, CERT, bug bounty or hosting CNA never is.
func cnaMayBeVendor(types []string, scope string) bool {
	maker := slices.ContainsFunc(types, func(t string) bool {
		t = strings.ToLower(strings.TrimSpace(t))
		return t == "vendor" || t == "open source"
	})
	return maker && !cnaCoordinator.MatchString(scope)
}

// legalForms are the words a company's legal form adds at the end of its name, in the languages of the CNAs' organizations ("Inc.",
// "GmbH", "S.A.", "AB", "spol. s r.o."), besides productid's company words.
var legalForms = map[string]bool{
	"ab": true, "ag": true, "aps": true, "as": true, "asa": true, "bv": true, "co": true, "corp": true, "corporation": true,
	"gmbh": true, "ggmbh": true, "inc": true, "incorporated": true, "kft": true, "kg": true, "kgaa": true, "kk": true, "llc": true,
	"llp": true, "lp": true, "ltd": true, "ltda": true, "limited": true, "nv": true, "oy": true, "oyj": true, "pbc": true, "plc": true,
	"pte": true, "pty": true, "pvt": true, "sa": true, "sarl": true, "sas": true, "se": true, "sl": true, "slu": true, "spa": true,
	"spol": true, "sro": true, "srl": true, "company": true,
}

var parenthesised = regexp.MustCompile(`\([^()]*\)`)

// cnaOrgForms is every form of an organization name a record's vendor may write it in, each as productid.Norm would: the name with
// and without its parts in parentheses ("Helix Robotics AB (HXR)") and a leading "The", then with each trailing legal-form or company
// word dropped in turn, keeping at least one word ("Zenith Widgets, Inc." is "zenithwidgetsinc" and "zenithwidgets"). Letters a legal
// form writes one by one ("S.A.", "s.r.o.") are one word.
func cnaOrgForms(org string) []string {
	var out []string
	for _, name := range []string{org, parenthesised.ReplaceAllString(org, " ")} {
		words := orgWords(name)
		for _, ws := range [][]string{words, dropThe(words)} {
			for n := len(ws); n >= 1; n-- {
				if f := strings.Join(ws[:n], ""); !slices.Contains(out, f) {
					out = append(out, f)
				}
				if n == 1 || !legalForms[ws[n-1]] && !companyWord(ws[n-1]) {
					break
				}
			}
		}
	}
	return out
}

// companyWord says productid.NormVendor drops the word at the end of a vendor's name.
func companyWord(w string) bool { return productid.NormVendor("x "+w) == "x" }

func dropThe(ws []string) []string {
	if len(ws) > 1 && ws[0] == "the" {
		return ws[1:]
	}
	return ws
}

// orgWords is the [a-z0-9] words of a name, letters written one by one joined into one word ("s.r.o." is "sro").
func orgWords(s string) []string {
	var out []string
	single := false
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') }) {
		if len(w) == 1 && single {
			out[len(out)-1] += w
			continue
		}
		out = append(out, w)
		single = len(w) == 1
	}
	return out
}

// The feed of the CNA list.
const (
	cnaFeedID = "cve-cna-list"
	// DecoderCNAList is the decoder of the CVE Program's CNA list (parseCNAList).
	DecoderCNAList Decoder = "cve-cna-list"
	// cnaListURL is the list as the CVE Program's website (cve.org, Partner Information) publishes it, from the branch the site runs.
	cnaListURL = "https://raw.githubusercontent.com/CVEProject/cve-website/main/src/assets/data/CNAsList.json"
	// cnaMaxBytes caps the list (about 0.8 MB with 570 CNAs in 2026).
	cnaMaxBytes = 2_000_000
	// cnaListFreshDays is how long after the feed's last good pull the list is still read (ownCNA); the feed pulls every 7 days.
	cnaListFreshDays = "30"
	// cnaNotice is the licence line of the feed.
	cnaNotice = "CVE Program Terms of Use (cve.org). Facts only: each CNA's short name, organization name and whether it may be a vendor; no contact data."
)

// buildCNAList pulls the CNA list, conditional on the last good pull's ETag and Last-Modified. A list with fewer than half the CNAs
// of the list stored is refused (a cut or broken file), and the stored list stays.
func (s *Service) buildCNAList(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	req := Request{URL: src.URL, MaxBytes: cnaMaxBytes}
	if src.Status == "ok" {
		req.ETag, req.LastModified = orEmpty(src.ETag), orEmpty(src.LastModified)
	}
	resp, err := s.get(ctx, req)
	if err != nil {
		return p, err
	}
	if resp.NotModified {
		p.out = outcome{OK: true, NotModified: true, ETag: req.ETag, LastModif: req.LastModified}
		return p, nil
	}
	rows, err := parseCNAList(bytes.NewReader(resp.Body), cnaMaxBytes)
	if err != nil {
		return p, fail(ErrBadSample, "The CVE Program's CNA list could not be read; the stored list was kept.")
	}
	var have int
	if err := s.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM feeds_cna WHERE source_id = ?`, src.ID).Scan(&have); err != nil {
		return p, fmt.Errorf("feeds: count CNAs: %w", err)
	}
	if len(rows)*2 < have {
		return p, fail(ErrBadSample, "The CVE Program's CNA list holds %d CNAs, fewer than half of the %d stored; the stored list was kept.", len(rows), have)
	}
	p.out = outcome{OK: true, Bytes: len(resp.Body), ETag: resp.ETag, LastModif: resp.LastModified, Records: len(rows), Accepted: len(rows)}
	p.cnas, p.hasCNAs = rows, true
	return p, nil
}

// applyCNAList replaces the stored CNA list with rows; changed says whether what ownCNA reads changed (a CNA added, removed, renamed,
// or typed otherwise), so findings matches again.
func applyCNAList(ctx context.Context, tx *sql.Tx, sourceID string, rows []cnaRow) (changed bool, err error) {
	sig := func(rs []cnaRow) string {
		var b strings.Builder
		for _, r := range rs {
			fmt.Fprintf(&b, "%s\x1f%s\x1f%t\x1e", r.Short, r.Org, r.Vendor)
		}
		return b.String()
	}
	var before []cnaRow
	q, err := tx.QueryContext(ctx, `SELECT short_name, organization, may_be_vendor FROM feeds_cna WHERE source_id = ? ORDER BY short_name`, sourceID)
	if err != nil {
		return false, fmt.Errorf("feeds: read CNAs: %w", err)
	}
	for q.Next() {
		var r cnaRow
		if err := q.Scan(&r.Short, &r.Org, &r.Vendor); err != nil {
			_ = q.Close()
			return false, fmt.Errorf("feeds: read CNAs: %w", err)
		}
		before = append(before, r)
	}
	if err := errors.Join(q.Err(), q.Close()); err != nil {
		return false, fmt.Errorf("feeds: read CNAs: %w", err)
	}
	if sig(before) == sig(rows) {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_cna WHERE source_id = ?`, sourceID); err != nil {
		return false, fmt.Errorf("feeds: clear CNAs: %w", err)
	}
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_cna (short_name, source_id, organization, may_be_vendor) VALUES (?, ?, ?, ?)`,
			r.Short, sourceID, r.Org, boolInt(r.Vendor)); err != nil {
			return false, fmt.Errorf("feeds: store CNA: %w", err)
		}
	}
	return true, nil
}
