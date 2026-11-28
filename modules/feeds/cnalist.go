package feeds

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

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

// cnaList is the CNAs of the list by short name (lower case). A short name two CNAs share, whatever its case, is left out: it does
// not say which organization a record's assigner is.
type cnaList struct {
	entries map[string]cnaEntry
}

// cnaEntry is what is kept of a CNA: the forms of its organization name (cnaOrgForms) and whether it may be the vendor of what it
// assigns (cnaMayBeVendor).
type cnaEntry struct {
	orgs   []string
	vendor bool
}

func (l *cnaList) len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

// orgIsVendor says the list holds the assigner as a CNA that may be a vendor and one form of its organization name is the vendor's.
func (l *cnaList) orgIsVendor(assigner, vendor string) bool {
	if l == nil {
		return false
	}
	e, ok := l.entries[strings.ToLower(strings.TrimSpace(assigner))]
	if !ok || !e.vendor {
		return false
	}
	for _, v := range []string{productid.Norm(vendor), productid.NormVendor(vendor)} {
		if v != "" && slices.Contains(e.orgs, v) {
			return true
		}
	}
	return false
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
// entry; an entry without a short name or organization, or with one over its bound, is passed over.
func parseCNAList(r io.Reader, maxBytes int64) (*cnaList, error) {
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
	l := &cnaList{entries: map[string]cnaEntry{}}
	shared := map[string]bool{}
	for _, c := range raw {
		short, org := strings.ToLower(strings.TrimSpace(c.ShortName)), strings.TrimSpace(c.OrganizationName)
		if short == "" || org == "" || len(short) > cnaMaxShort || len(org) > cnaMaxOrg {
			continue
		}
		if _, dup := l.entries[short]; dup || shared[short] {
			delete(l.entries, short)
			shared[short] = true
			continue
		}
		l.entries[short] = cnaEntry{orgs: cnaOrgForms(org), vendor: cnaMayBeVendor(c.CNA.Type, c.Scope)}
	}
	if len(l.entries) == 0 {
		return nil, errors.New("feeds: CNA list holds no usable entry")
	}
	return l, nil
}

// cnaCoordinator is a scope that takes the reports no other CNA covers: "vulnerabilities discovered by X that are not in another CNA's
// scope", "not within another CNA's scope", "not covered by the scope of another CNA". A CNA of such a scope assigns for products of
// others, so its name equal to an entry's vendor is not taken as its own word on its products.
var cnaCoordinator = regexp.MustCompile(`(?i)\bnot\s+(?:already\s+)?(?:in|within|covered\s+by|part\s+of)\s+(?:the\s+scope\s+of\s+)?(?:another|any\s+other|other)\s+cnas?\b`)

// cnaMayBeVendor says a CNA may be the vendor of what it assigns: the list types it as a vendor or an open-source project, and its
// scope does not take the reports of other CNAs' products (cnaCoordinator). A researcher, CERT, bug bounty or hosting CNA never is.
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
