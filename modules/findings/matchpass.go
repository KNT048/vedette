package findings

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// The match pass compares every device with every CVE of the catalogue that names a product it runs, in one pass: the exploited
// lists' entries and every other catalogue CVE alike. A CVE that matches with version evidence is a finding whatever its urgency;
// the urgency of the finding says how much it matters. There is no second list and no plan kept in memory.

// MatchScope is what the devices run, as the match pass asks the catalogue for it (Feeds.MatchSet): the products their software lines
// are known by (CPE, inventory name, aliases, the names a CVE record writes), and the CVEs findings holds a finding for
// (Pinned), which are compared whatever the devices run now, so a finding whose software went is judged gone.
type MatchScope struct {
	keys    map[string]bool // productid.NormKey of vendor and product
	prefix  []identity      // aliases that match every product starting with them
	windows bool            // a Windows release row: every Microsoft Windows product
	records map[string]bool // the lines' names as a CVE record writes them (recordIdentity)
	// Pinned are the CVEs of the findings the devices have (any state).
	Pinned []string
}

// DistroPackage is a source package of one release as the distributions' security data names it.
type DistroPackage struct{ Distro, Release, Package string }

// NewMatchScope collects the products of every software line of assets, the network OS they state included.
func NewMatchScope(assets []Asset, pinned []string) MatchScope {
	sc := MatchScope{keys: map[string]bool{}, records: map[string]bool{}, Pinned: pinned}
	for _, a := range assets {
		for _, s := range deviceSoftware(a) {
			in := newSWInfo(s, a.OS)
			if _, win := winDevice(in); win {
				sc.windows = true
			}
			if in.hasCPE {
				v, _ := in.cpe.Vendor.Literal()
				p, _ := in.cpe.Product.Literal()
				sc.keys[productid.NormKey(v, p)] = true
			}
			for _, id := range in.ids {
				if id.record {
					sc.records[productid.NormKey(id.vendor, id.product)] = true
					continue
				}
				if id.prefix {
					sc.prefix = append(sc.prefix, id)
					continue
				}
				sc.keys[productid.NormKey(id.vendor, id.product)] = true
			}
		}
	}
	return sc
}

// Keep says whether a catalogue range names a product of the scope: vendor and product as the matcher reads the range (a CPE's
// names, or a CVE record's product key as the catalogue resolves it, feeds' MatchName); record says the range is a CVE record's
// without a CPE, which also reaches a line by the names a record writes (recordIdentity).
func (sc MatchScope) Keep(vendor, product string, record bool) bool {
	v, p := productid.Norm(vendor), productid.Norm(product)
	if v == "" || p == "" {
		return false
	}
	if record && sc.records[productid.NormKey(v, p)] {
		return true
	}
	if sc.keys[productid.NormKey(v, p)] || sc.windows && v == "microsoft" && strings.HasPrefix(p, "windows") {
		return true
	}
	for _, id := range sc.prefix {
		if id.matches(v, p) {
			return true
		}
	}
	return false
}

// Empty says the devices run nothing a range could name.
func (sc MatchScope) Empty() bool { return len(sc.keys) == 0 && len(sc.prefix) == 0 && !sc.windows }

// matchSet is the list one pass compares with, indexed so that each device is compared only with the entries that can concern it:
// every exploited-list entry (CISA's key reaches a row by its name) and the catalogue CVEs whose ranges name a vendor of one of its
// rows.
type matchSet struct {
	vulns    []Vuln
	listed   []int            // entries of an exploited list (Vendor set)
	byVendor map[string][]int // normalised CPE vendor -> entries of the catalogue naming it
}

func newMatchSet(vulns []Vuln) *matchSet {
	m := &matchSet{vulns: vulns, byVendor: map[string][]int{}}
	for i, v := range vulns {
		if v.Vendor != "" || v.Product != "" || len(v.Affected) == 0 {
			m.listed = append(m.listed, i)
			continue
		}
		for _, af := range v.Affected {
			if vn := cpeVendor(af); vn != "" {
				if l := m.byVendor[vn]; len(l) == 0 || l[len(l)-1] != i {
					m.byVendor[vn] = append(l, i)
				}
			}
		}
	}
	return m
}

// forDevice is the entries the matcher reads for a, in list order.
func (m *matchSet) forDevice(a Asset) []Vuln {
	if len(m.listed) == len(m.vulns) {
		return m.vulns
	}
	at := slices.Clone(m.listed)
	seen := map[string]bool{}
	for _, s := range deviceSoftware(a) {
		for _, vn := range rowVendors(s) {
			if seen[vn] {
				continue
			}
			seen[vn] = true
			at = append(at, m.byVendor[vn]...)
		}
	}
	slices.Sort(at)
	at = slices.Compact(at)
	out := make([]Vuln, len(at))
	for i, x := range at {
		out[i] = m.vulns[x]
	}
	return out
}

// pinnedCVEs is the CVEs findings holds a finding for (any state), sorted: the catalogue keeps them whatever their age (feeds'
// retention rule) and the match pass compares them whatever the devices run now.
func (s *Service) pinnedCVEs(ctx context.Context, assetID string) ([]string, error) {
	q, args := `SELECT DISTINCT cve FROM fnd_finding ORDER BY cve`, []any{}
	if assetID != "" {
		q, args = `SELECT DISTINCT cve FROM fnd_finding WHERE asset_id = ? ORDER BY cve`, []any{assetID}
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the CVEs of the findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("findings: reading the CVEs of the findings: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PinnedCVEs is the CVEs any finding references (open or handled), read from db: feeds' catalogue keeps them whatever their age
// (feeds Deps.Pins), so nothing ages out from under a finding, its history or a report (selfcheck findings.cve_in_catalogue).
func PinnedCVEs(ctx context.Context, db *store.DB) ([]string, error) {
	rows, err := db.Reader().QueryContext(ctx, `SELECT DISTINCT cve FROM fnd_finding ORDER BY cve`)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the CVEs of the open findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("findings: reading the CVEs of the open findings: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
