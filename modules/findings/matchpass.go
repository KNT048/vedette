package findings

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

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
	// Packages are the devices' distribution packages as the distributions' security data names them (DevicePackages): a CVE a
	// distribution fixed in one of them is compared even before NVD names the upstream product.
	Packages []DistroPackage
}

// DistroPackage is a source package of one release as the distributions' security data names it.
type DistroPackage struct{ Distro, Release, Package string }

// NewMatchScope collects the products of every software line of assets, the network OS they state included.
func NewMatchScope(assets []Asset, pinned []string) MatchScope {
	sc := MatchScope{keys: map[string]bool{}, records: map[string]bool{}, Pinned: pinned}
	seenPkg := map[DistroPackage]bool{}
	for _, a := range assets {
		if d, rel, pkgs := DevicePackages(a); d != "" {
			for _, p := range pkgs {
				if k := (DistroPackage{Distro: d, Release: rel, Package: p}); !seenPkg[k] {
					seenPkg[k] = true
					sc.Packages = append(sc.Packages, k)
				}
			}
		}
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

// Empty says the devices run nothing a range or a distribution's data could name.
func (sc MatchScope) Empty() bool {
	return len(sc.keys) == 0 && len(sc.prefix) == 0 && !sc.windows && len(sc.Packages) == 0
}

// matchSet is the list one pass compares with, indexed so that each device is compared only with the entries that can concern it:
// every exploited-list entry (CISA's key reaches a row by its name) and the catalogue CVEs whose ranges name a vendor of one of its
// rows.
type matchSet struct {
	vulns    []Vuln
	listed   []int            // entries of an exploited list (Vendor set)
	byVendor map[string][]int // normalised CPE vendor -> entries of the catalogue naming it
	// backlog and recent are the CVEs of the set's backlog and recent entries (Service.judgedParts), split once per pass.
	splitOnce       sync.Once
	backlog, recent map[string]bool
	// hashes are the entries' hashes for the match stamps (entryHash), computed when first asked; hashed[i]: 1 done, 2 not hashable.
	hashes [][32]byte
	hashed []uint8
}

// entryHash is a hash of every field of entry i (matchStamp); ok is false when it cannot be encoded.
func (m *matchSet) entryHash(i int) ([32]byte, bool) {
	if m.hashes == nil {
		m.hashes, m.hashed = make([][32]byte, len(m.vulns)), make([]uint8, len(m.vulns))
	}
	switch m.hashed[i] {
	case 1:
		return m.hashes[i], true
	case 2:
		return [32]byte{}, false
	}
	b, err := json.Marshal(m.vulns[i])
	if err != nil {
		m.hashed[i] = 2
		return [32]byte{}, false
	}
	m.hashes[i], m.hashed[i] = sha256.Sum256(b), 1
	return m.hashes[i], true
}

func newMatchSet(vulns []Vuln) *matchSet {
	m := &matchSet{vulns: vulns, byVendor: map[string][]int{}}
	for i, v := range vulns {
		if v.Vendor != "" || v.Product != "" || len(entryVendors(v)) == 0 {
			m.listed = append(m.listed, i)
			continue
		}
		for _, vn := range entryVendors(v) {
			if l := m.byVendor[vn]; len(l) == 0 || l[len(l)-1] != i {
				m.byVendor[vn] = append(l, i)
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
	if out := pick(m.vulns, m.devIdx(a)); out != nil {
		return out
	}
	return []Vuln{}
}

// devIdx is forDevice as indexes into the set.
func (m *matchSet) devIdx(a Asset) []int {
	if len(m.listed) == len(m.vulns) {
		at := make([]int, len(m.vulns))
		for i := range at {
			at[i] = i
		}
		return at
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
	return slices.Compact(at)
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
