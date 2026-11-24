package findings

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/apkver"
	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/versionscheme"
)

// The Findings lists: By device and By fix are two GROUP BYs of the same open rows, so their totals are equal by construction (open
// findings = Σ by device = Σ by fix). The database groups the rows by (device, software line, fix key); the read then combines the
// fixes of one product on one line into one block, so the CVEs of one software that need different releases do not split it
// ("Update OpenSSH 10.2p1 → 10.6: fixes 25 CVEs"). An update block names the lowest release that clears every CVE it lists
// (blocktarget.go); other kinds the newest fix release of the group. Both lists, Home, the report and the handling of one fix on one
// device read the same combination.

// ListFilter is what a list of findings shows: open statuses (layers), one device or a set of devices, the ignored devices only or
// none of them, a search, one CVE.
type ListFilter struct {
	Layers  []int
	Device  string
	Devices []string // nil: every device; else only these (an empty set selects nothing)
	Ignored bool     // true: only the devices a person ignored; false: none of them
	Q       string
	CVE     string // "": every CVE; else only the findings of exactly this CVE (the blocks stay the ones the list shows without it)
}

// Page is one page of a list.
type Page struct{ Offset, Limit int }

// The page sizes of the lists (contract.ts PAGE_DEFAULT, PAGE_MAX).
const (
	PageDefault = 20
	PageMax     = 100
)

type readKey struct{}

// readTx runs fn with one read transaction in its context: every read of one answer (the grouping, the rows of the page, the device
// counts) sees one state of the findings, so a write between two reads cannot leave a page without its rows.
func (s *Service) readTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(readKey{}).(*sql.Tx); ok {
		return fn(ctx)
	}
	tx, err := s.cfg.DB.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("findings: starting a read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	return fn(context.WithValue(ctx, readKey{}, tx))
}

// rd is the read handle of ctx: its read transaction (readTx), else the reader pool.
func (s *Service) rd(ctx context.Context) querier {
	if tx, ok := ctx.Value(readKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.cfg.DB.Reader()
}

// ParsePage reads the offset and limit of a list (the API validated their shape): limit 0 is the default, above the largest the largest.
func ParsePage(offset, limit string) Page {
	p := Page{Limit: PageDefault}
	if n, err := strconv.Atoi(offset); err == nil && n > 0 {
		p.Offset = n
	}
	if n, err := strconv.Atoi(limit); err == nil && n > 0 {
		p.Limit = min(n, PageMax)
	}
	return p
}

func (p Page) cut(n int) (lo, hi int) {
	lo = min(p.Offset, n)
	return lo, min(lo+p.Limit, n)
}

// where is the condition of the rows of state that the device, ignored and search parts of f select, and the condition of the
// statuses (layers) within them ("" when none).
func (s *Service) where(ctx context.Context, state State, f ListFilter) (rows string, rowArgs []any, status string, statusArgs []any, err error) {
	ignored, err := s.cfg.Inventory.IgnoredIDs(ctx)
	if err != nil {
		return "", nil, "", nil, fmt.Errorf("findings: reading the ignored devices: %w", err)
	}
	ig, _ := json.Marshal(nonNilStrings(ignored))
	conds := []string{`state = ?`}
	rowArgs = []any{string(state)}
	if f.Ignored {
		conds = append(conds, `asset_id IN (SELECT value FROM json_each(?))`)
	} else {
		conds = append(conds, `asset_id NOT IN (SELECT value FROM json_each(?))`)
	}
	rowArgs = append(rowArgs, string(ig))
	if f.Device != "" {
		conds, rowArgs = append(conds, `asset_id = ?`), append(rowArgs, f.Device)
	}
	if f.Devices != nil {
		ds, _ := json.Marshal(nonNilStrings(f.Devices))
		conds, rowArgs = append(conds, `asset_id IN (SELECT value FROM json_each(?))`), append(rowArgs, string(ds))
	}
	rows = strings.Join(conds, " AND ")
	var sc []string
	if len(f.Layers) > 0 {
		ls, _ := json.Marshal(f.Layers)
		sc, statusArgs = append(sc, `urgency IN (SELECT value FROM json_each(?))`), append(statusArgs, string(ls))
	}
	if f.CVE != "" { // like the search: it selects rows inside the blocks, it does not change how they are combined
		sc, statusArgs = append(sc, `cve = ?`), append(statusArgs, f.CVE)
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		cond, args, err := s.search(ctx, rows, rowArgs, q)
		if err != nil {
			return "", nil, "", nil, err
		}
		sc, statusArgs = append(sc, cond), append(statusArgs, args...)
	}
	return rows, rowArgs, strings.Join(sc, " AND "), statusArgs, nil
}

// search is the condition of a search: the CVE id, the device's name or address, or the software line's name contains q (any case).
func (s *Service) search(ctx context.Context, rows string, args []any, q string) (string, []any, error) {
	r, err := s.rd(ctx).QueryContext(ctx, `SELECT DISTINCT asset_id, ifnull(software_id, '') FROM fnd_finding WHERE `+rows, args...)
	if err != nil {
		return "", nil, fmt.Errorf("findings: search: %w", err)
	}
	assets, lines := map[string]bool{}, map[string]bool{}
	for r.Next() {
		var a, l string
		if err := r.Scan(&a, &l); err != nil {
			_ = r.Close()
			return "", nil, fmt.Errorf("findings: search: %w", err)
		}
		assets[a] = true
		if l != "" {
			lines[l] = true
		}
	}
	if err := errors.Join(r.Err(), r.Close()); err != nil {
		return "", nil, fmt.Errorf("findings: search: %w", err)
	}
	low := strings.ToLower(q)
	var hitAssets, hitLines []string
	if len(assets) > 0 {
		as, err := s.cfg.Inventory.Assets(ctx, keys(assets))
		if err != nil {
			return "", nil, fmt.Errorf("findings: search: reading devices: %w", err)
		}
		for id, a := range as {
			a = shownAsset(a)
			if strings.Contains(strings.ToLower(a.Name), low) || a.HasIP() && strings.Contains(a.IP, low) {
				hitAssets = append(hitAssets, id)
			}
		}
	}
	if len(lines) > 0 {
		ls, err := s.cfg.Inventory.Lines(ctx, keys(lines))
		if err != nil {
			return "", nil, fmt.Errorf("findings: search: reading software lines: %w", err)
		}
		for id, l := range ls {
			if strings.Contains(strings.ToLower(l.Display), low) {
				hitLines = append(hitLines, id)
			}
		}
	}
	ha, _ := json.Marshal(nonNilStrings(hitAssets))
	hl, _ := json.Marshal(nonNilStrings(hitLines))
	like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToUpper(q)) + "%"
	return `(cve LIKE ? ESCAPE '\' OR asset_id IN (SELECT value FROM json_each(?)) OR software_id IN (SELECT value FROM json_each(?)))`,
		[]any{like, string(ha), string(hl)}, nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// lineGroup is the open findings of one device, software line and stored fix key: all of them (for the combination) and those the
// list's statuses and search select (N, Urgency: their count and most urgent layer; 0 when none).
type lineGroup struct {
	Asset, Software, Product, Key string
	Fix                           Fix
	All, N, Urgency               int
	Block                         string // the combined fix key the group is listed under
	BlockFix                      Fix
}

// lineGroups groups the open rows of f's devices by (device, line, fix key) and combines them into blocks.
func (s *Service) lineGroups(ctx context.Context, f ListFilter) ([]lineGroup, error) {
	rows, args, status, sargs, err := s.where(ctx, StateOpen, f)
	if err != nil {
		return nil, err
	}
	sel := "1"
	if status != "" {
		sel = "(" + status + ")"
	}
	q := `SELECT asset_id, ifnull(software_id, ''), fix_kind, ifnull(fix_version, ''), ifnull(fix_ref, ''), fix_key, count(*),
		sum(CASE WHEN ` + sel + ` THEN 1 ELSE 0 END), ifnull(min(CASE WHEN ` + sel + ` THEN urgency END), 0)
		FROM fnd_finding WHERE ` + rows + ` GROUP BY asset_id, ifnull(software_id, ''), fix_key ORDER BY asset_id, 2, fix_key`
	all := append(append(append([]any{}, sargs...), sargs...), args...)
	r, err := s.rd(ctx).QueryContext(ctx, q, all...)
	if err != nil {
		return nil, fmt.Errorf("findings: grouping open findings: %w", err)
	}
	var out []lineGroup
	for r.Next() {
		var g lineGroup
		var kind string
		if err := r.Scan(&g.Asset, &g.Software, &kind, &g.Fix.Version, &g.Fix.Ref, &g.Key, &g.All, &g.N, &g.Urgency); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("findings: grouping open findings: %w", err)
		}
		g.Fix.Kind = FixKind(kind)
		g.Product = productPart(Finding{FixKey: g.Key, Fix: g.Fix})
		out = append(out, g)
	}
	if err := errors.Join(r.Err(), r.Close()); err != nil {
		return nil, fmt.Errorf("findings: grouping open findings: %w", err)
	}
	j, err := s.releaseJudge(ctx, out, rows, args)
	if err != nil {
		return nil, err
	}
	combine(out, j)
	return out, nil
}

// combine sets the block of each group: the groups of one device, line, product and fix kind with a version combine when every
// version of them compares with the others; otherwise (or for a kind without a version) a group is its own block. Updates to
// different releases get the lowest release that clears every CVE (planReleases, with j's ranges; nil: each CVE cleared by its own
// fix and any later release), the other kinds the newest version of them.
func combine(gs []lineGroup, j *releaseJudge) {
	type bucket struct {
		asset, software, product string
		kind                     FixKind
	}
	idx := map[bucket][]int{}
	for i := range gs {
		gs[i].Block, gs[i].BlockFix = blockKey(gs[i].Product, gs[i].Fix), gs[i].Fix
		if gs[i].Fix.Version == "" {
			continue
		}
		b := bucket{gs[i].Asset, gs[i].Software, gs[i].Product, gs[i].Fix.Kind}
		idx[b] = append(idx[b], i)
	}
	for b, is := range idx {
		if len(is) < 2 {
			continue
		}
		top := is[0]
		ok := true
		for _, i := range is[1:] {
			c, same := compareFix(b.kind, b.product, gs[i].Fix.Version, gs[top].Fix.Version)
			if !same {
				ok = false
				break
			}
			if c > 0 {
				top = i
			}
		}
		if !ok {
			continue
		}
		if b.kind == FixUpdate && slices.ContainsFunc(is, func(i int) bool { return gs[i].Fix.Version != gs[top].Fix.Version }) {
			planReleases(gs, is, b.product, j)
			continue
		}
		fx := gs[top].Fix
		key := blockKey(b.product, fx)
		for _, i := range is {
			gs[i].Block, gs[i].BlockFix = key, fx
		}
	}
}

// blockKey is the key a block of product's fix is listed under: the fix key of the catalogue's product, so lines that name one product
// in two ways (Oracle's Java SE and Eclipse Temurin are both Java) are one row of By fix, as their one title says ("Update Java to
// 21.0.13.1"). A product the catalogue does not know keeps the line's own key.
func blockKey(product string, fx Fix) string {
	if p, ok := productOfKey(product); ok && p.Key != "" {
		product = p.Key
	}
	return FixKey(product, fx)
}

// compareFix orders two fix versions of one kind of product (a line's product key); false when they do not compare (two strings the
// order calls equal do not either: "7.0.0 build 1234" and "7.0.0" are not one release to install). An update the generic order cannot
// read is a release in the vendor's notation ("8.0 U3d (build 24585383)", "7.2.1-69057 Update 6"): the product's version scheme
// orders it (schemeOrder). Whether a later release also clears a CVE is not read from the order: the vendor's rows decide it
// (releaseJudge).
func compareFix(kind FixKind, product, a, b string) (int, bool) {
	if a == b {
		return 0, true
	}
	if kind == FixDistroUpdate {
		if debver.Valid(a) && debver.Valid(b) {
			c, err := debver.Compare(a, b)
			return c, err == nil && c != 0
		}
		if va, ok := apkver.Parse(a); ok {
			if vb, ok := apkver.Parse(b); ok {
				c := apkver.Compare(va, vb)
				return c, c != 0
			}
		}
		return 0, false
	}
	c, ok := CompareVersions(a, b)
	if (!ok || c == 0) && kind == FixUpdate {
		return schemeOrder(product, a, b)
	}
	return c, ok && c != 0
}

// schemeOrder orders two releases of product's version scheme in release order (line, train, place inside the train), read as their
// names; false without a scheme or for a name it does not read.
func schemeOrder(product, a, b string) (int, bool) {
	s := productScheme(product)
	if s == nil {
		return 0, false
	}
	va, okA := s.Release(a)
	vb, okB := s.Release(b)
	if !okA || !okB {
		return 0, false
	}
	c, ok := versionscheme.Compare(va, vb)
	return c, ok && c != 0
}

// productScheme is the version scheme the catalogue declares for a line's product key; nil when none.
func productScheme(product string) *versionscheme.Scheme {
	p, ok := productOfKey(product)
	if !ok || p.Scheme == "" {
		return nil
	}
	s, _ := versionscheme.Lookup(p.Scheme)
	return s
}

// blockOf maps a (device, line, stored fix key) to the block it is listed under and the fix the block names.
type blockOf map[[3]string]lineGroup

func blocksOf(gs []lineGroup) blockOf {
	m := blockOf{}
	for _, g := range gs {
		m[[3]string{g.Asset, g.Software, g.Key}] = g
	}
	return m
}

func (m blockOf) of(f Finding) (string, Fix) {
	if g, ok := m[[3]string{f.AssetID, f.SoftwareID, f.FixKey}]; ok {
		return g.Block, g.BlockFix
	}
	return f.FixKey, f.Fix
}

// listRows reads the open findings of f on these devices that the statuses and search select, most urgent first.
func (s *Service) listRows(ctx context.Context, f ListFilter, assets []string) ([]Finding, error) {
	rows, args, status, sargs, err := s.where(ctx, StateOpen, f)
	if err != nil {
		return nil, err
	}
	as, _ := json.Marshal(nonNilStrings(assets))
	w := rows + ` AND asset_id IN (SELECT value FROM json_each(?))`
	args = append(args, string(as))
	if status != "" {
		w += ` AND ` + status
		args = append(args, sargs...)
	}
	return selectFindings(ctx, s.rd(ctx), w+` ORDER BY urgency, cve, id`, args...)
}

// SeverityCounts is contract.ts SeverityCounts.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
	Unscored int `json:"unscored"`
}

func (c *SeverityCounts) add(v View) {
	if severityJS(v.Severity) == nil {
		c.Unscored++
		return
	}
	switch SeverityBand(*v.Severity) {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	case "low":
		c.Low++
	default:
		c.None++
	}
}

// StatusCounts is contract.ts StatusCounts: open findings by status.
type StatusCounts struct {
	UnderAttack       int `json:"under_attack"`
	Exploited         int `json:"exploited"`
	PublicExploit     int `json:"public_exploit"`
	CriticalEdge      int `json:"critical_edge"`
	UpdateRecommended int `json:"update_recommended"`
}

func (c *StatusCounts) add(layer, n int) {
	switch layer {
	case UrgencyUnderAttack:
		c.UnderAttack += n
	case UrgencyExploited:
		c.Exploited += n
	case UrgencyPublicExploit:
		c.PublicExploit += n
	case UrgencyCriticalEdge:
		c.CriticalEdge += n
	default:
		c.UpdateRecommended += n
	}
}

// rowOrder orders the findings of a block: the most severe first (no score last), then the most urgent, then the CVE.
func rowOrder(a, b View) int {
	return cmp.Or(cmp.Compare(bandRank(a.Severity), bandRank(b.Severity)), cmp.Compare(score(b.Severity), score(a.Severity)),
		cmp.Compare(a.Finding.Urgency, b.Finding.Urgency), cmp.Compare(a.Finding.CVE, b.Finding.CVE), cmp.Compare(a.Finding.ID, b.Finding.ID))
}

func score(c *CVSS) float64 {
	if c == nil {
		return -1
	}
	return c.Score
}

// causeOf is the finding that gives a set its status: the most urgent, then the most severe, then the CVE.
func causeOf(vs []View) View {
	return slices.MinFunc(vs, func(a, b View) int {
		return cmp.Or(cmp.Compare(a.Finding.Urgency, b.Finding.Urgency), rowOrder(a, b))
	})
}

// FixBlockJS is contract.ts FixBlock.
type FixBlockJS struct {
	Fix      fixJS          `json:"fix"`
	Software *softwareRefJS `json:"software"`
	Status   string         `json:"status"`
	Cause    string         `json:"cause"`
	Severity SeverityCounts `json:"severity"`
	Findings []cveRowJS     `json:"findings"`
	urgency  int
}

// block builds one fix block from its findings (one device, one line, one combined fix).
func block(key string, fx Fix, vs []View) FixBlockJS {
	slices.SortFunc(vs, rowOrder)
	c := causeOf(vs)
	b := FixBlockJS{Fix: fixOf(key, fx, productName(c.Finding, c.Line)), Software: softwareRef(c), Status: LayerCode(c.Finding.Urgency),
		Cause: c.Finding.CVE, Findings: make([]cveRowJS, 0, len(vs)), urgency: c.Finding.Urgency}
	if b.Software != nil && c.Line != nil {
		if v := c.Line.Version; v != "" { // the block names the version the line runs now, each CVE row its own
			b.Software.Version = &v
		}
	}
	for _, v := range vs {
		b.Severity.add(v)
		b.Findings = append(b.Findings, cveRow(v))
	}
	return b
}

// DeviceCardJS is contract.ts DeviceCard.
type DeviceCardJS struct {
	Device   deviceRefJS   `json:"device"`
	Status   *DeviceStatus `json:"status"`
	Counts   StatusCounts  `json:"counts"`
	Findings int           `json:"findings"`
	CVEs     int           `json:"cves"`
	Blocks   []FixBlockJS  `json:"blocks"`
}

// DeviceCards is contract.ts DeviceCards.
type DeviceCards struct {
	Items    []DeviceCardJS `json:"items"`
	Total    int            `json:"total"`
	Findings int            `json:"findings"`
}

// deviceAgg is one device of By device before paging.
type deviceAgg struct {
	asset      string
	n, urgency int
}

// ByDevice is the By device list: one card per device with open findings that f selects, the most urgent first, then the most
// findings, then the name; inside, one block per fix.
func (s *Service) ByDevice(ctx context.Context, f ListFilter, p Page) (DeviceCards, error) {
	var out DeviceCards
	err := s.readTx(ctx, func(ctx context.Context) error {
		var err error
		out, err = s.byDevice(ctx, f, p)
		return err
	})
	return out, err
}

func (s *Service) byDevice(ctx context.Context, f ListFilter, p Page) (DeviceCards, error) {
	gs, err := s.lineGroups(ctx, f)
	if err != nil {
		return DeviceCards{}, err
	}
	byAsset := map[string]*deviceAgg{}
	out := DeviceCards{Items: []DeviceCardJS{}}
	for _, g := range gs {
		if g.N == 0 {
			continue
		}
		d := byAsset[g.Asset]
		if d == nil {
			d = &deviceAgg{asset: g.Asset, urgency: g.Urgency}
			byAsset[g.Asset] = d
		}
		d.n += g.N
		d.urgency = min(d.urgency, g.Urgency)
		out.Findings += g.N
	}
	devs := make([]*deviceAgg, 0, len(byAsset))
	for _, d := range byAsset {
		devs = append(devs, d)
	}
	out.Total = len(devs)
	if len(devs) == 0 {
		return out, nil
	}
	names, err := s.cfg.Inventory.Assets(ctx, keysOf(byAsset))
	if err != nil {
		return DeviceCards{}, fmt.Errorf("findings: reading devices: %w", err)
	}
	slices.SortFunc(devs, func(a, b *deviceAgg) int {
		na, nb := shownName(names, a.asset), shownName(names, b.asset)
		return cmp.Or(cmp.Compare(a.urgency, b.urgency), cmp.Compare(b.n, a.n), cmp.Compare(strings.ToLower(na), strings.ToLower(nb)), cmp.Compare(a.asset, b.asset))
	})
	lo, hi := p.cut(len(devs))
	page := make([]string, 0, hi-lo)
	for _, d := range devs[lo:hi] {
		page = append(page, d.asset)
	}
	cards, err := s.deviceCards(ctx, f, page, blocksOf(gs))
	if err != nil {
		return DeviceCards{}, err
	}
	out.Items = cards
	return out, nil
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func shownName(m map[string]AssetView, id string) string {
	if a, ok := m[id]; ok {
		return shownAsset(a).Name
	}
	return id
}

// deviceCards builds the cards of these devices, in this order.
func (s *Service) deviceCards(ctx context.Context, f ListFilter, assets []string, blocks blockOf) ([]DeviceCardJS, error) {
	fs, err := s.listRows(ctx, f, assets)
	if err != nil {
		return nil, err
	}
	vs, err := s.listViews(ctx, fs)
	if err != nil {
		return nil, err
	}
	statuses, err := s.deviceStatuses(ctx, assets)
	if err != nil {
		return nil, err
	}
	type bk struct{ asset, software, key string }
	groups := map[bk][]View{}
	fixes := map[bk]Fix{}
	byAsset := map[string][]bk{}
	cves := map[string]map[string]bool{}
	counts := map[string]*StatusCounts{}
	found := map[string]int{}
	devices := map[string]AssetView{}
	for _, v := range vs {
		key, fx := blocks.of(v.Finding)
		k := bk{v.Finding.AssetID, v.Finding.SoftwareID, key}
		if _, ok := groups[k]; !ok {
			byAsset[k.asset] = append(byAsset[k.asset], k)
		}
		groups[k] = append(groups[k], v)
		fixes[k] = fx
		if cves[k.asset] == nil {
			cves[k.asset], counts[k.asset] = map[string]bool{}, &StatusCounts{}
		}
		cves[k.asset][v.Finding.CVE] = true
		counts[k.asset].add(v.Finding.Urgency, 1)
		found[k.asset]++
		devices[k.asset] = v.Device
	}
	out := make([]DeviceCardJS, 0, len(assets))
	for _, a := range assets {
		if counts[a] == nil { // no row of the filter on it any more: no card rather than an empty one
			continue
		}
		c := DeviceCardJS{Device: deviceRef(devices[a]), Status: statuses[a], Counts: *counts[a], Findings: found[a], CVEs: len(cves[a])}
		for _, k := range byAsset[a] {
			c.Blocks = append(c.Blocks, block(k.key, fixes[k], groups[k]))
		}
		slices.SortFunc(c.Blocks, func(x, y FixBlockJS) int {
			return cmp.Or(cmp.Compare(x.urgency, y.urgency), cmp.Compare(len(y.Findings), len(x.Findings)), cmp.Compare(x.Fix.Key, y.Fix.Key))
		})
		out = append(out, c)
	}
	var fxs []*fixJS
	var causes []string
	for i := range out {
		for j := range out[i].Blocks {
			fxs, causes = append(fxs, &out[i].Blocks[j].Fix), append(causes, out[i].Blocks[j].Cause)
		}
	}
	s.linkAdvisories(ctx, fxs, causes)
	return out, nil
}

// noFix reports whether a fix names no release to install: the block says "No fix known yet" or "See the vendor advisory", and its link is the
// vendor's advisory.
func noFix(kind string) bool { return kind == string(FixNoneYet) || kind == string(FixUnknown) }

// linkAdvisories gives each fix with no release and no link the vendor's advisory of its cause CVE (fixes[i] is caused by causes[i]),
// as the exploited list links it: the same advisory the finding's page links. Best-effort: without the list a fix keeps no link.
func (s *Service) linkAdvisories(ctx context.Context, fixes []*fixJS, causes []string) {
	want := map[string]bool{}
	for i, fx := range fixes {
		if noFix(fx.Kind) && fx.URL == nil {
			want[causes[i]] = true
		}
	}
	if len(want) == 0 {
		return
	}
	kev, err := s.cfg.Feeds.KevInfo(ctx, keys(want))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: the advisories of fixes could not be read", "error", err)
		return
	}
	for i, fx := range fixes {
		if !noFix(fx.Kind) || fx.URL != nil {
			continue
		}
		if u := vendorLink(kev[causes[i]].Links); u != "" {
			fx.URL = &u
		}
	}
}

// vendorLink is the first of an exploited-list entry's links that is the vendor's page: not CISA's pages and not NVD's entry.
func vendorLink(links []string) string {
	for _, l := range links {
		u, err := url.Parse(strings.TrimSpace(l))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h == "nvd.nist.gov" || h == "cisa.gov" || strings.HasSuffix(h, ".cisa.gov") {
			continue
		}
		return u.String()
	}
	return ""
}

// FixDeviceJS is contract.ts FixDevice.
type FixDeviceJS struct {
	Device   deviceRefJS    `json:"device"`
	Software *softwareRefJS `json:"software"`
	Status   string         `json:"status"`
	Severity SeverityCounts `json:"severity"`
	Findings int            `json:"findings"`
	urgency  int
}

// FixCardJS is contract.ts FixCard.
type FixCardJS struct {
	Fix      fixJS          `json:"fix"`
	Status   string         `json:"status"`
	Cause    string         `json:"cause"`
	Devices  int            `json:"devices"`
	Findings int            `json:"findings"`
	Severity SeverityCounts `json:"severity"`
	Items    []FixDeviceJS  `json:"items"`
}

// FixCards is contract.ts FixCards.
type FixCards struct {
	Items    []FixCardJS `json:"items"`
	Total    int         `json:"total"`
	Findings int         `json:"findings"`
}

// ByFix is the By fix list: one card per combined fix across devices, the most urgent first, then the most findings, then the key.
func (s *Service) ByFix(ctx context.Context, f ListFilter, p Page) (FixCards, error) {
	var out FixCards
	err := s.readTx(ctx, func(ctx context.Context) error {
		var err error
		out, err = s.byFix(ctx, f, p)
		return err
	})
	return out, err
}

func (s *Service) byFix(ctx context.Context, f ListFilter, p Page) (FixCards, error) {
	f.Ignored = false // ignored devices are never in By fix
	gs, err := s.lineGroups(ctx, f)
	if err != nil {
		return FixCards{}, err
	}
	type agg struct {
		key        string
		n, urgency int
		assets     map[string]bool
	}
	byKey := map[string]*agg{}
	out := FixCards{Items: []FixCardJS{}}
	for _, g := range gs {
		if g.N == 0 {
			continue
		}
		a := byKey[g.Block]
		if a == nil {
			a = &agg{key: g.Block, urgency: g.Urgency, assets: map[string]bool{}}
			byKey[g.Block] = a
		}
		a.n += g.N
		a.urgency = min(a.urgency, g.Urgency)
		a.assets[g.Asset] = true
		out.Findings += g.N
	}
	aggs := make([]*agg, 0, len(byKey))
	for _, a := range byKey {
		aggs = append(aggs, a)
	}
	out.Total = len(aggs)
	slices.SortFunc(aggs, func(a, b *agg) int {
		return cmp.Or(cmp.Compare(a.urgency, b.urgency), cmp.Compare(b.n, a.n), cmp.Compare(len(b.assets), len(a.assets)), cmp.Compare(a.key, b.key))
	})
	lo, hi := p.cut(len(aggs))
	if lo == hi {
		return out, nil
	}
	want, assets := map[string]bool{}, map[string]bool{}
	for _, a := range aggs[lo:hi] {
		want[a.key] = true
		for id := range a.assets {
			assets[id] = true
		}
	}
	blocks := blocksOf(gs)
	fs, err := s.listRows(ctx, f, keys(assets))
	if err != nil {
		return FixCards{}, err
	}
	vs, err := s.views(ctx, fs)
	if err != nil {
		return FixCards{}, err
	}
	type dk struct{ asset, software string }
	per := map[string]map[dk][]View{}
	all := map[string][]View{}
	fixes := map[string]Fix{}
	for _, v := range vs {
		k, fx := blocks.of(v.Finding)
		if !want[k] {
			continue
		}
		fixes[k] = fx
		if per[k] == nil {
			per[k] = map[dk][]View{}
		}
		d := dk{v.Finding.AssetID, v.Finding.SoftwareID}
		per[k][d] = append(per[k][d], v)
		all[k] = append(all[k], v)
	}
	for _, a := range aggs[lo:hi] {
		vs := all[a.key]
		if len(vs) == 0 {
			continue
		}
		c := causeOf(vs)
		card := FixCardJS{Fix: fixOf(a.key, fixes[a.key], productName(c.Finding, c.Line)), Status: LayerCode(c.Finding.Urgency),
			Cause: c.Finding.CVE, Devices: len(a.assets), Findings: len(vs)}
		for _, v := range vs {
			card.Severity.add(v)
		}
		for _, dvs := range per[a.key] {
			dc := causeOf(dvs)
			d := FixDeviceJS{Device: deviceRef(dc.Device), Software: softwareRef(dc), Status: LayerCode(dc.Finding.Urgency), Findings: len(dvs), urgency: dc.Finding.Urgency}
			if d.Software != nil && dc.Line != nil && dc.Line.Version != "" {
				v := dc.Line.Version
				d.Software.Version = &v
			}
			for _, v := range dvs {
				d.Severity.add(v)
			}
			card.Items = append(card.Items, d)
		}
		slices.SortFunc(card.Items, func(x, y FixDeviceJS) int {
			return cmp.Or(cmp.Compare(x.urgency, y.urgency), cmp.Compare(y.Findings, x.Findings), cmp.Compare(strings.ToLower(x.Device.Name), strings.ToLower(y.Device.Name)),
				cmp.Compare(x.Device.ID, y.Device.ID))
		})
		out.Items = append(out.Items, card)
	}
	var fxs []*fixJS
	var causes []string
	for i := range out.Items {
		fxs, causes = append(fxs, &out.Items[i].Fix), append(causes, out.Items[i].Cause)
	}
	s.linkAdvisories(ctx, fxs, causes)
	return out, nil
}

// FixFindings are the open findings of one device listed under one fix on one software line ("" for the block on no line): its block
// in By device, or its row in By fix. What POST /findings/handle with a device and a fix acts on. Two lines of one product can share a
// fix key (no fix known yet, or the same release), so the line is part of the handle: handling Java 21's block never touches Java 8's.
func (s *Service) FixFindings(ctx context.Context, device, software, key string) ([]string, error) {
	var ids []string
	err := s.readTx(ctx, func(ctx context.Context) error {
		var err error
		ids, err = s.fixFindings(ctx, device, software, key)
		return err
	})
	return ids, err
}

func (s *Service) fixFindings(ctx context.Context, device, software, key string) ([]string, error) {
	gs, err := s.lineGroups(ctx, ListFilter{Device: device})
	if err != nil {
		return nil, err
	}
	ig, err := s.lineGroups(ctx, ListFilter{Device: device, Ignored: true}) // a device a person ignored is still handled from its tab
	if err != nil {
		return nil, err
	}
	gs = append(gs, ig...)
	var conds []string
	var args []any
	for _, g := range gs {
		if g.Block == key && g.Software == software {
			conds = append(conds, `(ifnull(software_id, '') = ? AND fix_key = ?)`)
			args = append(args, g.Software, g.Key)
		}
	}
	if len(conds) == 0 {
		return nil, nil
	}
	fs, err := selectFindings(ctx, s.rd(ctx), `state = 'open' AND asset_id = ? AND (`+strings.Join(conds, " OR ")+`) ORDER BY id`,
		append([]any{device}, args...)...)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.ID
	}
	return ids, nil
}

// deviceStatuses is the status of these devices (every device with open findings or open questions when assets is nil), from one
// grouped read of the findings and one of the questions: DeviceStatusOf on each device's counts.
func (s *Service) deviceStatuses(ctx context.Context, assets []string) (map[string]*DeviceStatus, error) {
	counts, err := s.deviceCounts(ctx, assets)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*DeviceStatus, len(counts))
	for id, c := range counts {
		if st := DeviceStatusOf(*c); st != nil {
			out[id] = st
		}
	}
	return out, nil
}

// deviceCounts reads, per device, the distinct CVEs of its open findings at each layer and its questions waiting for an answer.
func (s *Service) deviceCounts(ctx context.Context, assets []string) (map[string]*DeviceCounts, error) {
	filter, args := "", []any{}
	if assets != nil {
		as, _ := json.Marshal(nonNilStrings(assets))
		filter, args = ` AND asset_id IN (SELECT value FROM json_each(?))`, []any{string(as)}
	}
	q := s.rd(ctx)
	out := map[string]*DeviceCounts{}
	get := func(id string) *DeviceCounts {
		c := out[id]
		if c == nil {
			c = &DeviceCounts{}
			out[id] = c
		}
		return c
	}
	r, err := q.QueryContext(ctx, `SELECT asset_id, urgency, count(DISTINCT cve) FROM fnd_finding WHERE state = 'open'`+filter+` GROUP BY asset_id, urgency`, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: counting device findings: %w", err)
	}
	for r.Next() {
		var id string
		var layer, n int
		if err := r.Scan(&id, &layer, &n); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("findings: counting device findings: %w", err)
		}
		if layer >= UrgencyUnderAttack && layer <= UrgencyUpdate {
			get(id).CVEs[layer] += n
		}
	}
	if err := errors.Join(r.Err(), r.Close()); err != nil {
		return nil, fmt.Errorf("findings: counting device findings: %w", err)
	}
	r, err = q.QueryContext(ctx, `SELECT asset_id, count(*) FROM fnd_question WHERE answer IS NULL`+filter+` GROUP BY asset_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: counting device questions: %w", err)
	}
	for r.Next() {
		var id string
		var n int
		if err := r.Scan(&id, &n); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("findings: counting device questions: %w", err)
		}
		get(id).Input += n
	}
	if err := errors.Join(r.Err(), r.Close()); err != nil {
		return nil, fmt.Errorf("findings: counting device questions: %w", err)
	}
	return out, nil
}

// DeviceStatuses is the badge of every device that has one (open findings, or questions waiting for a person): what the Devices list,
// the device page and Home show. A device absent from the map has none.
func (s *Service) DeviceStatuses(ctx context.Context) (map[string]DeviceStatus, error) {
	m, err := s.deviceStatuses(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]DeviceStatus, len(m))
	for id, st := range m {
		out[id] = *st
	}
	return out, nil
}

// ListedFix is the fix an open finding is listed under in By device and By fix: its block's combined release (the lowest release of
// its product that clears every CVE of the block on its line), which can be newer than the finding's own stored fix ("Update to
// 9.0.2.0200: fixes 3 CVEs", not 9.0.2.0100 for one of them). A reader that lists fixes (the report's "Do these first" and "Still open") uses it, so it names the fix the
// Findings lists name.
type ListedFix struct {
	Key string // the block key, By fix's group
	Fix Fix
}

// ListedFixes are the listed fixes of every open finding by its id (ignored devices left out, as in the lists).
func (s *Service) ListedFixes(ctx context.Context) (map[string]ListedFix, error) {
	out := map[string]ListedFix{}
	err := s.readTx(ctx, func(ctx context.Context) error {
		gs, err := s.lineGroups(ctx, ListFilter{})
		if err != nil {
			return err
		}
		rows, args, _, _, err := s.where(ctx, StateOpen, ListFilter{})
		if err != nil {
			return err
		}
		fs, err := selectFindings(ctx, s.rd(ctx), rows+` ORDER BY id`, args...)
		if err != nil {
			return err
		}
		blocks := blocksOf(gs)
		for _, f := range fs {
			key, fx := blocks.of(f)
			out[f.ID] = ListedFix{Key: clipBytes(key, 400), Fix: fx}
		}
		return nil
	})
	return out, err
}
