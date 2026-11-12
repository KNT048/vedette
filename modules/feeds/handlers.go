package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/server"
)

// FeedHandlers implements the operations of the feeds module (S-FEED-1..5) of oas.Handler. Embed it in the
// composite handler (cmd/vedette/handler.go); it implements no other operation. Roles, the module gate, CSRF
// and schema validation run before these methods (core/server), so no handler checks a role.
type FeedHandlers struct{ s *Service }

// NewHandlers returns the handlers of a service.
func NewHandlers(s *Service) *FeedHandlers { return &FeedHandlers{s: s} }

func actor(ctx context.Context) (server.Principal, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return server.Principal{}, apierr.Unauthenticated()
	}
	return p, nil
}

// ---------- S-FEED-1: status and the hot board

// FeedsGetFeedsStatus implements GET /feeds/status: when the data was pulled and from where.
func (h *FeedHandlers) FeedsGetFeedsStatus(ctx context.Context) (*oas.FeedsGetFeedsStatusOK, error) {
	rows, err := h.s.sources(ctx)
	if err != nil {
		return nil, err
	}
	type src struct {
		Name      string    `json:"name"`
		URL       string    `json:"url"`
		License   string    `json:"license"`
		FetchedAt time.Time `json:"fetched_at"`
	}
	type kev struct {
		State string  `json:"state"`
		Error *string `json:"error"`
	}
	out := struct {
		GeneratedAt       time.Time `json:"generated_at"`
		KevCatalogVersion string    `json:"kev_catalog_version"`
		Sources           []src     `json:"sources"`
		InventoryOn       bool      `json:"inventory_on"`
		Kev               kev       `json:"kev"`
	}{GeneratedAt: time.Unix(0, 0).UTC(), Sources: []src{}, InventoryOn: h.s.inventoryOn(), Kev: kev{State: "never_loaded"}} // never pulled: the epoch, not "now"
	var kevAt, oldest *time.Time
	for _, r := range rows {
		if r.ID == "cisa-kev" {
			kevAt = r.LastSuccess
			switch {
			case !r.Enabled: // D-92: Home must not count from a list the admin turned off
				out.Kev.State = "off"
			case r.LastSuccess != nil:
				out.Kev.State = "loaded"
			case r.Status == "error" && r.Error != nil:
				out.Kev.Error = oneLine(*r.Error, 200)
			}
			if r.CatalogVersion != nil {
				out.KevCatalogVersion = *r.CatalogVersion
			}
		}
		if r.Kind != KindVulnerabilities || r.LastSuccess == nil {
			continue
		}
		license := "Custom feed"
		if r.License != nil {
			license = *r.License
		}
		out.Sources = append(out.Sources, src{r.Name, r.URL, license, *r.LastSuccess})
		if oldest == nil || r.LastSuccess.Before(*oldest) {
			oldest = r.LastSuccess
		}
	}
	// generated_at is the age of the CISA list; without it, the oldest vulnerability source that was pulled
	switch {
	case kevAt != nil:
		out.GeneratedAt = *kevAt
	case oldest != nil:
		out.GeneratedAt = *oldest
	}
	return convert[oas.FeedsGetFeedsStatusOK](out)
}

// oneLine is an error text for a heading: whitespace runs become one space, valid UTF-8, at most limit runes (then "…"),
// no trailing full stop (the sentence around it adds its own); nil when nothing is left.
func oneLine(s string, limit int) *string {
	s = strings.TrimRight(strings.Join(strings.Fields(strings.ToValidUTF8(s, "")), " "), ".")
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit]) + "…"
	}
	if s == "" {
		return nil
	}
	return &s
}

type hotCve struct {
	CVE         string   `json:"cve"`
	DateAdded   string   `json:"date_added"`
	Ransomware  bool     `json:"ransomware"`
	EPSS        *float64 `json:"epss"`
	HasTemplate bool     `json:"has_template"`
}

type hotRow struct {
	Key           string   `json:"key"`
	Vendor        string   `json:"vendor"`
	Product       string   `json:"product"`
	Display       string   `json:"display"`
	Cves          []hotCve `json:"cves"`
	MaxEPSS       *float64 `json:"max_epss"`
	MaxEPSSDelta  *float64 `json:"max_epss_delta"`
	HasTemplate   bool     `json:"has_template"`
	Ransomware    bool     `json:"ransomware"`
	YouHave       *string  `json:"you_have"`
	MatchedAssets []string `json:"matched_assets"`
}

// matchOf asks the inventory about products; with the inventory off it returns nil (INV-10).
func (s *Service) matchOf(ctx context.Context, products []Product) (map[string][]MatchedAsset, bool) {
	if !s.inventoryOn() {
		return nil, false
	}
	m, err := s.Inventory.MatchProducts(ctx, products)
	if err != nil { // INV-10: a broken inventory degrades the answer, it does not fail it
		s.Log.WarnContext(ctx, "the inventory could not match products; answering without it", "error", err)
		return nil, false
	}
	return m, true
}

// FeedsGetFeedsHot implements GET /feeds/hot (S-FEED-1, PRE-2, POST-2): the vulnerabilities added in the
// window, grouped by product; rows are ordered you_have=yes first, then the number of CVEs, then the top EPSS.
func (h *FeedHandlers) FeedsGetFeedsHot(ctx context.Context, params oas.FeedsGetFeedsHotParams) (*oas.FeedsGetFeedsHotOK, error) {
	window, hours := string(params.Window), 24
	switch window {
	case "24h":
	case "7d":
		hours = 24 * 7
	default:
		return nil, apierr.New(http.StatusBadRequest, "bad_window", "window must be 24h or 7d.")
	}
	cutoff := h.s.now().Add(-time.Duration(hours) * time.Hour)
	rows, err := h.s.st.vulnsNewestFirst(ctx, cutoff.AddDate(0, 0, -1).Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	var groups []*hotRow
	byKey := map[string]*hotRow{}
	var products []Product
	for _, v := range rows {
		// the day counts until its last second (the GUI mock does the same)
		day, err := parseDate(v.DateAdded)
		if err != nil || day.Add(24*time.Hour-time.Second).Before(cutoff) {
			continue
		}
		k := v.Key()
		g := byKey[k]
		if g == nil {
			g = &hotRow{Key: k, Vendor: v.Vendor, Product: v.Product, Display: DisplayOf(v.Vendor, v.Product), Cves: []hotCve{}, MatchedAssets: []string{}}
			byKey[k] = g
			groups = append(groups, g)
			products = append(products, Product{v.Vendor, v.Product})
		}
		g.Cves = append(g.Cves, hotCve{v.CVE, v.DateAdded, v.Ransomware, v.EPSS, v.HasTemplate})
		g.HasTemplate = g.HasTemplate || v.HasTemplate
		g.Ransomware = g.Ransomware || v.Ransomware
		if v.EPSS != nil && (g.MaxEPSS == nil || *v.EPSS > *g.MaxEPSS) {
			e := *v.EPSS
			g.MaxEPSS = &e
		}
		if v.EPSS != nil && v.EPSS7dAgo != nil { // a CVE without an old score is not "rising"
			if d := *v.EPSS - *v.EPSS7dAgo; g.MaxEPSSDelta == nil || d > *g.MaxEPSSDelta {
				g.MaxEPSSDelta = &d
			}
		}
	}
	match, on := h.s.matchOf(ctx, products)
	if on {
		for _, g := range groups {
			m := match[g.Key]
			yh := string(youHave(m))
			g.YouHave = &yh
			for _, a := range m {
				g.MatchedAssets = append(g.MatchedAssets, a.ID)
			}
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if ay, by := a.YouHave != nil && *a.YouHave == "yes", b.YouHave != nil && *b.YouHave == "yes"; ay != by {
			return ay
		}
		if len(a.Cves) != len(b.Cves) {
			return len(a.Cves) > len(b.Cves)
		}
		return epssOr0(a.MaxEPSS) > epssOr0(b.MaxEPSS)
	})
	out := struct {
		Window string    `json:"window"`
		Rows   []*hotRow `json:"rows"`
		Latest *struct {
			CVE       string `json:"cve"`
			DateAdded string `json:"date_added"`
			Display   string `json:"display"`
		} `json:"latest"`
	}{Window: window, Rows: append([]*hotRow{}, groups...)}
	latest, err := h.s.st.latest(ctx)
	if err != nil {
		return nil, err
	}
	if latest != nil {
		out.Latest = &struct {
			CVE       string `json:"cve"`
			DateAdded string `json:"date_added"`
			Display   string `json:"display"`
		}{latest.CVE, latest.DateAdded, DisplayOf(latest.Vendor, latest.Product)}
	}
	return convert[oas.FeedsGetFeedsHotOK](out)
}

func epssOr0(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// ---------- S-FEED-2: "This week, in short"

type weeklyItem struct {
	ID        string  `json:"id"`
	Key       string  `json:"key"`
	Text      string  `json:"text"`
	DateAdded string  `json:"date_added"`
	CVE       string  `json:"cve"`
	Answer    *string `json:"answer"`
}

const weeklyMax = 8

// weekly builds the sentences from a template on the box (INV-14, no AI): the newest CISA-list CVE of each of
// the latest products, with the answer already given. Read from SQL: only the rows shown are loaded.
func (s *Service) weekly(ctx context.Context) ([]weeklyItem, []VulnRow, error) {
	rows, err := s.st.weeklyVulns(ctx, weeklyMax)
	if err != nil {
		return nil, nil, err
	}
	keys := make([]string, len(rows))
	for i, v := range rows {
		keys[i] = v.Key()
	}
	answers, err := s.st.weeklyAnswers(ctx, keys)
	if err != nil {
		return nil, nil, err
	}
	items := make([]weeklyItem, 0, len(rows))
	for i, v := range rows {
		it := weeklyItem{ID: keys[i], Key: keys[i], Text: weeklyText(v.Vuln), DateAdded: v.DateAdded, CVE: v.CVE}
		if a, ok := answers[keys[i]]; ok {
			ans := a.Answer
			it.Answer = &ans
		}
		items = append(items, it)
	}
	return items, rows, nil
}

// FeedsGetFeedsWeekly implements GET /feeds/weekly.
func (h *FeedHandlers) FeedsGetFeedsWeekly(ctx context.Context) (*oas.FeedsGetFeedsWeeklyOK, error) {
	items, _, err := h.s.weekly(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.FeedsGetFeedsWeeklyOK](map[string]any{"items": items})
}

// FeedsPostFeedsWeeklyID implements POST /feeds/weekly/{id}: "I have it" or "Not relevant" (INV-14). "I have it"
// declares one manual device through the inventory (once per product) when the inventory is on; with the
// inventory off only the answer is stored, as in the GUI mock.
func (h *FeedHandlers) FeedsPostFeedsWeeklyID(ctx context.Context, req *oas.FeedsPostFeedsWeeklyIDReq, params oas.FeedsPostFeedsWeeklyIDParams) (*oas.FeedsPostFeedsWeeklyIDOK, error) {
	p, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	answer := string(req.Answer)
	if answer != "have" && answer != "not_relevant" {
		return nil, apierr.New(http.StatusBadRequest, "bad_answer", "answer must be have or not_relevant.")
	}
	items, vulns, err := h.s.weekly(ctx)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(items, func(w weeklyItem) bool { return w.ID == params.ID })
	if i < 0 {
		return nil, apierr.New(http.StatusNotFound, apierr.CodeNotFound, "No such item.")
	}
	item, v := items[i], vulns[i]
	err = h.s.writeDeclaring(ctx, func(tx *sql.Tx) error {
		var prev string
		var added int
		switch err := tx.QueryRowContext(ctx, `SELECT answer, device_added FROM feeds_weekly_answer WHERE key = ?`, item.Key).Scan(&prev, &added); err {
		case nil, sql.ErrNoRows:
		default:
			return fmt.Errorf("feeds: read answer: %w", err)
		}
		// The device is created once per product, whatever is answered later (have, not relevant, have again).
		// With the inventory off the answer is stored and the pull job adds the device when it is back.
		if answer == "have" && added == 0 && h.s.inventoryOn() {
			if err := h.s.declareDevice(ctx, tx, p.Email, item.Key, v); err != nil {
				return err
			}
			added = 1
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_weekly_answer (key, answer, user_id, answered_at, device_added) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET answer = excluded.answer, user_id = excluded.user_id, answered_at = excluded.answered_at, device_added = excluded.device_added`,
			item.Key, answer, p.ID, h.s.now().Format(tsLayout), added)
		if err != nil {
			return fmt.Errorf("feeds: store answer: %w", err)
		}
		return h.s.Audit.Append(ctx, tx, audit.Entry{User: p.Email, Action: "feeds.weekly_answer", Target: DisplayOf(v.Vendor, v.Product), Detail: answer})
	})
	if err != nil {
		return nil, err
	}
	items, _, err = h.s.weekly(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.FeedsPostFeedsWeeklyIDOK](map[string]any{"items": items})
}

// ---------- S-FEED-1/3: one CVE, and lookup

// FeedsGetFeedsCveID implements GET /feeds/cve/{id} (PRE-3, POST-3).
func (h *FeedHandlers) FeedsGetFeedsCveID(ctx context.Context, params oas.FeedsGetFeedsCveIDParams) (*oas.FeedsGetFeedsCveIDOK, error) {
	v, found, err := h.s.st.VulnByCVE(ctx, strings.ToUpper(params.ID))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, apierr.New(http.StatusNotFound, "not_in_kev", "This CVE is not on the exploited list (CISA KEV) in the current data.")
	}
	match, on := h.s.matchOf(ctx, []Product{{v.Vendor, v.Product}})
	out := struct {
		vulnDTO
		Matched *[]MatchedAsset `json:"matched"`
	}{vulnDTO: toVulnDTO(v)}
	if on {
		m := match[v.Key()]
		if m == nil {
			m = []MatchedAsset{}
		}
		out.Matched = &m
	}
	return convert[oas.FeedsGetFeedsCveIDOK](out)
}

var cveQueryRE = regexp.MustCompile(`(?i)^cve-\d{4}-\d{4,}$`)

// iocCategories is the plain-language category of what a built-in feed lists; a custom feed is "Custom feed".
var iocCategories = map[string]string{
	"ipsum":         "Reported by several blocklists",
	"et-open":       "Compromised host",
	"abusech-feodo": "Botnet command-and-control server",
	"tor-exit":      "Tor exit node",
	"hagezi-tif":    "Threat-intelligence domain list",
}

// iocHit turns a stored indicator into the answer of a lookup; nil when no switched-on feed lists it now, or when it has no
// verdict (a whitelisted domain, a value that cannot be an IOC). A switched-off feed is not named: it is not pulled, so its
// listings are stale (as logs ignores them).
func iocHit(rec IOCRecord) map[string]any {
	rec.Sightings = slices.DeleteFunc(slices.Clone(rec.Sightings), func(g IOCSighting) bool { return !g.Enabled })
	order := map[string]int{}
	for i, b := range BuiltinSources() {
		order[b.ID] = i
	}
	rank := func(id string) int {
		if r, ok := order[id]; ok {
			return r
		}
		return len(order) // custom feeds after the built-in ones
	}
	sort.SliceStable(rec.Sightings, func(i, j int) bool {
		a, b := rec.Sightings[i], rec.Sightings[j]
		if ra, rb := rank(a.SourceID), rank(b.SourceID); ra != rb {
			return ra < rb
		}
		return a.SourceName < b.SourceName
	})
	var sights []Sighting
	var names, cats []string
	score := 0.0
	for _, g := range rec.Sightings {
		if b, ok := BuiltinByID(g.SourceID); ok {
			sights = append(sights, SightingOf(b))
		} else {
			sights = append(sights, Sighting{Source: g.SourceID})
		}
		names = append(names, g.SourceName)
		c, ok := iocCategories[g.SourceID]
		if !ok {
			c = "Custom feed"
		}
		if !slices.Contains(cats, c) && len(cats) < 2 {
			cats = append(cats, c)
		}
		score = max(score, g.Confidence)
	}
	v := Judge(rec.Type, rec.Value, sights, Whitelist{})
	if v == VerdictNone {
		return nil
	}
	return map[string]any{"value": rec.Value, "type": rec.Type, "category": strings.Join(cats, ", "), "sources": names, "score": score,
		"first_seen": rec.FirstSeen.Format("2006-01-02"), "last_seen": rec.LastSeen.Format("2006-01-02"), "verdict": string(v)}
}

// FeedsGetFeedsSearch implements GET /feeds/search (S-FEED-3, PRE-4, POST-4): one of cve, ioc or text, answered
// from the data on the box, never from the network.
func (h *FeedHandlers) FeedsGetFeedsSearch(ctx context.Context, params oas.FeedsGetFeedsSearchParams) (oas.FeedsGetFeedsSearchOK, error) {
	var zero oas.FeedsGetFeedsSearchOK
	q := strings.TrimSpace(params.Q)
	if len([]rune(q)) > 200 {
		q = string([]rune(q)[:200])
	}
	if q == "" {
		return zero, apierr.New(http.StatusBadRequest, "empty_query", "Enter a CVE, product name, IP or domain.")
	}
	var out any
	switch addr, ipErr := netip.ParseAddr(q); {
	case cveQueryRE.MatchString(q):
		cve := strings.ToUpper(q)
		_, found, err := h.s.st.VulnByCVE(ctx, cve)
		if err != nil {
			return zero, err
		}
		out = map[string]any{"kind": "cve", "cve": cve, "found": found}
	case (ipErr == nil && addr.Zone() == "") || validDomain(q): // the parser's idea of a domain (the GUI mock's FEED_DOMAIN_RE); IOCKey decides whether it can be an IOC
		kind, value := "domain", strings.ToLower(q)
		if ipErr == nil {
			kind = "ip"
		}
		var hit map[string]any
		if key, ok := IOCKey(kind, value); ok {
			rec, found, err := h.s.st.IOCLookup(ctx, kind, key)
			if err != nil {
				return zero, err
			}
			if found {
				hit = iocHit(rec)
			}
			value = key
		}
		out = map[string]any{"kind": "ioc", "value": value, "type": kind, "hit": hit}
	default:
		rows, err := h.s.st.searchVulns(ctx, strings.ToLower(q))
		if err != nil {
			return zero, err
		}
		vulns := make([]vulnDTO, 0, len(rows))
		for _, v := range rows {
			vulns = append(vulns, toVulnDTO(v))
		}
		out = map[string]any{"kind": "text", "q": q, "vulns": vulns}
	}
	res, err := convert[oas.FeedsGetFeedsSearchOK](out)
	if err != nil {
		return zero, err
	}
	return *res, nil
}
