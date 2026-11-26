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
	type kevCopy struct {
		Name           string     `json:"name"`
		URL            string     `json:"url"`
		CheckedAt      *time.Time `json:"checked_at"`
		Error          *string    `json:"error"`
		CatalogVersion *string    `json:"catalog_version"`
	}
	type kev struct {
		State         string     `json:"state"`
		Error         *string    `json:"error"`
		IntervalHours int        `json:"interval_hours"`
		CheckedAt     *time.Time `json:"checked_at"`
		LastSuccess   *time.Time `json:"last_success"`
		AnsweredBy    *string    `json:"answered_by"`
		Copies        []kevCopy  `json:"copies"`
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
			// Home says how often the list is checked, when it last was, and when it last loaded
			out.Kev.IntervalHours, out.Kev.CheckedAt, out.Kev.LastSuccess = r.IntervalHours, r.LastFetch, r.LastSuccess
			switch {
			case !r.Enabled: // Home must not count from a list the admin turned off
				out.Kev.State = "off"
			case r.LastSuccess != nil:
				out.Kev.State = "loaded"
			}
			// the last pull failed: why, also when an earlier pull had loaded the list (Home then says since when it is stale)
			if r.Enabled && r.Status == "error" && r.Error != nil {
				out.Kev.Error = oneLine(*r.Error, 200)
			}
			if r.CatalogVersion != nil {
				out.KevCatalogVersion = *r.CatalogVersion
			}
			// Which copy answered the last good pull, and why cisa.gov did not when CISA's GitHub copy did
			// The copy the catalog on the box came from, and what each copy said at its last check
			out.Kev.AnsweredBy, out.Kev.Copies = r.AnsweredBy, []kevCopy{}
			if r.URL == h.s.kevPrimary() {
				cs, _, err := h.s.st.kevCopies(ctx)
				if err != nil {
					return nil, err
				}
				for _, c := range []struct {
					by  string
					url string
					st  kevCopyState
				}{{AnsweredCISA, h.s.kevPrimary(), cs.CISA}, {AnsweredMirror, h.s.kevFallback(), cs.Mirror}} {
					if c.st.CheckedAt.IsZero() {
						continue // not asked since this version: nothing to say
					}
					at := c.st.CheckedAt
					out.Kev.Copies = append(out.Kev.Copies, kevCopy{Name: c.by, URL: c.url, CheckedAt: &at, Error: oneLine(c.st.Error, 200), CatalogVersion: nonEmpty(c.st.Version)})
				}
			}
		}
		if r.Kind != KindVulnerabilities || r.LastSuccess == nil {
			continue
		}
		license := "Custom feed"
		if r.License != nil {
			license = *r.License
		}
		from := r.URL
		if r.ID == "cisa-kev" && r.URL == h.s.kevPrimary() && r.AnsweredBy != nil && *r.AnsweredBy == AnsweredMirror {
			from = h.s.kevFallback() // The copy the catalog on the box came from
		}
		out.Sources = append(out.Sources, src{r.Name, from, license, *r.LastSuccess})
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

// hot is the newly exploited board of the last hours (Home, S-FEED-1): the CISA entries added in the window, grouped by
// product, you_have=yes first, then the number of CVEs, then the top EPSS. A day counts until its last second.
func (s *Service) hot(ctx context.Context, hours int) ([]*hotRow, error) {
	now := s.now()
	cutoff := now.Add(-time.Duration(hours) * time.Hour)
	rows, err := s.st.vulnsNewestFirst(ctx, cutoff.AddDate(0, 0, -1).Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	var groups []*hotRow
	byKey := map[string]*hotRow{}
	var products []Product
	for _, v := range rows {
		// the day counts until its last second (the GUI mock does the same)
		day, err := parseDate(v.DateAdded)
		// a date in the future (a feed or box clock that is off) is not "newly exploited" yet
		if err != nil || day.Add(24*time.Hour-time.Second).Before(cutoff) || day.After(now) {
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
	match, on := s.matchOf(ctx, products)
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
	return groups, nil
}

// NewlyExploited is the Home headline as numbers, for the weekly report: the CVEs newly exploited in the last
// 7 days and how many of their products the inventory says are in use (you_have=yes; 0 while the inventory is off). One
// definition for both pages: the same board as GET /feeds/hot?window=7d.
func (s *Service) NewlyExploited(ctx context.Context) (cves, productsInUse int, err error) {
	groups, err := s.hot(ctx, 24*7)
	if err != nil {
		return 0, 0, err
	}
	for _, g := range groups {
		cves += len(g.Cves)
		if g.YouHave != nil && *g.YouHave == string(HaveYes) {
			productsInUse++
		}
	}
	return cves, productsInUse, nil
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

// withoutNotAffected drops the devices the platform rules prove are not affected by v (PlatformChecker). A failed check keeps
// the list by product (INV-10: the inventory degrades the answer, never fails it).
func (s *Service) withoutNotAffected(ctx context.Context, v VulnRow, m []MatchedAsset) []MatchedAsset {
	pc, ok := s.Inventory.(PlatformChecker)
	if !ok || len(m) == 0 {
		return m
	}
	ids := make([]string, len(m))
	for i, a := range m {
		ids[i] = a.ID
	}
	distro, err := s.st.DistroFixesOf(ctx, v.CVE)
	if err != nil {
		s.Log.WarnContext(ctx, "reading the distribution data of a CVE failed; answering by product", "cve", v.CVE, "error", err)
		return m
	}
	out, err := pc.NotAffected(ctx, v.CVE, v.Vendor, v.Product, distro, ids)
	if err != nil {
		s.Log.WarnContext(ctx, "the platform check of a CVE failed; answering by product", "cve", v.CVE, "error", err)
		return m
	}
	return slices.DeleteFunc(slices.Clone(m), func(a MatchedAsset) bool { return out[a.ID] })
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
	groups, err := h.s.hot(ctx, hours)
	if err != nil {
		return nil, err
	}
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
		// The scope of "I have this" starts a week before the answered entry (HaveWindow) and is set by the
		// first "have" only: a later answer (not relevant, have again) never moves it.
		var since any
		if d, err := time.Parse(time.DateOnly, v.DateAdded); answer == "have" && err == nil {
			since = d.Add(-HaveWindow).Format(time.DateOnly)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO feeds_weekly_answer (key, answer, user_id, answered_at, device_added, have_since) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET answer = excluded.answer, user_id = excluded.user_id, answered_at = excluded.answered_at,
	have_since = coalesce(feeds_weekly_answer.have_since, excluded.have_since)`,
			item.Key, answer, p.ID, h.s.now().Format(tsLayout), added, since)
		if err != nil {
			return fmt.Errorf("feeds: store answer: %w", err)
		}
		// The device is created once per product, whatever is answered later (have, not relevant, have again).
		// With the inventory off the answer is stored and the pull job adds the device when it is back.
		if answer == "have" && added == 0 && h.s.inventoryOn() {
			if err := h.s.declareDevice(ctx, tx, p.Email, item.Key, v); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE feeds_weekly_answer SET device_added = 1 WHERE key = ?`, item.Key); err != nil {
				return fmt.Errorf("feeds: mark device added: %w", err)
			}
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

// FeedsGetFeedsCveID implements GET /feeds/cve/{id} (PRE-3, POST-3): the brief of a CVE the catalogue holds (Store.Brief), and the
// devices whose product matches its exploited-list entry; 404 not_in_data when the catalogue does not hold the CVE.
func (h *FeedHandlers) FeedsGetFeedsCveID(ctx context.Context, params oas.FeedsGetFeedsCveIDParams) (*oas.FeedsGetFeedsCveIDOK, error) {
	b, found, err := h.s.st.Brief(ctx, strings.ToUpper(params.ID))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, apierr.New(http.StatusNotFound, "not_in_data", "The vulnerability data on this box does not hold this CVE.")
	}
	out := toBriefDTO(b)
	if len(b.Lists) > 0 { // "Do you have it?" is the exploited-list entry's product, as on Home (INV-11)
		v, listed, err := h.s.st.VulnByCVE(ctx, b.CVE)
		if err != nil {
			return nil, err
		}
		if match, on := h.s.matchOf(ctx, []Product{{v.Vendor, v.Product}}); listed && on {
			all := match[v.Key()]
			m := h.s.withoutNotAffected(ctx, v, all)
			if m == nil {
				m = []MatchedAsset{}
			}
			out.Matched, out.NotAffected = &m, len(all)-len(m)
		}
	}
	return convert[oas.FeedsGetFeedsCveIDOK](out)
}

// FeedsGetFeedsCveIDTier implements GET /feeds/cve/{id}/tier (S-TIER-1): a CVE on no exploited list, from the
// tier data of the feeds that are on (epss-all, nvd-recent); 404 not_in_data when neither holds it.
func (h *FeedHandlers) FeedsGetFeedsCveIDTier(ctx context.Context, params oas.FeedsGetFeedsCveIDTierParams) (*oas.FeedsGetFeedsCveIDTierOK, error) {
	t, found, err := h.s.st.TierCVEOf(ctx, strings.ToUpper(params.ID), h.s.now())
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, apierr.New(http.StatusNotFound, "not_in_data", "This CVE is not on an exploited list, and the EPSS and NVD data on this box do not hold it.")
	}
	day := func(p *time.Time) *string {
		if p == nil {
			return nil
		}
		d := p.UTC().Format(time.DateOnly)
		return &d
	}
	var tier *string
	if t.Tier != "" {
		tier = &t.Tier
	}
	return convert[oas.FeedsGetFeedsCveIDTierOK](map[string]any{
		"cve": t.CVE, "tier": tier, "published": day(t.Published), "last_modified": day(t.LastModified), "nvd_status": t.NVDStatus,
		"severity": t.Severity, "score": t.Score, "epss": t.EPSS, "percentile": t.Percentile, "epss_date": day(t.EPSSDate),
		"products": t.Products, "ranges": t.Ranges,
	})
}

var cveQueryRE = regexp.MustCompile(`(?i)^cve-\d{4}-\d{4,}$`)

// iocCategories is the plain-language category of what a built-in feed lists; a custom feed is "Custom feed".
var iocCategories = map[string]string{
	"ipsum":         "Reported by several blocklists",
	"et-open":       "Compromised host",
	"abusech-feodo": "Botnet command-and-control server",
	"tor-exit":      "Tor exit node",
	"hagezi-tif":    "Threat-intelligence domain list",
	dropFeedID:      "Hijacked or criminal network",
}

// iocHit turns a stored indicator into the answer of a lookup; nil when no switched-on feed lists it now, or when it has no
// verdict (a whitelisted domain, a value that cannot be an IOC). A switched-off feed is not named: it is not pulled, so its
// listings are stale (as logs ignores them).
func iocHit(rec IOCRecord, credit func(IOCSighting) string) map[string]any {
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
	for _, g := range rec.Sightings {
		if b, ok := BuiltinByID(g.SourceID); ok {
			sights = append(sights, SightingOf(b))
		} else {
			sights = append(sights, Sighting{Source: g.SourceID})
		}
		names = append(names, credit(g))
		c, ok := iocCategories[g.SourceID]
		if !ok {
			c = "Custom feed"
		}
		if !slices.Contains(cats, c) && len(cats) < 2 {
			cats = append(cats, c)
		}
	}
	score, _ := IOCConfidence(rec.Sightings) // the same rating logs gives a hit on the value
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
		var hit any // null when there is no hit: a nil interface stays null through apijson.Into, a nil map would become {}
		if key, ok := IOCKey(kind, value); ok {
			rec, found, err := h.s.st.IOCLookup(ctx, kind, key)
			if err != nil {
				return zero, err
			}
			if m := iocHit(rec, func(g IOCSighting) string { return h.s.st.CreditName(ctx, g) }); found && m != nil {
				hit = m
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

// nonEmpty is nil for "", else a pointer to s.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
