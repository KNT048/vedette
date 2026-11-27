package findings

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// The customer's AI identifies what code cannot. A software line no standard data names (no CPE, no distribution package, no catalogue
// alias, no CVE record that writes its names) has no CVE product, so nothing can ever be decided for it. After a match pass, the box
// generates up to 20 candidates for each such line from its own catalogue (identitycand.go) and asks the AI, the way a person would
// read the list, which one the software is: a candidate's id, none or unsure, whether it is that product itself or only a part of its
// family (an agent, a client), with a short reason, by schema. The box keeps a product only when it is one it offered and its name
// shares a word that may tell the product with the line's name. The answer is stored per cleaned publisher and name (fnd_identity), so
// one answer serves every device, and asked again only when it no longer fits the candidates (askAgain).
//
// What it may do: the chosen product's ranges only open, and only for the program itself (a family match opens nothing yet; it is
// counted as identity ai_family). A version inside them is a finding labelled "Identified by AI as <title>"
// with a one-click "Not this product"; what they say otherwise decides nothing (devMatch.aiGuard). A person's "Not this product" is
// stored for the name, applies to every device at once, is audited and wins: that product is never offered for the name again. A line
// the AI cannot place, and every such line while no AI runs, stays unlinked and is counted as identity none in the coverage.
//
// What leaves the box: the publisher, the display name (with the names of the box's own devices and accounts, email addresses and
// user folders replaced) and the version of the line, and the candidates' names and CVE counts, to the customer's own AI profile for
// explaining findings, within the daily number of automatic AI reads it shares with the reading of vendor advisories.

// The identity methods of a line whose product the customer's AI chose (Software.AIProduct): the program itself (IdentityAI), or only a
// part of the product's family (IdentityAIFamily: an agent, a client of it), which opens nothing.
const (
	IdentityAI       = "ai"
	IdentityAIFamily = "ai_family"
)

// The limits of the automatic identification.
const (
	identityAutoMax    = 100                 // the most names one run asks about
	identityBatch      = 5                   // the names of one AI call
	identityRecheck    = 30 * 24 * time.Hour // an answer of none or unsure is asked again after this, whatever the candidates
	identityNewTop     = 7 * 24 * time.Hour  // ... or after this, when a new candidate entered the top identityTopN
	identityTopN       = 5                   // the candidates whose change may ask again about none or unsure
	identityFailedWait = 24 * time.Hour      // the names of a call that failed wait this long before they are asked again
	identityRunTimeout = 15 * time.Minute
	identityReasonMax  = 200
)

// The matches of fnd_identity.fit: the program is the chosen product itself, or only a part of its family (an agent, a client, a
// plugin, a driver of it). Only an exact match opens findings.
const (
	MatchExact  = "exact"
	MatchFamily = "family"
)

// The choices of fnd_identity.choice.
const (
	ChoiceProduct = "product"
	ChoiceNone    = "none"
	ChoiceUnsure  = "unsure"
)

// AIProduct is the catalogue product the customer's AI chose for a line (Software.AIProduct): the candidate's names as the catalogue
// stores them, and the name it is stored under.
type AIProduct struct {
	Vendor, Product string
	Record          bool   // a CVE record's product key without a CPE
	Kev             string // the exploited-list entry's own "vendor|product" when the product is one, else ""
	Title           string
	Publisher, Name string // IdentityKey of the line
	// Family: the AI said the program is only a part of the product's family (MatchFamily): stored and counted, it opens nothing.
	Family bool `json:",omitempty"`
}

// ids are the identities the matcher reads the chosen product by (marked ai): its names as a CPE's (unless it is a record key) and as
// a CVE record's product key.
func (p *AIProduct) ids() []identity {
	if p == nil || p.Family {
		return nil
	}
	v, pr := productid.Norm(p.Vendor), productid.Norm(p.Product)
	if v == "" || pr == "" {
		return nil
	}
	out := []identity{{vendor: v, product: pr, record: true, ai: true}}
	if !p.Record {
		out = append(out, identity{vendor: v, product: pr, ai: true})
	}
	return out
}

// note is the identity a finding opened through the product rests on (Evidence.Identity).
func (p *AIProduct) note() *IdentityNote {
	return &IdentityNote{Method: IdentityAI, Vendor: p.Vendor, Product: p.Product, Title: p.Title, Publisher: p.Publisher, Name: p.Name}
}

// Identifier is what the identification needs from outside findings (the binary's adapter over feeds and the ai module). nil: no
// identification (the AI module is off); the Checker's Ready and Budget say whether the AI can run and the automatic run is on.
type Identifier interface {
	// Products is every product the catalogue names, with its CVE counts: the only products a line may be given.
	Products(ctx context.Context) ([]CatalogueName, error)
	// Identify asks the AI to choose each item's product among its candidates (one call, the explain-finding job's profile and budget;
	// actor SystemUser is the automatic run, held to the daily number of automatic AI reads).
	Identify(ctx context.Context, actor string, req IdentifyRequest) (IdentifyAnswer, error)
	// PrivateNames are the names of the box's own devices and accounts: never sent inside a software name.
	PrivateNames(ctx context.Context) ([]string, error)
}

// IdentifyRequest is the lines of one identification call.
type IdentifyRequest struct{ Items []IdentifyItem }

// IdentifyItem is one line asked about: its publisher, display name and version as read (names scrubbed), and its candidates.
type IdentifyItem struct {
	Index                    int
	Publisher, Name, Version string
	Candidates               []IdentifyCandidate
}

// IdentifyCandidate is one product offered: its id in the request, its readable name, its catalogue names and CVE count.
type IdentifyCandidate struct {
	ID, Title, Product string // Product: "vendor:product" as the catalogue writes it
	CVEs               int
}

// IdentifyAnswer is the AI's answer: one choice per item (a candidate's id, none or unsure) with its reason.
type IdentifyAnswer struct {
	Choices    []IdentifyChoice
	Model      string
	ActivityID string
}

// IdentifyChoice is the AI's choice for one item: a candidate id, none or unsure; whether the program is the product itself or a part
// of its family (MatchExact, MatchFamily); and why.
type IdentifyChoice struct {
	Index                 int
	Choice, Match, Reason string
}

// SetIdentifier sets the door the identification goes through (the binary sets it once while wiring, before serving).
func (s *Service) SetIdentifier(id Identifier) { s.cfg.Identifier = id }

// identityRow is one row of fnd_identity.
type identityRow struct {
	Publisher, Name, Kind, Choice string
	Fit                           string // MatchExact or MatchFamily for a product, "" otherwise
	Vendor, Product               string
	Record                        bool
	Kev, Title, Reason            string
	Candidates, Model, ActivityID string
	By                            string
	At                            time.Time
}

func (r identityRow) product() CatalogueProduct {
	return CatalogueProduct{Vendor: r.Vendor, Product: r.Product, Record: r.Record, Kev: r.Kev, Title: r.Title}
}

// nameKey is a cleaned publisher and name (IdentityKey).
type nameKey struct{ publisher, name string }

// identities is fnd_identity as the match reads it: the AI's row per name, and the products a person rejected per name.
type identities struct {
	ai         map[nameKey]identityRow
	rejected   map[nameKey]map[string]bool   // CatalogueProduct.key
	rejectedBy map[nameKey]map[string]string // CatalogueProduct.key -> the person who rejected it
}

// identityCache keeps fnd_identity in memory between its writes (every write goes through this service and drops it).
type identityCache struct {
	mu   sync.Mutex
	have *identities
}

func (c *identityCache) drop() {
	c.mu.Lock()
	c.have = nil
	c.mu.Unlock()
}

// identities reads fnd_identity, from memory when no write happened since the last read.
func (s *Service) identities(ctx context.Context) (*identities, error) {
	s.idCache.mu.Lock()
	defer s.idCache.mu.Unlock()
	if s.idCache.have != nil {
		return s.idCache.have, nil
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT publisher, name, kind, choice, fit, vendor, product, record, kev, title, reason, candidates, model,
		ifnull(activity_id, ''), by, at FROM fnd_identity`)
	if err != nil {
		return nil, fmt.Errorf("findings: reading identities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := &identities{ai: map[nameKey]identityRow{}, rejected: map[nameKey]map[string]bool{}, rejectedBy: map[nameKey]map[string]string{}}
	for rows.Next() {
		var r identityRow
		var at string
		if err := rows.Scan(&r.Publisher, &r.Name, &r.Kind, &r.Choice, &r.Fit, &r.Vendor, &r.Product, &r.Record, &r.Kev, &r.Title, &r.Reason, &r.Candidates,
			&r.Model, &r.ActivityID, &r.By, &at); err != nil {
			return nil, fmt.Errorf("findings: reading identities: %w", err)
		}
		if r.At, err = parseTS(at); err != nil {
			return nil, fmt.Errorf("findings: reading identities: %w", err)
		}
		k := nameKey{r.Publisher, r.Name}
		if r.Kind == "rejected" {
			if out.rejected[k] == nil {
				out.rejected[k], out.rejectedBy[k] = map[string]bool{}, map[string]string{}
			}
			out.rejected[k][r.product().key()], out.rejectedBy[k][r.product().key()] = true, r.By
			continue
		}
		out.ai[k] = r
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: reading identities: %w", err)
	}
	s.idCache.have = out
	return out, nil
}

// aiProductOf is the product the AI chose for line sw (Family set when it is only a part of that product's family), nil when it chose
// none, a person rejected it, or the line has names of its own that standard data reads (a CPE, a distribution package, a catalogue
// alias).
func (ids *identities) aiProductOf(sw Software) *AIProduct {
	if len(ids.ai) == 0 || sw.CPE != "" || sw.Packaged || sw.Guess ||
		len(cpeAliases[identity{vendor: productid.Norm(sw.Vendor), product: productid.Norm(sw.Product)}]) > 0 {
		return nil
	}
	pub, name, ok := IdentityKey(sw)
	if !ok {
		return nil
	}
	k := nameKey{pub, name}
	r, ok := ids.ai[k]
	if !ok || r.Choice != ChoiceProduct || ids.rejected[k][r.product().key()] {
		return nil
	}
	return &AIProduct{Vendor: r.Vendor, Product: r.Product, Record: r.Record, Kev: r.Kev, Title: cmpNonEmpty(r.Title, titleOf(r.product())),
		Publisher: pub, Name: name, Family: r.Fit == MatchFamily}
}

// withAIProducts gives each line of a the product the AI chose for it (Software.AIProduct). The rows are copied before any is
// changed: the inventory's answer may be shared.
func (s *Service) withAIProducts(ctx context.Context, a *Asset) error {
	ids, err := s.identities(ctx)
	if err != nil {
		return err
	}
	if len(ids.rejectedBy) > 0 {
		a.rejectedBy = ids.rejectedBy
	}
	if len(ids.ai) == 0 {
		return nil
	}
	copied := false
	for i := range a.Software {
		p := ids.aiProductOf(a.Software[i])
		if p == nil {
			continue
		}
		if !copied {
			a.Software, copied = slices.Clone(a.Software), true
		}
		a.Software[i].AIProduct = p
	}
	return nil
}

// identityRejectedBy is the person who said the software of f is not the product the AI chose for it ("Not this product"), "" when f
// does not rest on the AI's choice or nobody rejected that product.
func identityRejectedBy(a Asset, f Finding) string {
	if f.Evidence == nil || f.Evidence.Identity == nil || f.Evidence.Identity.Method != IdentityAI {
		return ""
	}
	n := f.Evidence.Identity
	return a.rejectedBy[nameKey{n.Publisher, n.Name}][productid.NormKey(n.Vendor, n.Product)]
}

// aiInventory is the inventory as every match of this service reads it: MatchInput's lines carry the product the AI chose for them,
// so the match pass, a single device's match and every list that matches again agree. A failed read of the choices fails the read of
// the device: a match without them would close what they opened.
type aiInventory struct {
	Inventory
	s *Service
}

func (i aiInventory) MatchInput(ctx context.Context, assetID string) (Asset, bool, error) {
	a, ok, err := i.Inventory.MatchInput(ctx, assetID)
	if err != nil || !ok {
		return a, ok, err
	}
	if err := i.s.withAIProducts(ctx, &a); err != nil {
		return Asset{}, false, err
	}
	return a, true, nil
}

// identityAsk is one unidentified line as the identification asks about it: its name key, and its names and version as read.
type identityAsk struct {
	key                               nameKey
	vendor, product, display, version string
}

// unlinkedOf is line s of a match as the identification asks about it, when s has no identity of its own (none, or only the AI's) and
// its version is the device's or a person's word (only such a version may open a finding on no exploited list): ok false otherwise. A
// line the AI identified is asked again only when its product leaves the candidates (identify).
func unlinkedOf(s Software, in swInfo, method string) (identityAsk, bool) {
	if method != IdentityNone && method != IdentityAI && method != IdentityAIFamily || s.Guess || !in.given || !trustedReading(s) {
		return identityAsk{}, false
	}
	pub, name, ok := IdentityKey(s)
	if !ok {
		return identityAsk{}, false
	}
	return identityAsk{key: nameKey{pub, name}, vendor: s.Vendor, product: s.Product, display: s.Display, version: s.Version}, true
}

// identityState is the one identification run at a time.
type identityState struct {
	mu      sync.Mutex
	running bool
	failed  map[nameKey]time.Time // names of a call that failed, until when they wait (identityFailedWait); kept in memory only
}

// waiting says whether name k waits after a failed call at now.
func (st *identityState) waiting(k nameKey, now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	until, ok := st.failed[k]
	return ok && now.Before(until)
}

// fail makes the names of a failed call wait until until.
func (st *identityState) fail(keys []nameKey, until time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.failed == nil {
		st.failed = map[nameKey]time.Time{}
	}
	for k, t := range st.failed { // forget what no longer waits
		if !t.After(until.Add(-identityFailedWait)) {
			delete(st.failed, k)
		}
	}
	for _, k := range keys {
		st.failed[k] = until
	}
}

// AutoIdentify starts the identification of the lines the last match pass left without an identity, in the background: when the AI can
// run, the automatic run is on and today's automatic reads are not used up. It returns whether a run started; nothing happens while
// another runs.
func (s *Service) AutoIdentify(ctx context.Context) bool {
	if s.cfg.Identifier == nil || s.cfg.Checker == nil || s.cfg.Checker.Ready(ctx) != nil {
		return false
	}
	if b := s.cfg.Checker.Budget(ctx); !b.Auto || b.Reached {
		return false
	}
	asks, devices := s.covers.unlinked()
	if len(asks) == 0 {
		return false
	}
	s.ident.mu.Lock()
	if s.ident.running {
		s.ident.mu.Unlock()
		return false
	}
	s.ident.running = true
	s.ident.mu.Unlock()
	go func() {
		defer func() {
			s.ident.mu.Lock()
			s.ident.running = false
			s.ident.mu.Unlock()
		}()
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), identityRunTimeout)
		defer cancel()
		if _, err := s.identify(bg, asks, devices); err != nil {
			s.cfg.Log.WarnContext(bg, "findings: the identification of software failed", "error", err)
		}
	}()
	return true
}

// identityDue is one name to ask about, with its candidates.
type identityDue struct {
	ask   identityAsk
	cands []identityCandidate
	set   string
}

// identify asks the AI about the names of asks that are due (askAgain), the names whose candidates include an exploited-list product
// first, then the most CVEs; stores what the box verified, and matches again the devices (devices: by name) whose lines got a product.
// It returns how many names got one that opens. A budget or a missing profile stops it; what was stored stays. A call that fails after
// it was sent costs its names a day's wait (identityFailedWait) and the run goes on with the next names.
func (s *Service) identify(ctx context.Context, asks []identityAsk, devices map[nameKey][]string) (int, error) {
	names, err := s.cfg.Identifier.Products(ctx)
	if err != nil {
		return 0, err
	}
	ix := newProductIndex(mergeCatalogue(names))
	ids, err := s.identities(ctx)
	if err != nil {
		return 0, err
	}
	now := s.now()
	var due []identityDue
	for _, a := range asks {
		if s.ident.waiting(a.key, now) {
			continue // a call about it failed less than a day ago
		}
		cands := ix.identityCandidates(strings.Fields(a.key.publisher), strings.Fields(a.key.name), ids.rejected[a.key])
		if len(cands) == 0 {
			continue // no catalogue product shares a word with it: it stays none, and nothing is asked
		}
		if r, ok := ids.ai[a.key]; ok && !askAgain(r, cands, now) {
			continue
		}
		due = append(due, identityDue{ask: a, cands: cands, set: topSet(cands)})
	}
	slices.SortStableFunc(due, func(a, b identityDue) int {
		ea, eb := exploitedCand(a.cands), exploitedCand(b.cands)
		if ea != eb {
			if ea {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(mostCVEs(b.cands), mostCVEs(a.cands)); c != 0 {
			return c
		}
		return cmp.Or(strings.Compare(a.ask.key.publisher, b.ask.key.publisher), strings.Compare(a.ask.key.name, b.ask.key.name))
	})
	if len(due) > identityAutoMax {
		due = due[:identityAutoMax]
	}
	if len(due) == 0 {
		return 0, nil
	}
	private, err := s.cfg.Identifier.PrivateNames(ctx)
	if err != nil {
		return 0, err
	}
	scrub := newScrubber(private)
	linked := 0
	touched := map[string]bool{}
	for i := 0; i < len(due); i += identityBatch {
		batch := due[i:min(i+identityBatch, len(due))]
		req := IdentifyRequest{}
		for k, d := range batch {
			it := IdentifyItem{Index: k + 1, Publisher: scrub.clean(d.ask.vendor), Name: scrub.clean(cmpNonEmpty(d.ask.display, d.ask.product)),
				Version: scrub.clean(d.ask.version)}
			for _, c := range d.cands {
				it.Candidates = append(it.Candidates, IdentifyCandidate{ID: c.ID, Title: c.Title, Product: c.Product.Vendor + ":" + c.Product.Product, CVEs: c.Product.CVEs})
			}
			req.Items = append(req.Items, it)
		}
		ans, err := s.cfg.Identifier.Identify(ctx, SystemUser, req)
		if err != nil {
			if stop := (*CheckStop)(nil); errors.As(err, &stop) {
				break // no profile, or a budget: what was stored stays, the rest waits for the next pass
			}
			// the call failed after it was sent (an answer outside the schema, the provider): its names wait a day, the rest go on
			keys := make([]nameKey, len(batch))
			for k, d := range batch {
				keys[k] = d.ask.key
			}
			s.ident.fail(keys, now.Add(identityFailedWait))
			s.cfg.Log.WarnContext(ctx, "findings: an identification call failed; its software waits a day", "names", len(batch), "error", err)
			continue
		}
		rows := verifyChoices(batch, ans, now)
		if err := s.storeIdentities(ctx, rows); err != nil {
			return linked, err
		}
		for _, r := range rows {
			if r.Choice == ChoiceProduct && r.Fit == MatchExact {
				linked++
				for _, d := range devices[nameKey{r.Publisher, r.Name}] {
					touched[d] = true
				}
			}
		}
	}
	for _, d := range slices.Sorted(maps.Keys(touched)) { // the new products apply now, through the match (the one detection writer)
		s.stamps.drop(d)
		if _, err := s.OnMatchChanged(ctx, d); err != nil && !errors.Is(err, ErrUnknownAsset) {
			s.cfg.Log.WarnContext(ctx, "findings: matching a device after its software was identified failed", "device", d, "error", err)
		}
	}
	return linked, nil
}

// askAgain says whether the stored answer r is asked again with the candidates offered now: a product only when it left the
// candidates; none or unsure after identityRecheck, or after identityNewTop when a candidate the answer was not offered entered the
// top identityTopN. The rest of the candidates coming and going (the catalogue changes every day) asks nothing.
func askAgain(r identityRow, cands []identityCandidate, now time.Time) bool {
	if r.Choice == ChoiceProduct {
		return !slices.ContainsFunc(cands, func(c identityCandidate) bool { return c.Product.key() == r.product().key() })
	}
	age := now.Sub(r.At)
	if age >= identityRecheck {
		return true
	}
	if age < identityNewTop {
		return false
	}
	was := strings.Fields(r.Candidates)
	for _, h := range strings.Fields(topSet(cands)) {
		if !slices.Contains(was, h) {
			return true
		}
	}
	return false
}

func exploitedCand(cs []identityCandidate) bool {
	return slices.ContainsFunc(cs, func(c identityCandidate) bool { return c.Product.Exploited > 0 })
}

func mostCVEs(cs []identityCandidate) int {
	n := 0
	for _, c := range cs {
		n = max(n, c.Product.CVEs)
	}
	return n
}

// verifyChoices is the rows the box keeps of the AI's answer for a batch: a product only when its id is one the item was offered and
// its name shares a word that may tell the product with the line's name; none and unsure as they are; a choice that is neither (an id
// not offered, a product that fails the check, no answer for the item) is kept as unsure with the box's own reason, so the same
// candidates are not asked again before askAgain says so. A product the AI did not say is the program itself is a family match.
func verifyChoices(batch []identityDue, ans IdentifyAnswer, now time.Time) []identityRow {
	by := map[int]IdentifyChoice{}
	for _, c := range ans.Choices {
		if _, ok := by[c.Index]; !ok {
			by[c.Index] = c
		}
	}
	out := make([]identityRow, 0, len(batch))
	for k, d := range batch {
		r := identityRow{Publisher: d.ask.key.publisher, Name: d.ask.key.name, Kind: "ai", Choice: ChoiceUnsure, Candidates: d.set,
			Model: clipRunes(ans.Model, 80), ActivityID: ans.ActivityID, By: SystemUser, At: now}
		c, ok := by[k+1]
		switch {
		case !ok:
			r.Reason = "The AI gave no answer for this software."
		case c.Choice == ChoiceNone || c.Choice == ChoiceUnsure:
			r.Choice, r.Reason = c.Choice, oneLine(c.Reason, identityReasonMax)
		default:
			r.Reason = "The AI chose a product it was not offered."
			for _, cand := range d.cands {
				if cand.ID != c.Choice {
					continue
				}
				if !sharesNameWord(cand.Product.Product, strings.Fields(d.ask.key.name)) {
					r.Reason = "The AI chose a product whose name shares no word with the software's."
					break
				}
				p := cand.Product
				r.Choice, r.Fit, r.Reason = ChoiceProduct, MatchExact, oneLine(c.Reason, identityReasonMax)
				if c.Match != MatchExact { // only the program itself opens: a part of the family, or no word on it, opens nothing
					r.Fit = MatchFamily
				}
				r.Vendor, r.Product, r.Record, r.Kev, r.Title = clipRunes(p.Vendor, 200), clipRunes(p.Product, 200), p.Record, clipRunes(p.Kev, 400), clipRunes(cand.Title, 200)
			}
		}
		out = append(out, r)
	}
	return out
}

// storeIdentities writes the AI's rows (one per name: a new answer replaces the last) and drops the kept copy.
func (s *Service) storeIdentities(ctx context.Context, rows []identityRow) error {
	if len(rows) == 0 {
		return nil
	}
	err := s.write(ctx, func(tx *sql.Tx, _ time.Time, _ func(string, any)) error {
		for _, r := range rows {
			if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_identity WHERE publisher = ? AND name = ? AND kind = 'ai'`, r.Publisher, r.Name); err != nil {
				return fmt.Errorf("findings: storing an identity: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_identity (publisher, name, kind, choice, fit, vendor, product, record, kev, title, reason, candidates,
				model, activity_id, by, at) VALUES (?, ?, 'ai', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)`, r.Publisher, r.Name, r.Choice, r.Fit, r.Vendor,
				r.Product, r.Record, r.Kev, r.Title, r.Reason, r.Candidates, r.Model, clipRunes(r.ActivityID, 96), r.By, store.FormatTS(r.At)); err != nil {
				return fmt.Errorf("findings: storing an identity: %w", err)
			}
		}
		return nil
	})
	s.idCache.drop()
	return err
}

// ErrNoIdentity says the finding does not rest on the AI's identification of its software.
var ErrNoIdentity = &APIError{"not_found", 404, "This finding does not rest on the AI's identification of its software."}

// RejectIdentity is a person's "Not this product" on a finding opened through the AI's identification of its software: the product is
// stored as not this software's for its name (every device, audited), the AI's choice is dropped, and the finding's device and every
// device whose last match had a line of that name are matched again at once (the findings close as a correction of
// the box's data; any other device follows at its next match, whose input the rejection changed). The AI may be asked again; that product
// is never offered for the name again.
func (s *Service) RejectIdentity(ctx context.Context, findingID, user string) error {
	if err := ValidUser(user); err != nil {
		return err
	}
	f, err := loadFinding(ctx, s.cfg.DB.Reader(), findingID)
	if err != nil {
		return err
	}
	if f.Evidence == nil || f.Evidence.Identity == nil || f.Evidence.Identity.Method != IdentityAI {
		return ErrNoIdentity
	}
	n := *f.Evidence.Identity
	var devices []string
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, _ func(string, any)) error {
		var r identityRow
		err := tx.QueryRowContext(ctx, `SELECT record, kev, title FROM fnd_identity WHERE publisher = ? AND name = ? AND kind = 'ai' AND vendor = ? AND product = ?`,
			n.Publisher, n.Name, n.Vendor, n.Product).Scan(&r.Record, &r.Kev, &r.Title)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("findings: reading an identity: %w", err)
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO fnd_identity (publisher, name, kind, choice, vendor, product, record, kev, title, by, at)
			VALUES (?, ?, 'rejected', 'product', ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, n.Publisher, n.Name, n.Vendor, n.Product, r.Record, r.Kev,
			clipRunes(cmpNonEmpty(r.Title, n.Title), 200), user, store.FormatTS(now))
		if err != nil {
			return fmt.Errorf("findings: storing a rejected identity: %w", err)
		}
		if added, _ := res.RowsAffected(); added == 0 {
			return nil // rejected before: nothing changes
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_identity WHERE publisher = ? AND name = ? AND kind = 'ai' AND vendor = ? AND product = ?`,
			n.Publisher, n.Name, n.Vendor, n.Product); err != nil {
			return fmt.Errorf("findings: dropping an identity: %w", err)
		}
		devices = slices.Compact(slices.Sorted(slices.Values(append(s.covers.withName(nameKey{n.Publisher, n.Name}), f.AssetID))))
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.ai_identity_rejected", Target: f.ID,
			Detail: clipBytes(fmt.Sprintf("%s: the software %q is not %s (%s:%s), as the AI chose; applies to every device with it", f.CVE, n.Name,
				cmpNonEmpty(n.Title, n.Product), n.Vendor, n.Product), 500)})
	})
	s.idCache.drop()
	if err != nil {
		return err
	}
	for _, d := range devices {
		s.stamps.drop(d)
		if _, err := s.OnMatchChanged(ctx, d); err != nil && !errors.Is(err, ErrUnknownAsset) {
			s.cfg.Log.WarnContext(ctx, "findings: matching a device after a rejected identity failed", "device", d, "error", err)
		}
	}
	return nil
}

// identityReason is the AI's reason and model for the choice a finding rests on, "" when it is no longer stored.
func identityReason(ctx context.Context, q querier, n IdentityNote) (reason, model string, err error) {
	err = q.QueryRowContext(ctx, `SELECT reason, model FROM fnd_identity WHERE publisher = ? AND name = ? AND kind = 'ai' AND vendor = ? AND product = ?`,
		n.Publisher, n.Name, n.Vendor, n.Product).Scan(&reason, &model)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return reason, model, err
}

// scrubber replaces, in a software name sent to the AI, what could name the customer: the box's own device and account names (whole
// words, case-insensitive, at least three characters), email addresses and a user's folder in a path.
type scrubber struct{ names *regexp.Regexp }

var (
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reUserPath = regexp.MustCompile(`(?i)(\\users\\|/users/|/home/|\\documents and settings\\)[^\\/)"]+`) // a folder name may have spaces
)

func newScrubber(private []string) scrubber {
	var parts []string
	seen := map[string]bool{}
	add := func(n string) {
		if len([]rune(n)) < 3 || seen[strings.ToLower(n)] {
			return
		}
		seen[strings.ToLower(n)] = true
		parts = append(parts, regexp.QuoteMeta(n))
	}
	for _, n := range private {
		n = strings.TrimSpace(n)
		add(n)
		if host, _, ok := strings.Cut(n, "."); ok && !strings.ContainsAny(n, "@ \t") {
			add(host) // a hostname's own name, as a software name writes it, without its domain
		}
	}
	if len(parts) == 0 {
		return scrubber{}
	}
	slices.SortFunc(parts, func(a, b string) int { return cmp.Compare(len(b), len(a)) }) // the longest first
	// a name may be written with the network's domain after it ("pc-7.branch.example"): the domain names the customer too
	return scrubber{names: regexp.MustCompile(`(?i)(^|[^\pL\pN])(` + strings.Join(parts, "|") + `)(?:\.[\pL\pN][\pL\pN-]*)*([^\pL\pN]|$)`)}
}

// clean is s as it may be sent.
func (sc scrubber) clean(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = reEmail.ReplaceAllString(s, "[email]")
	s = reUserPath.ReplaceAllString(s, "${1}[user]")
	if sc.names != nil {
		// a match takes the character after the name, so a name right after it is found by the next pass; the mark is no letter or
		// digit until the end, so no pass finds a name in it, and every pass that changes s shortens it
		for prev := ""; prev != s; {
			prev, s = s, sc.names.ReplaceAllString(s, "${1}\x00${3}")
		}
		s = strings.ReplaceAll(s, "\x00", "[name]")
	}
	return clipRunes(s, 200)
}
