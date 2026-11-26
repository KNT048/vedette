package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// A target as a node of the tree (GET /exposure/tree, contract.ts TargetNode): its place under its parent, its proof (its own, or the
// proof of an ancestor that covers it), its consents, why Scan now is refused, its newest run and the numbers of its open rows. One
// function (nodeOf) builds it from the stored rows; the list and the single node read it the same way.

// ScheduleOwner is the owner key of the scan schedules of the targets (core/schedule): a target's schedule is ScheduleOwner:<id>.
const ScheduleOwner = "exposure.target"

// ScheduleKey is the owner_key of the scan schedule of target id.
func ScheduleKey(id string) string { return ScheduleOwner + ":" + id }

// The states of a node's proof (contract.ts ProofState).
const (
	ProofProven     = "proven"      // its own proof holds
	ProofCovered    = "covered"     // the proof of an ancestor covers it
	ProofMissing    = "missing"     // never proved, or the proof was withdrawn (the target whose record proved it was removed)
	ProofExpired    = "expired"     // the proof has not passed for ValidDays
	ProofNotCurrent = "not_current" // an IP the box found that the box no longer goes out through: still scannable until it expires
)

// The reasons Scan now of a node is refused (contract.ts NodeBlock).
const (
	NodeDisabled     = "disabled"
	NodeProof        = "proof"
	NodeNoCommitment = "no_commitment"
)

// DNSProof is where a domain's TXT record goes (contract.ts DnsProof).
type DNSProof struct {
	Zone    string  `json:"zone"`
	Host    string  `json:"host"`
	AltHost *string `json:"alt_host"`
	Value   string  `json:"value"`
}

// FileProof is where a typed IP's proof file goes (contract.ts FileProof).
type FileProof struct {
	URLs       []string `json:"urls"`
	Content    string   `json:"content"`
	PTRDomains []string `json:"ptr_domains"`
}

// ProofView is the ownership proof of a node (contract.ts Proof).
type ProofView struct {
	State       string     `json:"state"`
	Method      *string    `json:"method"`
	CoveredBy   *TargetRef `json:"covered_by"`
	VerifiedAt  *string    `json:"verified_at"`
	ExpiresAt   *string    `json:"expires_at"`
	NextCheckAt *string    `json:"next_check_at"`
	LastCheck   *Check     `json:"last_check"`
	DNS         *DNSProof  `json:"dns"`
	File        *FileProof `json:"file"`
	Replaced    *Replaced  `json:"replaced"`
}

// Replaced says that an IP the box found was replaced: By, the box's current egress address, was first seen At, after this
// address was last seen.
type Replaced struct {
	By string `json:"by"`
	At string `json:"at"`
}

// ConsentView is an accepted text of a node: the scan confirmation or the testing terms (contract.ts Consent).
type ConsentView struct {
	Version    string `json:"version"`
	Text       string `json:"text"`
	By         string `json:"by"`
	At         string `json:"at"`
	Disruptive bool   `json:"disruptive"`
}

// NodeCounts are the numbers of a node's rows (contract.ts TargetNode.counts).
type NodeCounts struct {
	Hosts    int     `json:"hosts"`
	Services int     `json:"services"`
	Web      int     `json:"web"`
	Issues   int     `json:"issues"`
	Worst    *string `json:"worst"`
}

// NodeView is a target as a node of the tree (contract.ts TargetNode).
type NodeView struct {
	ID               string       `json:"id"`
	ParentID         *string      `json:"parent_id"`
	ScheduleKey      string       `json:"schedule_key"`
	Kind             Kind         `json:"kind"`
	Value            string       `json:"value"`
	Origin           Origin       `json:"origin"`
	ScopeMode        *ScopeMode   `json:"scope_mode"`
	Enabled          bool         `json:"enabled"`
	CreatedAt        string       `json:"created_at"`
	Proof            ProofView    `json:"proof"`
	Commitment       *ConsentView `json:"commitment"`
	Terms            *ConsentView `json:"terms"`
	CommitmentNotice *Notice      `json:"commitment_notice"`
	TermsNotice      TermsNotice  `json:"terms_notice"`
	TermsWarning     *string      `json:"terms_warning"`
	Deep             bool         `json:"deep"`
	Blocked          *string      `json:"blocked"`
	LastScan         *ScanView    `json:"last_scan"`
	Counts           NodeCounts   `json:"counts"`
}

// TreeView is GET /exposure/tree (contract.ts TargetTree).
type TreeView struct {
	Items   []NodeView   `json:"items"`
	BoxIP   BoxIP        `json:"box_ip"`
	Ignored []IgnoredIP  `json:"ignored"`
	Gateway *GatewayView `json:"gateway"`
}

// nodeRead is what every node of one read shares: the targets, the checks of the box's IPs, the newest run and the counts of each.
type nodeRead struct {
	all    []Target
	byID   map[string]Target
	checks checks
	last   map[string]ScanView
	counts map[string]NodeCounts
	egress egressNow // the box's current egress address, for the replaced line of an IP the box found
}

func (s *Service) readNodes(ctx context.Context, q querier) (nodeRead, error) {
	all, err := listTargets(ctx, q)
	if err != nil {
		return nodeRead{}, err
	}
	c, err := s.loadChecks(ctx, q)
	if err != nil {
		return nodeRead{}, err
	}
	last, err := lastScans(ctx, q)
	if err != nil {
		return nodeRead{}, err
	}
	counts, err := nodeCounts(ctx, q)
	if err != nil {
		return nodeRead{}, err
	}
	r := nodeRead{all: all, byID: make(map[string]Target, len(all)), checks: c, last: last, counts: counts, egress: egressNowOf(all, s.clock())}
	for _, t := range all {
		r.byID[t.ID] = t
	}
	return r, nil
}

// Tree lists every target as a node, each right after its parent and siblings by value, with the box-IP settings, the Ignored list
// and the gateway note (GET /exposure/tree).
func (s *Service) Tree(ctx context.Context) (TreeView, error) {
	db := s.cfg.DB.Reader()
	r, err := s.readNodes(ctx, db)
	if err != nil {
		return TreeView{}, fmt.Errorf("exposure: reading the tree: %w", err)
	}
	items := make([]NodeView, 0, len(r.all))
	open := false
	for _, t := range treeOrder(r.all) {
		n := s.nodeOf(t, r)
		items = append(items, n)
		open = open || (t.Kind == KindIP && t.Origin == OriginBox && n.Counts.Services > 0)
	}
	box, err := s.Settings(ctx)
	if err != nil {
		return TreeView{}, err
	}
	ignored, err := s.Ignored(ctx)
	if err != nil {
		return TreeView{}, err
	}
	return TreeView{Items: items, BoxIP: box, Ignored: ignored, Gateway: s.gatewayNote(ctx, open)}, nil
}

// Node returns one target as a node (GET /exposure/tree/{id}), with the shared-address warning of an IP; an error wrapping ErrNotFound.
func (s *Service) Node(ctx context.Context, id string) (NodeView, error) {
	r, err := s.readNodes(ctx, s.cfg.DB.Reader())
	if err != nil {
		return NodeView{}, fmt.Errorf("exposure: reading target: %w", err)
	}
	t, ok := r.byID[id]
	if !ok {
		return NodeView{}, fmt.Errorf("exposure: reading target: %w", ErrNotFound)
	}
	n := s.nodeOf(t, r)
	if w := s.sharedAddress(ctx, t); w != "" { // on the one node only, not on every list
		n.TermsWarning = &w
	}
	return n, nil
}

// treeOrder is every target in tree order: each right after its parent, siblings by value. A target whose parent is not in the list
// (never written by settleTree) is at the top.
func treeOrder(all []Target) []Target {
	ids := map[string]bool{}
	for _, t := range all {
		ids[t.ID] = true
	}
	kids := map[string][]Target{}
	for _, t := range all {
		p := t.ParentID
		if !ids[p] || p == t.ID {
			p = ""
		}
		kids[p] = append(kids[p], t)
	}
	out := make([]Target, 0, len(all))
	seen := map[string]bool{}
	var visit func(string)
	visit = func(parent string) {
		l := kids[parent]
		slices.SortFunc(l, func(a, b Target) int { return strings.Compare(a.Value, b.Value) })
		for _, t := range l {
			if seen[t.ID] {
				continue
			}
			seen[t.ID] = true
			out = append(out, t)
			visit(t.ID)
		}
	}
	visit("")
	return out
}

// nodeOf builds the node of t.
func (s *Service) nodeOf(t Target, r nodeRead) NodeView {
	now := r.checks.now
	n := NodeView{ID: t.ID, ScheduleKey: ScheduleKey(t.ID), Kind: t.Kind, Value: t.Value, Origin: t.Origin, Enabled: t.Enabled,
		CreatedAt: store.FormatTS(t.CreatedAt), Proof: proofOf(t, r, now), TermsNotice: termsOf(t), Deep: t.mode().Full, Counts: r.counts[t.ID]}
	if n.Origin == "" {
		n.Origin = OriginPerson
	}
	if t.ParentID != "" {
		p := t.ParentID
		n.ParentID = &p
	}
	if t.Kind == KindDomain {
		m := t.ScopeMode
		if m == "" {
			m = ScopeAll
		}
		n.ScopeMode = &m
	}
	if c := t.Commitment; c != nil {
		n.Commitment = &ConsentView{Version: deref(c.Version), Text: deref(c.Sentence), By: c.By, At: c.At}
	}
	if !t.Commitment.current() {
		x := noticeOf(t)
		n.CommitmentNotice = &x
	}
	if tr := t.Terms; tr != nil {
		n.Terms = &ConsentView{Version: tr.Version, Text: tr.Text, By: tr.By, At: tr.At, Disruptive: tr.Disruptive}
	}
	var b string
	switch {
	case !t.Enabled:
		b = NodeDisabled
	case n.Proof.State == ProofMissing || n.Proof.State == ProofExpired: // inside its days a proof not found now is a warning only (INV-4)
		b = NodeProof
	case !t.Commitment.current():
		b = NodeNoCommitment
	}
	if b != "" {
		n.Blocked = &b
	}
	if v, ok := r.last[t.ID]; ok {
		n.LastScan = &v
	}
	return n
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func tsPtr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	x := store.FormatTS(t)
	return &x
}

// proofOf is the proof of t as the stored rows say it: the record or file a check found, the box's own sighting of its IP, or the record
// of an ancestor that covers it (a domain proved with no method of its own, exp_target.method NULL). It holds for ValidDays from its last
// pass (INV-4): a last check that did not find it stays in last_check, as a warning, and changes the state only once those days ran out.
func proofOf(t Target, r nodeRead, now time.Time) ProofView {
	p := ProofView{State: ProofMissing, VerifiedAt: tsPtr(t.VerifiedAt), LastCheck: t.LastCheck, ExpiresAt: tsPtr(t.expiresAt(now))}
	if t.Method != "" {
		m := t.Method
		p.Method = &m
	}
	switch {
	case t.VerifiedAt.IsZero():
	case t.validity(now) == validityExpired:
		p.State = ProofExpired
	case t.Kind == KindIP && !t.Typed && r.checks.paused(t):
		p.State = ProofNotCurrent
	default:
		p.State = ProofProven
	}
	if p.State == ProofProven || p.State == ProofNotCurrent {
		_, p.Replaced, _ = r.egress.proofOf(t, now)
	}
	switch t.Kind {
	case KindIP:
		if t.Typed {
			p.NextCheckAt = tsPtr(t.proofNext(now))
			if h := ipProofHintOf(t, r.all); h != nil {
				p.File = &FileProof{URLs: h.URLs, Content: h.Content, PTRDomains: nz(h.PTRDomains)}
			}
		}
		if p.Method == nil && !t.Typed && !t.VerifiedAt.IsZero() {
			m := methodBoxEgress
			p.Method = &m
		}
	case KindDomain:
		p.NextCheckAt = tsPtr(t.proofNext(now))
		if p.State == ProofProven && t.Method == "" {
			p.State, p.VerifiedAt = ProofCovered, nil
			p.CoveredBy = coverOf(t, r)
			if t.LastCheck != nil && t.LastCheck.OK { // a passing check is the ancestor's; one that did not pass is this node's warning
				p.LastCheck = nil
			}
		}
		if p.State != ProofCovered {
			if h := proofHint(t, nil); h != nil {
				p.DNS = &DNSProof{Zone: h.Zone, Host: h.Host, AltHost: h.AltHost, Value: txtRecord(t.Token)}
			}
		}
	}
	return p
}

// coverOf is the target whose record covers t: the ancestor its last check named, else the nearest proved ancestor.
func coverOf(t Target, r nodeRead) *TargetRef {
	up := ancestors(t, r.byID)
	via := ""
	if t.LastCheck != nil {
		via = t.LastCheck.Via
	}
	for _, a := range up {
		if via != "" && a.Value == via {
			return &TargetRef{ID: a.ID, Value: a.Value}
		}
	}
	for _, a := range up {
		if !a.VerifiedAt.IsZero() && a.LastCheck != nil && a.LastCheck.OK && a.Method != "" {
			return &TargetRef{ID: a.ID, Value: a.Value}
		}
	}
	return nil
}

// lastScans is the newest run of every target that has one.
func lastScans(ctx context.Context, q querier) (map[string]ScanView, error) {
	rows, err := q.QueryContext(ctx, `SELECT r.id, x.target_id, r.status, r.trigger, r.requested_by, x.mode, r.queued_at, r.started_at, r.ended_at,
		r.waiting_for, r.stop_reason, r.error, x.summary FROM exp_scan x JOIN core_run r ON r.id = x.run_id
		WHERE r.id = (SELECT x2.run_id FROM exp_scan x2 JOIN core_run r2 ON r2.id = x2.run_id WHERE x2.target_id = x.target_id
			ORDER BY r2.queued_at DESC, r2.rowid DESC LIMIT 1)`)
	if err != nil {
		return nil, fmt.Errorf("newest scans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]ScanView{}
	for rows.Next() {
		v, err := scanScanView(rows)
		if err != nil {
			return nil, fmt.Errorf("newest scans: %w", err)
		}
		out[v.TargetID] = v
	}
	return out, rows.Err()
}

// nodeCounts are the numbers of the open rows of every target: names, open services, those that answered HTTP, open issues and
// the worst severity among them.
func nodeCounts(ctx context.Context, q querier) (map[string]NodeCounts, error) {
	rows, err := q.QueryContext(ctx, `SELECT t.id,
		(SELECT count(*) FROM exp_host h WHERE h.target_id = t.id),
		(SELECT count(*) FROM exp_service x WHERE x.target_id = t.id AND x.state = 'open'),
		(SELECT count(*) FROM exp_service x WHERE x.target_id = t.id AND x.state = 'open' AND x.is_web = 1),
		(SELECT count(*) FROM exp_issue i WHERE i.target_id = t.id AND i.state = 'open'),
		(SELECT min(CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END)
			FROM exp_issue i WHERE i.target_id = t.id AND i.state = 'open')
		FROM exp_target t`)
	if err != nil {
		return nil, fmt.Errorf("counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]NodeCounts{}
	for rows.Next() {
		var id string
		var c NodeCounts
		var worst sql.NullInt64
		if err := rows.Scan(&id, &c.Hosts, &c.Services, &c.Web, &c.Issues, &worst); err != nil {
			return nil, fmt.Errorf("counts: %w", err)
		}
		if worst.Valid && int(worst.Int64) < len(severities) {
			w := severities[worst.Int64]
			c.Worst = &w
		}
		out[id] = c
	}
	return out, rows.Err()
}
