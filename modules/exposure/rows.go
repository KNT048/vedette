package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
)

// The results of the scans as rows (exp_host, exp_address, exp_service, exp_issue, exp_scan): what is exposed now, with when
// each thing was first and last seen, is these rows, never a document of one scan. The scan writer (writer.go) is their one
// writer; the readers below are their one read model.

// Origin is who added a target (exp_target.origin).
type Origin string

// The origins.
const (
	OriginPerson     Origin = "person"     // typed in
	OriginBox        Origin = "box"        // a public IP the box found as its own egress address
	OriginDiscovered Origin = "discovered" // a name found under a domain target, made its own target
)

// ScopeMode is what a scan of a domain target covers (exp_target.scope_mode).
type ScopeMode string

// The scope modes.
const (
	ScopeSelf     ScopeMode = "self"     // only this name
	ScopeAll      ScopeMode = "all"      // this name and every name found under it (the default)
	ScopeSelected ScopeMode = "selected" // this name and the names chosen (exp_host.selected)
)

// Valid reports whether m is one of the three modes.
func (m ScopeMode) Valid() bool { return m == ScopeSelf || m == ScopeAll || m == ScopeSelected }

// HostSource is where a name under a domain was found (exp_host.source, an open vocabulary this type owns).
type HostSource string

// The host sources.
const (
	SourceCT       HostSource = "ct"       // a certificate-transparency log
	SourceDNS      HostSource = "dns"      // the domain's own records
	SourceMX       HostSource = "mx"       // its MX records
	SourceNS       HostSource = "ns"       // its NS records
	SourceWordlist HostSource = "wordlist" // the list of common names
	SourcePerson   HostSource = "person"   // typed by a person
)

// HostSources lists every source.
var HostSources = []HostSource{SourceCT, SourceDNS, SourceMX, SourceNS, SourceWordlist, SourcePerson}

// Valid reports whether h is one of HostSources.
func (h HostSource) Valid() bool { return slices.Contains(HostSources, h) }

// IssueEngine is the engine that reported an issue (exp_issue.engine, an open vocabulary this type owns).
type IssueEngine string

// The engines.
const (
	EngineSurface IssueEngine = "surface" // the port scan, its checks by name and nmap's scripts: admin pages, certificates, script findings
	EngineNuclei  IssueEngine = "nuclei"  // a template matched
	EngineZAP     IssueEngine = "zap"     // the passive web scan
	EngineOpenVAS IssueEngine = "openvas" // OpenVAS
	EngineMatch   IssueEngine = "match"   // an exploited vulnerability matched an identified service
)

// IssueEngines lists every engine.
var IssueEngines = []IssueEngine{EngineSurface, EngineNuclei, EngineZAP, EngineOpenVAS, EngineMatch}

// Valid reports whether e is one of IssueEngines.
func (e IssueEngine) Valid() bool { return slices.Contains(IssueEngines, e) }

// The states of a service and of an issue (closed vocabularies, CHECKed in the schema).
const (
	ServiceOpen   = "open"
	ServiceClosed = "closed"

	IssueOpen    = "open"
	IssueGone    = "gone"    // the engine ran again and no longer reported it
	IssueHandled = "handled" // a person decided (resolution)
)

// The severities of an issue, most severe first.
var severities = []string{"critical", "high", "medium", "low", "info"}

// The ways a service was identified (exp_service.ident).
const (
	identProbed = "probed"
	identTable  = "table"
	identNone   = "none"
)

// TargetRef names another target.
type TargetRef struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// HostView is a name found under a domain target (contract.ts Host).
type HostView struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Source    HostSource `json:"source"`
	Selected  bool       `json:"selected"`
	Child     *TargetRef `json:"child"`
	CNAME     *string    `json:"cname"`
	FirstSeen string     `json:"first_seen"`
	LastSeen  string     `json:"last_seen"`
}

// AddressView is an address of a target or of one of its names (contract.ts Address).
type AddressView struct {
	HostID    *string `json:"host_id"`
	IP        string  `json:"ip"`
	Family    string  `json:"family"`
	Class     string  `json:"class"`
	FirstSeen string  `json:"first_seen"`
	LastSeen  string  `json:"last_seen"`
}

// CertView is the TLS certificate a service showed (exp_service.cert).
type CertView struct {
	Names     []string `json:"names"`
	Issuer    string   `json:"issuer"`
	ExpiresAt string   `json:"expires_at"`
}

// ServiceView is an open or closed port on a public address of a target (contract.ts Service).
type ServiceView struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	Name      string    `json:"name"`
	Product   string    `json:"product"`
	Version   string    `json:"version"`
	CPE       string    `json:"cpe"`
	Title     string    `json:"title"`
	Cert      *CertView `json:"cert"`
	IsWeb     bool      `json:"is_web"`
	Ident     string    `json:"ident"`
	State     string    `json:"state"`
	FirstSeen string    `json:"first_seen"`
	LastSeen  string    `json:"last_seen"`
	// NotReachedSince is, on an open row whose newest verdicts are unreached, lost or unknown, the start of the first scan of that
	// streak (notReachedSince): the row is kept until a scan reaches the port again or notReachedFor after it was last seen. Nil otherwise.
	NotReachedSince *string `json:"not_reached_since"`
}

// IssueDetail is what the page shows of an issue (exp_issue.detail): for display only, never read by logic.
type IssueDetail struct {
	Description string   `json:"description"`
	Solution    string   `json:"solution"`
	Evidence    []string `json:"evidence"`
	// ZAP is, on an issue of the zap engine, ZAP's own rating of the alert and the pass that raised it (contract.ts IssueZap); nil on
	// every other engine and on a ZAP issue stored before it was kept.
	ZAP *IssueZAP `json:"zap,omitempty"`
}

// IssueZAP is ZAP's rating of an alert: Risk high, medium, low or info; Confidence low, medium, high or confirmed; Pass passive (the
// baseline read it in the pages) or active (an attack request of the active scan showed it).
type IssueZAP struct {
	Risk       string `json:"risk"`
	Confidence string `json:"confidence"`
	Pass       string `json:"pass"`
	// Disruptive: an active alert of a rule that runs only with the disruptive rules (the box's own IP), found by a pass that ran them;
	// only another such pass closes the issue.
	Disruptive bool `json:"disruptive,omitempty"`
}

// IssueCVE is a CVE an issue names, with its score when the catalogue has one (nil: not scored yet).
type IssueCVE struct {
	CVE      string          `json:"cve"`
	Severity json.RawMessage `json:"severity"`
}

// IssueView is anything a scan reported as wrong (contract.ts Issue).
type IssueView struct {
	ID            string      `json:"id"`
	TargetID      string      `json:"target_id"`
	ServiceID     *string     `json:"service_id"`
	Engine        IssueEngine `json:"engine"`
	Key           string      `json:"key"`
	Title         string      `json:"title"`
	Severity      string      `json:"severity"`
	CVEs          []IssueCVE  `json:"cves"`
	Detail        IssueDetail `json:"detail"`
	State         string      `json:"state"`
	Resolution    *string     `json:"resolution"`
	ResolvedBy    *string     `json:"resolved_by"`
	ResolvedAt    *string     `json:"resolved_at"`
	Note          *string     `json:"note"`
	AcceptedUntil *string     `json:"accepted_until"`
	FirstSeen     string      `json:"first_seen"`
	LastSeen      string      `json:"last_seen"`
}

// ScanCounts is what one scan left (exp_scan.summary counts; contract.ts ScanCounts).
type ScanCounts struct {
	Hosts          int `json:"hosts"`
	Services       int `json:"services"`
	NewServices    int `json:"new_services"`
	ClosedServices int `json:"closed_services"`
	Issues         int `json:"issues"`
	NewIssues      int `json:"new_issues"`
}

// scanSummary is exp_scan.summary: read and written whole, shown on the run.
type scanSummary struct {
	Counts     *ScanCounts     `json:"counts,omitempty"` // nil until the scan wrote its rows
	Found      *Counts         `json:"found,omitempty"`  // the numbers of what this scan itself found
	Checks     []CheckRow      `json:"checks,omitempty"`
	NotChecked []NotCheckedRow `json:"not_checked,omitempty"`
	// Settings are the target's deep-scan settings this run used (written at its check step); nil on a run before them.
	Settings *settingsSummary `json:"settings,omitempty"`
}

// ScanView is one scan of a target: its shared run, with the exposure facts (contract.ts Scan).
type ScanView struct {
	RunID       string      `json:"run_id"`
	TargetID    string      `json:"target_id"`
	Status      string      `json:"status"`
	Trigger     string      `json:"trigger"`
	RequestedBy string      `json:"requested_by"`
	Mode        string      `json:"mode"`
	QueuedAt    string      `json:"queued_at"`
	StartedAt   *string     `json:"started_at"`
	EndedAt     *string     `json:"ended_at"`
	WaitingFor  *string     `json:"waiting_for"`
	StopReason  *string     `json:"stop_reason"`
	Error       *string     `json:"error"`
	Counts      *ScanCounts `json:"counts"`
}

// The modes of a scan (exp_scan.mode).
const (
	modeSurface = "surface"
	modeDeep    = "deep"
)

func modeWord(m ScanMode) string {
	if m.Full {
		return modeDeep
	}
	return modeSurface
}

// ---- reads ----

// Hosts lists the names found under a target, by name (GET /exposure/tree/{id}/hosts); empty for an IP.
func (s *Service) Hosts(ctx context.Context, id string) ([]HostView, error) {
	db := s.cfg.DB.Reader()
	if _, err := loadTarget(ctx, db, id); err != nil {
		return nil, fmt.Errorf("exposure: listing names: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT h.id, h.name, h.source, h.selected, h.child_target_id, c.value, h.cname, h.first_seen, h.last_seen
		FROM exp_host h LEFT JOIN exp_target c ON c.id = h.child_target_id WHERE h.target_id = ? ORDER BY h.name`, id)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []HostView{}
	for rows.Next() {
		var h HostView
		var sel int
		var child, childValue, cname sql.NullString
		if err := rows.Scan(&h.ID, &h.Name, &h.Source, &sel, &child, &childValue, &cname, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, fmt.Errorf("exposure: listing names: %w", err)
		}
		h.Selected, h.CNAME = sel == 1, optText(cname)
		if child.Valid && childValue.Valid {
			h.Child = &TargetRef{ID: child.String, Value: childValue.String}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Addresses lists the addresses of a target and of its names (GET /exposure/tree/{id}/addresses).
func (s *Service) Addresses(ctx context.Context, id string) ([]AddressView, error) {
	db := s.cfg.DB.Reader()
	if _, err := loadTarget(ctx, db, id); err != nil {
		return nil, fmt.Errorf("exposure: listing addresses: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT a.host_id, a.ip, a.family, a.class, a.first_seen, a.last_seen FROM exp_address a
		LEFT JOIN exp_host h ON h.id = a.host_id WHERE a.target_id = ? ORDER BY coalesce(h.name, ''), a.ip`, id)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []AddressView{}
	for rows.Next() {
		var a AddressView
		var host sql.NullString
		if err := rows.Scan(&host, &a.IP, &a.Family, &a.Class, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, fmt.Errorf("exposure: listing addresses: %w", err)
		}
		a.HostID = optText(host)
		out = append(out, a)
	}
	return out, rows.Err()
}

const serviceColumns = `id, ip, port, proto, name, product, version, cpe, title, cert, is_web, ident, state, first_seen, last_seen`

func scanService(sc scanner) (ServiceView, error) {
	var v ServiceView
	var cert sql.NullString
	var web int
	if err := sc.Scan(&v.ID, &v.IP, &v.Port, &v.Proto, &v.Name, &v.Product, &v.Version, &v.CPE, &v.Title, &cert, &web, &v.Ident, &v.State, &v.FirstSeen, &v.LastSeen); err != nil {
		return ServiceView{}, err
	}
	v.IsWeb = web == 1
	if cert.Valid {
		v.Cert = new(CertView)
		if err := json.Unmarshal([]byte(cert.String), v.Cert); err != nil {
			return ServiceView{}, fmt.Errorf("certificate of %s:%d: %w", v.IP, v.Port, err)
		}
		v.Cert.Names = nz(v.Cert.Names)
	}
	return v, nil
}

// servicesOf reads the services of a target; open only when openOnly.
func servicesOf(ctx context.Context, q querier, id string, openOnly bool) ([]ServiceView, error) {
	query := `SELECT ` + serviceColumns + ` FROM exp_service WHERE target_id = ?`
	if openOnly {
		query += ` AND state = 'open'`
	}
	rows, err := q.QueryContext(ctx, query+` ORDER BY state DESC, ip, port, proto`, id)
	if err != nil {
		return nil, fmt.Errorf("services: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ServiceView{}
	for rows.Next() {
		v, err := scanService(rows)
		if err != nil {
			return nil, fmt.Errorf("services: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Services lists the services of a target, open first (GET /exposure/tree/{id}/services).
func (s *Service) Services(ctx context.Context, id string) ([]ServiceView, error) {
	db := s.cfg.DB.Reader()
	if _, err := loadTarget(ctx, db, id); err != nil {
		return nil, fmt.Errorf("exposure: listing services: %w", err)
	}
	out, err := servicesOf(ctx, db, id, false)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing %w", err)
	}
	for i := range out { // names a script read without the certificate's expiry are not a certificate the page can show
		if c := out[i].Cert; c != nil && c.ExpiresAt == "" {
			out[i].Cert = nil
		}
		if out[i].State != ServiceOpen {
			continue
		}
		if out[i].NotReachedSince, err = notReachedSince(ctx, db, id, portKey(out[i].IP, out[i].Port)); err != nil {
			return nil, fmt.Errorf("exposure: listing services: %w", err)
		}
	}
	return out, nil
}

// Issues lists the issues of a target, open first and the most severe first (GET /exposure/tree/{id}/issues).
func (s *Service) Issues(ctx context.Context, id string) ([]IssueView, error) {
	db := s.cfg.DB.Reader()
	if _, err := loadTarget(ctx, db, id); err != nil {
		return nil, fmt.Errorf("exposure: listing issues: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT id, target_id, service_id, engine, key, title, severity, cves, detail, state, resolution, resolved_by,
		resolved_at, note, accepted_until, first_seen, last_seen FROM exp_issue WHERE target_id = ?
		ORDER BY CASE state WHEN 'open' THEN 0 WHEN 'handled' THEN 1 ELSE 2 END,
		CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, first_seen, key`, id)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing issues: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []IssueView{}
	for rows.Next() {
		var v IssueView
		var svc, res, by, at, note, until sql.NullString
		var cves, detail string
		if err := rows.Scan(&v.ID, &v.TargetID, &svc, &v.Engine, &v.Key, &v.Title, &v.Severity, &cves, &detail, &v.State, &res, &by, &at, &note, &until,
			&v.FirstSeen, &v.LastSeen); err != nil {
			return nil, fmt.Errorf("exposure: listing issues: %w", err)
		}
		var ids []string
		if err := json.Unmarshal([]byte(cves), &ids); err != nil {
			return nil, fmt.Errorf("exposure: the CVEs of issue %s: %w", v.ID, err)
		}
		v.CVEs = make([]IssueCVE, 0, len(ids))
		for _, c := range ids {
			v.CVEs = append(v.CVEs, IssueCVE{CVE: c, Severity: json.RawMessage("null")})
		}
		if err := json.Unmarshal([]byte(detail), &v.Detail); err != nil {
			return nil, fmt.Errorf("exposure: the detail of issue %s: %w", v.ID, err)
		}
		v.Detail.Evidence = nz(v.Detail.Evidence)
		v.ServiceID, v.Resolution, v.ResolvedBy, v.ResolvedAt, v.Note, v.AcceptedUntil = optText(svc), optText(res), optText(by), optText(at), optText(note), optText(until)
		out = append(out, v)
	}
	return out, rows.Err()
}

// maxScans bounds the scans GET /exposure/tree/{id}/scans lists.
const maxScans = 100

// Scans lists the runs of a target, newest first (GET /exposure/tree/{id}/scans).
func (s *Service) Scans(ctx context.Context, id string) ([]ScanView, error) {
	db := s.cfg.DB.Reader()
	if _, err := loadTarget(ctx, db, id); err != nil {
		return nil, fmt.Errorf("exposure: listing scans: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT r.id, x.target_id, r.status, r.trigger, r.requested_by, x.mode, r.queued_at, r.started_at, r.ended_at,
		r.waiting_for, r.stop_reason, r.error, x.summary FROM exp_scan x JOIN core_run r ON r.id = x.run_id
		WHERE x.target_id = ? ORDER BY r.queued_at DESC, r.rowid DESC LIMIT ?`, id, maxScans)
	if err != nil {
		return nil, fmt.Errorf("exposure: listing scans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ScanView{}
	for rows.Next() {
		v, err := scanScanView(rows)
		if err != nil {
			return nil, fmt.Errorf("exposure: listing scans: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanScanView(sc scanner) (ScanView, error) {
	var v ScanView
	var started, ended, waiting, stop, errText sql.NullString
	var summary string
	if err := sc.Scan(&v.RunID, &v.TargetID, &v.Status, &v.Trigger, &v.RequestedBy, &v.Mode, &v.QueuedAt, &started, &ended, &waiting, &stop, &errText, &summary); err != nil {
		return ScanView{}, err
	}
	var sum scanSummary
	if err := json.Unmarshal([]byte(summary), &sum); err != nil {
		return ScanView{}, fmt.Errorf("summary of %s: %w", v.RunID, err)
	}
	v.StartedAt, v.EndedAt, v.WaitingFor, v.StopReason, v.Error = optText(started), optText(ended), optText(waiting), optText(stop), optText(errText)
	if v.Status == "done" || v.Status == "partial" {
		v.Counts = sum.Counts
	}
	return v, nil
}

// latestResult is what the target list shows of a target's rows: the numbers of what is exposed now, its first open ports, and when
// its newest scan ended.
type latestResult struct {
	Counts     Counts
	Ports      []PortRow
	FinishedAt *string // when the newest scan ended; nil while one runs or when never scanned
}

// The key spaces of the issues of the surface engine: the kind of the issue, then what it is about.
const (
	keyAdminPage  = "admin_page:"  // an admin page open to the Internet, by its URL
	keyCertExpiry = "cert_expiry:" // a certificate that expires within CertWarnDays, by host name
	keyScript     = "nse:"         // a finding an nmap script confirmed, by script id and title
)

// keyRange is the bounds of the keys that start with prefix, for an indexed comparison instead of a pattern.
func keyRange(prefix string) (from, to string) {
	return prefix, prefix[:len(prefix)-1] + string(rune(prefix[len(prefix)-1]+1))
}

// latestResults returns what the rows say of every target that was ever scanned: the numbers of open things and the first
// MaxOpenPorts open services.
func latestResults(ctx context.Context, q querier) (map[string]latestResult, error) {
	out := map[string]latestResult{}
	adminFrom, adminTo := keyRange(keyAdminPage)
	certFrom, certTo := keyRange(keyCertExpiry)
	rows, err := q.QueryContext(ctx, `SELECT t.id,
		(SELECT count(*) FROM exp_host h WHERE h.target_id = t.id),
		(SELECT count(DISTINCT a.ip) FROM exp_address a WHERE a.target_id = t.id),
		(SELECT count(*) FROM exp_service x WHERE x.target_id = t.id AND x.state = 'open'),
		(SELECT count(*) FROM exp_issue i WHERE i.target_id = t.id AND i.state = 'open' AND i.engine = 'surface' AND i.key >= ?1 AND i.key < ?2),
		(SELECT count(*) FROM exp_issue i WHERE i.target_id = t.id AND i.state = 'open' AND i.engine = 'surface' AND i.key >= ?3 AND i.key < ?4),
		(SELECT r.ended_at FROM exp_scan x JOIN core_run r ON r.id = x.run_id WHERE x.target_id = t.id AND r.started_at IS NOT NULL ORDER BY r.started_at DESC LIMIT 1)
		FROM exp_target t WHERE EXISTS (SELECT 1 FROM exp_scan x WHERE x.target_id = t.id)`, adminFrom, adminTo, certFrom, certTo)
	if err != nil {
		return nil, fmt.Errorf("latest results: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var r latestResult
		var fin sql.NullString
		if err := rows.Scan(&id, &r.Counts.Subdomains, &r.Counts.IPs, &r.Counts.Ports, &r.Counts.AdminPanels, &r.Counts.CertsExpiring, &fin); err != nil {
			return nil, fmt.Errorf("latest results: %w", err)
		}
		r.FinishedAt = optText(fin)
		out[id] = r
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("latest results: %w", err)
	}
	for id, r := range out {
		svc, err := servicesOf(ctx, q, id, true)
		if err != nil {
			return nil, err
		}
		r.Ports = make([]PortRow, 0, min(len(svc), MaxOpenPorts))
		rows := make([]ServiceRow, 0, len(svc))
		for _, x := range svc[:min(len(svc), MaxOpenPorts)] {
			r.Ports = append(r.Ports, portRowOf(x))
			rows = append(rows, ServiceRow{IP: x.IP, Port: x.Port, Name: x.Name, Product: x.Product, Version: x.Version, CPE: x.CPE})
		}
		nameAppliances(r.Ports, nil, rows)
		out[id] = r
	}
	return out, nil
}

// portRowOf is a service row as the port lists show it.
func portRowOf(x ServiceView) PortRow {
	p := PortRow{IP: x.IP, Port: x.Port, Service: x.Name, Product: x.Product, Title: x.Title}
	switch x.Ident {
	case identProbed:
		p.Ident = IdentProbed
	case identTable:
		p.Ident = IdentPort
	default:
		p.Ident = IdentNone
	}
	if x.Cert != nil {
		p.CertNames = x.Cert.Names
	}
	return p
}

// ScanRecord is one scan of a public target that wrote its rows, for Settings › Scanning › History.
type ScanRecord struct {
	RunID, TargetID, Target, ScannedAt string
	Date                               string  // the day the scan started (UTC)
	StartedAt                          string  // when the scan started
	FinishedAt                         *string // when its run ended; nil while it runs
	Counts                             Counts  // what the scan itself found
	NotChecked                         int     // steps the scan says it did not check (OpenVAS off, a page ZAP could not scan, …)
	Greenbone                          string  // the state of its OpenVAS step (done, partial, failed, stopped, running); "" when none ran
}

// RecentScans lists the newest scans that wrote their rows, newest first, at most limit (1..500). Read only.
func (s *Service) RecentScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT r.id, x.target_id, coalesce(r.subject_label, ''), r.started_at, r.ended_at, x.summary,
		coalesce((SELECT st.status FROM core_run_step st WHERE st.run_id = r.id AND st.name = ? ORDER BY st.seq DESC LIMIT 1), '')
		FROM exp_scan x JOIN core_run r ON r.id = x.run_id WHERE r.started_at IS NOT NULL
		AND EXISTS (SELECT 1 FROM core_run_step st WHERE st.run_id = r.id AND st.name IN (?, ?) AND st.status = 'done')
		ORDER BY r.started_at DESC LIMIT ?`, stepNameOpenVAS, stepNameSave, stepSurface, max(1, min(500, limit)))
	if err != nil {
		return nil, fmt.Errorf("exposure: recent scans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ScanRecord{}
	for rows.Next() {
		var r ScanRecord
		var ended sql.NullString
		var summary string
		if err := rows.Scan(&r.RunID, &r.TargetID, &r.Target, &r.StartedAt, &ended, &summary, &r.Greenbone); err != nil {
			return nil, fmt.Errorf("exposure: recent scans: %w", err)
		}
		var sum scanSummary
		if err := json.Unmarshal([]byte(summary), &sum); err != nil {
			return nil, fmt.Errorf("exposure: recent scan %s: %w", r.RunID, err)
		}
		if sum.Found != nil {
			r.Counts = *sum.Found
		}
		r.NotChecked, r.ScannedAt, r.FinishedAt = len(sum.NotChecked), r.StartedAt, optText(ended)
		r.Date = r.StartedAt[:min(10, len(r.StartedAt))]
		out = append(out, r)
	}
	return out, rows.Err()
}
