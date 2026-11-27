package exposure

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corerun "github.com/knt048/vedette/core/run"
	"github.com/knt048/vedette/core/store"
)

// The reuse of an address's own deep scan by a domain's deep scan (INV-47).
//
// A domain whose name points at an address that was deep-scanned a moment ago as its own target would send the same port sweep,
// nmap -sV and scripts, OpenVAS and nmap's disruptive scripts again (about an hour for the same results), doubling the load on the
// customer's firewall for nothing new. So the address-level layer of the domain's step for that address is taken from that run instead,
// when every rule below holds; otherwise the address is scanned as before (fail closed). The web layer of the domain always runs there:
// the templates with the domain's own step, ZAP by name, the certificates by name (a different Host can be a different web app).
//
// The source is the newest finished run of the IP target whose value is the address, and only when: it is a deep run that ended done
// (a partly done, failed or stopped run is never a source), it started within ReuseWindow and not after now, the IP target's testing
// terms and deep-scan settings were last changed before it started, its port and service steps ran, its settings allowed at least
// what the domain's step allows now (no group it turned off that the step has on, the normal speed unless the step is gentle, every
// port and web path it skipped skipped by the step too), and its OpenVAS and disruptive steps ran when the domain's step would run
// them now on an address with open ports; every open port this run found there was seen by it; at least one port it saw open is one
// the step does not skip when it would give a finding; and no finding it would give comes from a check the domain's step would not
// run (reuseNarrower). A reuse must never close or reopen anything of the domain by itself: when the domain holds
// an open port of the address the source did not see, an open address-level issue (nmap scripts, OpenVAS, the comparison with
// exploited CVEs) the source did not report, or one gone or marked patched or mitigated that it did report, the address is scanned.

// ReuseWindow is how old (from its start) a deep scan of an address may be for a domain's deep scan to reuse it.
const ReuseWindow = 24 * time.Hour

// The run item that links the run a domain's step reused (the run page links a "run" subject to its page).
const (
	itemRun       = "run"
	outcomeReused = "reused"
)

// reuseSource is the run a domain's deep step reuses for one address, with what it found there.
type reuseSource struct {
	runID    string
	target   string // the IP target that ran it
	ip       string
	started  time.Time
	services []ServiceRow
	// issues are the source's findings at the address that become the domain's: nmap's scripts, and OpenVAS and nmap's disruptive
	// scripts when the domain's step would have run them (issueIn.reused).
	issues []issueIn
	// openVAS and disruptive say the source's OpenVAS and disruptive results stand for the domain's step at the address.
	openVAS, disruptive bool
}

// line is what the steps of the domain's run say of the address: "Reused from the deep scan of 203.0.113.5 at <time>".
func (s *Service) reuseLine(r *reuseSource) string {
	return "Reused from the deep scan of " + r.ip + " at " + s.momentText(r.started)
}

// modeGroups are the groups m has on.
func modeGroups(m ScanMode) Groups {
	var g Groups
	for _, x := range []struct {
		on bool
		g  Groups
	}{{m.DoS, GroupDoS}, {m.Logins, GroupLogins}, {m.Change, GroupChange}, {m.WebActive, GroupWebActive}, {m.OpenVAS, GroupOpenVAS}} {
		if x.on {
			g |= x.g
		}
	}
	return g
}

// groupsNamed is the groups of the names a run's summary kept (Groups.Names); ok false when a name is not one of them.
func groupsNamed(names []string) (Groups, bool) {
	var g Groups
	for _, n := range names {
		i := slices.IndexFunc(groupNames, func(x struct {
			g    Groups
			name string
		}) bool {
			return x.name == n
		})
		if i < 0 {
			return 0, false
		}
		g |= groupNames[i].g
	}
	return g, true
}

// reuseFor is the source a domain's deep step stD may reuse for address a, or nil with why not (for the log; "" when the address has
// no IP target). st is the domain's run; stD the step as deepGate gave it; seen the ports this run itself found open at the address.
// Every error is a no (fail closed).
func (s *Service) reuseFor(ctx context.Context, st, stD ScanTarget, a deepAddr, seen []PortRow) (*reuseSource, string) {
	q := s.cfg.DB.Reader()
	ip := a.ip.String()
	it, found, err := loadTargetByValue(ctx, q, ip)
	if err != nil || !found || it.Kind != KindIP || it.Deep.Problem != nil {
		return nil, ""
	}
	var runID, status, started, ended, mode, summary, by string
	err = q.QueryRowContext(ctx, `SELECT r.id, r.status, coalesce(r.started_at, ''), r.ended_at, x.mode, x.summary, r.requested_by FROM exp_scan x JOIN core_run r ON r.id = x.run_id
		WHERE x.target_id = ? AND r.ended_at IS NOT NULL ORDER BY r.ended_at DESC, r.started_at DESC LIMIT 1`, it.ID).Scan(&runID, &status, &started, &ended, &mode, &summary, &by)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, "no finished scan of the address"
	case err != nil:
		return nil, "its scans could not be read"
	case status != string(corerun.Done) || mode != modeDeep:
		return nil, "its newest scan is not a deep scan that ended done"
	}
	at, err1 := parseTS(started)
	end, err2 := parseTS(ended)
	now := s.clock()
	switch {
	case err1 != nil || err2 != nil || at.After(now) || end.After(now):
		return nil, "its newest scan has no readable time"
	case now.Sub(at) > ReuseWindow:
		return nil, "its newest deep scan started more than 24 hours ago"
	}
	// The IP target's terms and settings as that run had them: a change since (a group turned on, fewer ports skipped) is never reused.
	var setAt, termsAt string
	var termsDisruptive bool
	if err := q.QueryRowContext(ctx, `SELECT updated_at FROM exp_deep_setting WHERE target_id = ?`, it.ID).Scan(&setAt); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "its settings could not be read"
	}
	if err := q.QueryRowContext(ctx, `SELECT at, disruptive IS 1 FROM exp_consent WHERE target_id = ? AND kind = 'terms'`, it.ID).Scan(&termsAt, &termsDisruptive); err != nil {
		return nil, "its testing terms are not accepted now"
	}
	if setAt >= started || termsAt >= started {
		return nil, "its testing terms or deep-scan settings changed after its deep scan started"
	}
	var sum scanSummary
	if json.Unmarshal([]byte(summary), &sum) != nil || sum.Settings == nil {
		return nil, "the settings of its deep scan are not recorded"
	}
	if why := scopeCovers(*sum.Settings, it.Deep, stD); why != "" {
		return nil, why
	}
	steps, err := stepStates(ctx, q, runID)
	if err != nil {
		return nil, "its steps could not be read"
	}
	src := &reuseSource{runID: runID, target: it.ID, ip: ip, started: at}
	if src.services, err = sourceServices(ctx, q, it.ID, runID, ip, stD); err != nil {
		return nil, "its services could not be read"
	}
	open := len(src.services) > 0
	had := map[int]bool{}
	for _, r := range src.services {
		had[r.Port] = true
	}
	if slices.ContainsFunc(seen, func(p PortRow) bool { return !p.Unchecked && !stD.Skips(p.Port) && !had[p.Port] }) {
		return nil, "this scan found an open port there that its deep scan did not see" // the address changed since: scan it
	}
	switch svc := steps[stepNameServiceDeep]; {
	case steps[stepNamePortsDeep] != corerun.Done:
		return nil, "its port scan did not run"
	case svc != corerun.Done && (svc != corerun.Skipped || open):
		return nil, "its service identification did not run"
	}
	gbOn := false
	if s.cfg.Greenbone != nil && stD.Mode.OpenVAS {
		on, _, _, err := loadGreenbone(ctx, q)
		if err != nil {
			return nil, "OpenVAS's settings could not be read"
		}
		gbOn = on
	}
	src.openVAS = gbOn && steps[stepNameOpenVAS] == corerun.Done
	if gbOn && open && !src.openVAS {
		return nil, "OpenVAS did not run in its deep scan"
	}
	_, canD := s.cfg.Services.(DisruptiveScanner) // the disruptive step's own conditions for a domain's address (disruptiveStep)
	needD := canD && stD.Mode.Disruptive && stD.Domain == nil && a.box && a.inZone && st.User != SystemUser
	src.disruptive = needD && steps[stepNameDisruptive] == corerun.Done
	if needD && open && !src.disruptive {
		return nil, "nmap's disruptive scripts did not run in its deep scan"
	}
	reported, err := sourceIssues(ctx, q, it.ID, runID, ip, stD)
	if err != nil {
		return nil, "its findings could not be read"
	}
	for _, in := range reported {
		switch {
		case in.engine == EngineSurface && strings.HasPrefix(in.key, keyScript):
		case in.engine == EngineSurface && strings.HasPrefix(in.key, keyScriptDisruptive) && src.disruptive:
		case in.engine == EngineOpenVAS && src.openVAS:
		default:
			continue
		}
		in.reused = true
		src.issues = append(src.issues, in)
	}
	if !open && len(src.issues) > 0 { // every open port it saw is one the step skips: the step would send nothing there
		return nil, "this scan skips every open port its deep scan saw there"
	}
	if why := reuseNarrower(stD, it.Deep, termsDisruptive && by != SystemUser, src.issues); why != "" {
		return nil, why
	}
	if why, err := s.reuseKeepsRows(ctx, q, st.ID, src, reported, stD); err != nil {
		return nil, "the domain's rows could not be read"
	} else if why != "" {
		return nil, why
	}
	return src, ""
}

// disruptiveGroups are the groups of nmap's disruptive scripts, and of OpenVAS's brute force, default accounts and denial-of-service
// families (levelOf).
const disruptiveGroups = GroupDoS | GroupLogins | GroupChange

// reuseNarrower says "" when no finding a reuse would take (ins) can come from a check the domain's step stD would not run: a reuse
// never reports what the domain's own terms and settings would not have found. The source's full sweep ran nmap's scripts of its
// target's settings' groups (d, unchanged since it started); its OpenVAS config and disruptive scripts followed the disruptive groups
// of its run, at most those same groups and only with the disruptive terms on a run a person started (disruptive). The sweep also
// leaves out the scripts that follow ports another service names (nmapargv's followScripts) as soon as any port is skipped, so a
// source that skipped none ran scripts a step that skips one would not. A finding does not say which check found it, so one such
// finding is enough to scan the address instead.
func reuseNarrower(stD ScanTarget, d DeepSettings, disruptive bool, ins []issueIn) string {
	sweep, ran := d.Groups()&disruptiveGroups, Groups(0)
	if disruptive {
		ran = sweep
	}
	follows := len(d.SkipPorts) == 0 && len(stD.SkipPorts) > 0
	for _, in := range ins {
		switch {
		case in.engine == EngineSurface && strings.HasPrefix(in.key, keyScript) && sweep&^stD.Groups != 0:
			return "its deep scan ran nmap's scripts of a group this scan has turned off"
		case in.engine == EngineSurface && strings.HasPrefix(in.key, keyScript) && follows:
			return "its deep scan skipped no port, so it ran nmap's scripts that this scan leaves out while it skips one"
		case (in.engine == EngineOpenVAS || strings.HasPrefix(in.key, keyScriptDisruptive)) && ran&^modeGroups(stD.Mode) != 0:
			return "its deep scan ran disruptive checks this scan does not run"
		}
	}
	return ""
}

// scopeCovers says "" when the settings a source run used (sum, with its target's settings d, unchanged since) allowed at least what
// the domain's step stD allows now; else why not.
func scopeCovers(sum settingsSummary, d DeepSettings, stD ScanTarget) string {
	off, ok := groupsNamed(sum.Off)
	switch {
	case !ok:
		return "the settings of its deep scan cannot be read"
	case off&(modeGroups(stD.Mode)|stD.Groups) != 0:
		return "its deep scan ran with a group turned off that this scan has on"
	case stD.Groups&^d.Groups() != 0:
		return "its deep scan ran with fewer groups than this scan has on"
	case sum.Speed != SpeedNormal && !stD.Gentle:
		return "its deep scan ran at the gentle speed"
	case slices.ContainsFunc(sum.SkipPorts, func(p int) bool { return !stD.Skips(p) }):
		return "its deep scan skipped ports this scan does not skip"
	case slices.ContainsFunc(sum.SkipPaths, func(p string) bool {
		return !slices.ContainsFunc(stD.SkipPaths, func(q string) bool { return strings.HasPrefix(p, q) })
	}):
		return "its deep scan skipped web paths this scan does not skip"
	}
	return ""
}

// stepStates is the state of each step of run id, by name.
func stepStates(ctx context.Context, q querier, id string) (map[string]corerun.Status, error) {
	rows, err := q.QueryContext(ctx, `SELECT name, status FROM core_run_step WHERE run_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]corerun.Status{}
	for rows.Next() {
		var name, status string
		if err := rows.Scan(&name, &status); err != nil {
			return nil, err
		}
		out[name] = corerun.Status(status)
	}
	return out, rows.Err()
}

// sourceServices are the open TCP services run id saw at ip (its rows of target that it last saw), without the ports stD skips.
func sourceServices(ctx context.Context, q querier, target, id, ip string, stD ScanTarget) ([]ServiceRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT port, name, product, version, cpe, ident FROM exp_service
		WHERE target_id = ? AND ip = ? AND proto = 'tcp' AND state = 'open' AND last_run_id = ? ORDER BY port`, target, ip, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ServiceRow
	for rows.Next() {
		r := ServiceRow{IP: ip}
		var ident string
		if err := rows.Scan(&r.Port, &r.Name, &r.Product, &r.Version, &r.CPE, &ident); err != nil {
			return nil, err
		}
		if ident != "none" {
			r.Method = ident
		}
		if !stD.Skips(r.Port) {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// addrIssue is a finding of a target at one address: its engine, key and port (0: about the address), its state and resolution.
type addrIssue struct {
	engine     IssueEngine
	key        string
	port       int
	state, res string
}

func (x addrIssue) id() string { return string(x.engine) + "|" + x.key + "|" + fmt.Sprint(x.port) }

// addressLevel says an issue is of the address-level layer: nmap's scripts (the first run and the disruptive one), OpenVAS, and the
// comparison with exploited CVEs (which reads the services that layer identified).
func addressLevel(e IssueEngine, key string) bool {
	switch e {
	case EngineOpenVAS, EngineMatch:
		return true
	case EngineSurface:
		return strings.HasPrefix(key, keyScript) || strings.HasPrefix(key, keyScriptDisruptive)
	}
	return false
}

// issuesAt are target's address-level issues at ip (on a service of ip, or naming ip in their key), without those on a port stD skips;
// lastRun, when set, keeps only those that run reported.
func issuesAt(ctx context.Context, q querier, target, ip, lastRun string, stD ScanTarget) ([]addrIssue, []issueIn, error) {
	rows, err := q.QueryContext(ctx, `SELECT i.engine, i.key, i.title, i.severity, i.cves, i.detail, i.state, coalesce(i.resolution, ''), coalesce(x.ip, ''), coalesce(x.port, 0)
		FROM exp_issue i LEFT JOIN exp_service x ON x.id = i.service_id WHERE i.target_id = ? AND (? = '' OR i.last_run_id = ?)`, target, lastRun, lastRun)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []addrIssue
	var ins []issueIn
	for rows.Next() {
		var x addrIssue
		var title, sev, cves, detail, at string
		if err := rows.Scan(&x.engine, &x.key, &title, &sev, &cves, &detail, &x.state, &x.res, &at, &x.port); err != nil {
			return nil, nil, err
		}
		if at == "" {
			at = keyAddr(x.engine, x.key)
		}
		if ipKey(at) != ip || !addressLevel(x.engine, x.key) || (x.port > 0 && stD.Skips(x.port)) {
			continue
		}
		in := issueIn{engine: x.engine, key: x.key, port: x.port, title: title, severity: sev}
		if x.port > 0 {
			in.ip = ip
		}
		if json.Unmarshal([]byte(cves), &in.cves) != nil || json.Unmarshal([]byte(detail), &in.detail) != nil {
			return nil, nil, fmt.Errorf("issue %s %s: unreadable detail", x.engine, x.key)
		}
		out, ins = append(out, x), append(ins, in)
	}
	return out, ins, rows.Err()
}

// sourceIssues are the address-level findings run id reported at ip, as the domain's write takes them.
func sourceIssues(ctx context.Context, q querier, target, id, ip string, stD ScanTarget) ([]issueIn, error) {
	_, ins, err := issuesAt(ctx, q, target, ip, id, stD)
	return ins, err
}

// reuseKeepsRows says "" when reusing src for domain closes and reopens nothing there: every open port of the address the domain
// holds was seen by src, every open address-level issue it holds there src reported (one src's engines would not run for the domain,
// OpenVAS or the disruptive scripts, is left as it is and does not count), and none src reported is gone or marked patched or mitigated
// on the domain. Otherwise why the address is scanned instead.
func (s *Service) reuseKeepsRows(ctx context.Context, q querier, domain string, src *reuseSource, reported []issueIn, stD ScanTarget) (string, error) {
	seen := map[int]bool{}
	for _, r := range src.services {
		seen[r.Port] = true
	}
	rows, err := q.QueryContext(ctx, `SELECT port FROM exp_service WHERE target_id = ? AND ip = ? AND state = 'open'`, domain, src.ip)
	if err != nil {
		return "", err
	}
	var stale []int
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			_ = rows.Close()
			return "", err
		}
		if !seen[p] && !stD.Skips(p) {
			stale = append(stale, p)
		}
	}
	if err := cmp.Or(rows.Err(), rows.Close()); err != nil {
		return "", err
	}
	if len(stale) > 0 {
		return "the domain holds open ports there that its deep scan did not see", nil
	}
	by := map[string]bool{}
	for _, in := range reported {
		by[addrIssue{engine: in.engine, key: in.key, port: in.port}.id()] = true
	}
	held, _, err := issuesAt(ctx, q, domain, src.ip, "", stD)
	if err != nil {
		return "", err
	}
	for _, x := range held {
		switch {
		case x.engine == EngineOpenVAS && !src.openVAS, strings.HasPrefix(x.key, keyScriptDisruptive) && !src.disruptive:
			continue // this step would not run that engine there: its issues stay as they are either way
		case x.state == IssueOpen && !by[x.id()]:
			return "the domain holds findings there that its deep scan did not report", nil
		case by[x.id()] && (x.state == IssueGone || x.state == IssueHandled && (x.res == string(ResolvedPatched) || x.res == string(ResolvedMitigated))):
			return "a finding its deep scan reported is closed or marked fixed on the domain", nil
		}
	}
	return "", nil
}

// reuseIP is the deep step of a domain's address whose address-level layer src gives: its services become the step's, its findings
// are written with the run's results (scanWrite.reused), and the templates run there with the domain's step (the web layer). It
// says DeepScanned, or DeepIncomplete when the run was stopped.
func (s *Service) reuseIP(ctx context.Context, stD ScanTarget, a deepAddr, src *reuseSource, sub Content, how string, c *Content) (string, error) {
	line := s.reuseLine(src)
	now := store.FormatTS(s.clock())
	sub.Checks = append(sub.Checks, CheckRow{Kind: "deep", At: now, Text: "deep scan at the testing terms depth (" + how + ")."})
	sub.Services = append(sub.Services, src.services...)
	parts := []string{"ports, services and nmap's scripts"}
	if src.openVAS {
		parts = append(parts, "OpenVAS")
	}
	if src.disruptive {
		parts = append(parts, "nmap's disruptive scripts")
	}
	sub.Checks = append(sub.Checks, CheckRow{Kind: "services", At: now, Text: fmt.Sprintf("%s (%s): %s, %s. The templates ran here again in this scan.",
		line, strings.Join(parts, ", "), servicesRead(src.services), plural(len(src.issues), "finding"))})
	s.observerOf(ctx).noteReused(src)
	var err error
	if sub, err = s.runTemplates(ctx, stD, a.ip, sub); err != nil {
		return DeepIncomplete, err
	}
	mergeAddress(c, sub, a.label(), a.ip.String())
	return DeepScanned, nil
}

// mergeAddress adds what the deep step of one of a domain's addresses found to the run's content c, each line with the address in front.
func mergeAddress(c *Content, sub Content, label, ip string) {
	c.Ports = addServicePorts(c.Ports, sub.Services, sub.Scripts, ip) // an open port the deep scan found is an open port of the domain (counts, the day diff, INV-22)
	c.Services = append(c.Services, sub.Services...)
	c.Scripts = append(c.Scripts, sub.Scripts...)
	c.Templates = append(c.Templates, sub.Templates...)
	c.TemplatesRan, c.ScriptsRan = append(c.TemplatesRan, sub.TemplatesRan...), append(c.ScriptsRan, sub.ScriptsRan...)
	for _, r := range sub.Checks {
		r.Text = clipText(label+": "+r.Text, maxLineText)
		c.Checks = append(c.Checks, r)
	}
	for _, r := range sub.NotChecked {
		r.Text = clipText(label+": "+r.Text, maxLineText)
		c.NotChecked = append(c.NotChecked, r)
	}
}

// noteReused records that this run reused src for its address.
func (o *observer) noteReused(src *reuseSource) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.reused == nil {
		o.reused = map[string]*reuseSource{}
	}
	o.reused[ipKey(src.ip)] = src
}

// reusedOf is the source this run reused for ip; nil when none.
func (o *observer) reusedOf(ip string) *reuseSource {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.reused[ipKey(ip)]
}

// reusedAll are the sources this run reused, by address.
func (o *observer) reusedAll() []*reuseSource {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]*reuseSource, 0, len(o.reused))
	for _, r := range o.reused {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *reuseSource) int { return cmpAddr(a.ip, b.ip) })
	return out
}

// reusedWrite is what the writer takes of the run's reuses: the findings, and the addresses whose services came from a source (the
// comparison with exploited CVEs closes nothing there: it did not read those services itself).
func (o *observer) reusedWrite() ([]issueIn, map[string]bool) {
	var ins []issueIn
	at := map[string]bool{}
	for _, r := range o.reusedAll() {
		ins = append(ins, r.issues...)
		at[ipKey(r.ip)] = true
	}
	return ins, at
}

// recordReused links each run this one reused from its page (a run item), with what was reused.
func (s *Service) recordReused(ctx context.Context, x *corerun.Exec) {
	for _, r := range s.observerOf(ctx).reusedAll() {
		parts := []string{"ports, services and nmap's scripts"}
		if r.openVAS {
			parts = append(parts, "OpenVAS")
		}
		if r.disruptive {
			parts = append(parts, "nmap's disruptive scripts")
		}
		_ = x.AddItem(ctx, corerun.Item{SubjectKind: itemRun, SubjectID: r.runID, Label: clipText("Deep scan of "+r.ip+" at "+s.momentText(r.started), 200),
			Outcome: outcomeReused, Note: clipText("Its "+strings.Join(parts, ", ")+" at "+r.ip+" were reused by this scan; this scan ran its own web checks there.", 500)})
	}
}
