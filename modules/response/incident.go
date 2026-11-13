package response

import (
	"context"
	"database/sql"
	"net/http"
	"net/netip"
	"slices"
	"sort"
)

// Respond from an incident (D-509, S-RESP-3, customer walk W1-16). Respond on an incident opens a panel for that incident's source and
// offers only what can really happen to it. Asking for one creates a pending request through the same planner and gates as a rule
// run (typed values, never-touch, D-469, the connection), with source "person": it waits for approval, expires, is undone after
// incidentTTL and is logged like every request. Nothing here sends a step to a device (FORBID-1).

// IncidentInfo is what response needs of an incident: the notify incident, and for a trap the source of its hit (honeypot), joined
// by cmd/vedette. SourceIP is "" when the incident names no single address (another kind, a test hit, an unreadable hit).
type IncidentInfo struct {
	ID, Kind, Title, Action string
	Status                  string // new, acknowledged or resolved: a resolved incident offers nothing
	SourceIP                string
	AssetID                 string // the inventory device of the source, "" when not known
	HitKind                 string // a trap's hit: service, token or scan
	// Unconfirmed: the source may be forged. A scan hit can be made from attempts that completed no handshake, and a UDP trap hit
	// from one datagram (honeypot D-467); it counts as confirmed only when the same source also completed a connection to a trap
	// service (a TCP service hit) near it. Nothing is offered for an unconfirmed source.
	Unconfirmed bool
}

// IncidentReader reads one incident (Config.Incidents). ok is false for an unknown id or while the notify module is off.
type IncidentReader interface {
	Incident(ctx context.Context, id string) (IncidentInfo, bool, error)
}

// IncidentPanel is GET /response/incidents/{id} (contract.ts IncidentPanel).
type IncidentPanel struct {
	Incident  IncidentRef      `json:"incident"`
	Note      *string          `json:"note"` // why nothing can be asked for a source that is there: resolved (no options), or unconfirmed
	Source    *IncidentSource  `json:"source"`
	Options   []IncidentOption `json:"options"`
	Execution bool             `json:"execution"`
}

// IncidentRef names the incident in the panel.
type IncidentRef struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Action string `json:"action"`
	Status string `json:"status"`
}

// IncidentSource is the address the response acts on, read by the server from the incident.
type IncidentSource struct {
	IP      string  `json:"ip"`
	Device  *string `json:"device"`
	AssetID *string `json:"asset_id"`
	Scope   string  `json:"scope"` // "lan" (the block list never publishes it, D-469) or "public"
}

// IncidentOption is one action that can be asked for the source.
type IncidentOption struct {
	ActionID   string  `json:"action_id"`
	Name       string  `json:"name"`
	Title      string  `json:"title"`
	Connection *string `json:"connection"`
	Device     bool    `json:"device"`
	Risk       Risk    `json:"risk"`
	TTLMin     int     `json:"ttl_min"`
	Ready      bool    `json:"ready"`
	Why        *string `json:"why"`
	Requested  bool    `json:"requested"`
}

// incidentTTL is the undo time of a request asked from an incident: 24 hours, as the trap rule templates (tpl-trap-fgt).
const incidentTTL = 1440

const sourcePerson = "person"

const (
	resolvedMsg    = "This incident is resolved, so nothing is offered. Reopen it in Incidents to act on it."
	unconfirmedMsg = "The source of a scan or of a UDP request can be forged: it completed no connection, so this address may belong to someone innocent. Confirm on the device first. Nothing is offered for it."
	scanConfirmed  = " (a scan; the same source also completed a connection to a trap, so its address is not forged)"
)

var errNoIncident = fail(http.StatusNotFound, "not_found", "No such incident. It may have been removed.")

// incidentSource reads the incident and its source. The address is checked here, at the edge: anything that is not one plain
// address (a zone, garbage) is no source.
func (s *Service) incidentSource(ctx context.Context, id string) (IncidentInfo, *IncidentSource, error) {
	if !idRE.MatchString(id) || s.cfg.Incidents == nil {
		return IncidentInfo{}, nil, errNoIncident
	}
	inc, ok, err := s.cfg.Incidents.Incident(ctx, id)
	if err != nil {
		return IncidentInfo{}, nil, err
	}
	if !ok {
		return IncidentInfo{}, nil, errNoIncident
	}
	inc.Title, inc.Action = oneLine(inc.Title, 200), oneLine(inc.Action, 1000)
	a, err := netip.ParseAddr(inc.SourceIP)
	if err != nil || a.Zone() != "" {
		return inc, nil, nil
	}
	a = a.Unmap()
	src := &IncidentSource{IP: a.String(), Scope: "lan"}
	if publishable(a) {
		src.Scope = "public"
	}
	if inc.AssetID != "" && s.cfg.Directory != nil {
		d, ok, err := s.cfg.Directory.Device(ctx, inc.AssetID)
		switch {
		case err != nil: // the source still counts; it only names no device
			s.cfg.Log.WarnContext(ctx, "response: incident source device could not be read", "error", err)
		case ok && d.IP == src.IP: // the device may have moved since the hit
			src.Device, src.AssetID = strp(oneLine(d.Name, 120)), strp(d.ID)
		}
	}
	return inc, src, nil
}

// incidentOffers lists the catalog actions offered for a source, by name: every device action whose only parameter is {ip} (block an
// address on a firewall or a switch ACL) that is switched on or has a connection chosen, and the block list for a public address.
// A port shutdown or a quarantine VLAN needs the switch port, which no source gives yet, so it is not offered.
func incidentOffers(src *IncidentSource, cats map[string]catRow) []catRow {
	var out []catRow
	for _, c := range cats {
		p := c.params()
		switch {
		case c.ID == "blocklist_add":
			if src.Scope == "public" {
				out = append(out, c)
			}
		case c.device() && len(p) == 1 && p[0] == PIP && (c.Enabled || c.ConnectionID != ""):
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].device() != out[j].device() {
			return !out[i].device() // the block list first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func incidentEvent(inc IncidentInfo, src *IncidentSource) Det {
	return Det{ID: "incident:" + inc.ID, Trigger: "honeypot", Summary: inc.Title,
		Fields: map[string]string{"source_ip": src.IP, "source_device": deref2(src.Device), "decoy": "", "kind": orStr(inc.HitKind, "service"), "switch_port": ""}}
}

// planIncident plans one action on the source, through the planner of a rule run: {ip} resolves to the source the server read.
func (s *Service) planIncident(c catRow, inc IncidentInfo, src *IncidentSource, cats map[string]catRow, cs conns, never []AllowEntry) (planned, *planFail) {
	ttl := incidentTTL
	a := RuleAction{ActionID: c.ID, Params: map[string]string{string(PIP): "{{trigger.source_ip}}"}, TTLMin: &ttl}
	return s.planAction(a, incidentEvent(inc, src), incidentWhy(inc), cats, cs, never)
}

// incidentWhy is the reason the request carries (its approval message and the change's "after" line): the incident, and for a scan
// that the source is confirmed.
func incidentWhy(inc IncidentInfo) string {
	why := "Incident: " + inc.Title
	if inc.HitKind == "scan" {
		why += scanConfirmed
	}
	return oneLine(why, 300)
}

// IncidentPanel is GET /response/incidents/{id}: the incident's source and the actions that can be asked for it, each saying why
// it is not ready. It changes nothing.
func (s *Service) IncidentPanel(ctx context.Context, id string) (IncidentPanel, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return IncidentPanel{}, err
	}
	inc, src, err := s.incidentSource(ctx, id)
	if err != nil {
		return IncidentPanel{}, err
	}
	q := s.cfg.DB.Reader()
	st, err := loadSettings(ctx, q)
	if err != nil {
		return IncidentPanel{}, err
	}
	out := IncidentPanel{Incident: IncidentRef{ID: inc.ID, Kind: inc.Kind, Title: inc.Title, Action: inc.Action, Status: inc.Status}, Source: src, Options: []IncidentOption{}, Execution: st.Execution}
	if src == nil {
		return out, nil
	}
	if inc.Status == "resolved" {
		out.Note = strp(resolvedMsg)
		return out, nil
	}
	if inc.Unconfirmed {
		out.Note = strp(unconfirmedMsg)
	}
	cats, err := s.cats(ctx, q)
	if err != nil {
		return IncidentPanel{}, err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return IncidentPanel{}, err
	}
	never, nt, err := s.neverTouchOrRefusal(ctx, q)
	if err != nil {
		return IncidentPanel{}, err
	}
	open, err := openKeys(ctx, q, s.now())
	if err != nil {
		return IncidentPanel{}, err
	}
	held := maintenanceNow(st, s.now())
	for _, c := range incidentOffers(src, cats) {
		o := IncidentOption{ActionID: c.ID, Name: c.Name, Title: c.Name, Device: c.device(), Risk: c.Risk, TTLMin: incidentTTL}
		if cn, ok := cs.get(c.ConnectionID); ok && c.device() {
			o.Connection = strp(cn.Name)
		}
		why := ""
		switch pl, f := s.planIncident(c, inc, src, cats, cs, never); {
		case inc.Unconfirmed:
			why = unconfirmedMsg
		case !c.Enabled:
			why = "This action is switched off in the action catalog (Settings, AI response). An administrator turns it on."
		case nt != nil:
			why = nt.Message
		case f != nil:
			why = f.msg
		default:
			o.Title = pl.rec.Title
			o.Requested = open[pl.key]
			switch {
			case c.device() && !st.Execution:
				why = offMsg
			case held != nil:
				why = "Held: maintenance window \"" + oneLine(held.Name, 80) + "\" is active."
			case st.BreakerTrippedAt != nil:
				why = breakerMsg
			case o.Requested:
				why = "Already asked for: see Requests."
			}
		}
		o.Ready = why == ""
		if why != "" {
			o.Why = strp(why)
		}
		out.Options = append(out.Options, o)
	}
	return out, nil
}

// RequestFromIncident is POST /response/incidents/{id}/request: ask for approval of one offered action on the incident's source. The
// source is read again here (the browser never sends it); the gates are those of RequestProposal without the AI ones. The request is
// pending: a person approves it (D-41).
func (s *Service) RequestFromIncident(ctx context.Context, who Actor, id, actionID string) (ActionRequest, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return ActionRequest{}, err
	}
	inc, src, err := s.incidentSource(ctx, id) // outside the lock: it reads other modules
	if err != nil {
		return ActionRequest{}, err
	}
	target := "incident:" + oneLine(id, 96)
	switch {
	case src == nil:
		return ActionRequest{}, s.refuse(ctx, fail(http.StatusConflict, "no_source", "This incident names no single address Vedette can act on. Nothing was requested."), target, who.Email)
	case inc.Status == "resolved":
		return ActionRequest{}, s.refuse(ctx, fail(http.StatusConflict, "incident_resolved", resolvedMsg), target, who.Email)
	case inc.Unconfirmed:
		return ActionRequest{}, s.refuse(ctx, fail(http.StatusConflict, "source_unconfirmed", unconfirmedMsg), target, who.Email)
	}
	var refusal error
	var out request
	var fx effects
	err = func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			refusal, fx = nil, effects{}
			no := func(e error) error { refusal = e; return nil }
			cats, err := s.cats(ctx, tx)
			if err != nil {
				return err
			}
			i := slices.IndexFunc(incidentOffers(src, cats), func(c catRow) bool { return c.ID == actionID })
			if i < 0 {
				return no(fail(http.StatusForbidden, "tool_not_allowed", "This action is not offered for this incident. Nothing was requested."))
			}
			c := incidentOffers(src, cats)[i]
			if !c.Enabled {
				return no(fail(http.StatusForbidden, "tool_not_allowed", "The action \""+c.Name+"\" is not enabled in the action catalog."))
			}
			st, err := loadSettings(ctx, tx)
			if err != nil {
				return err
			}
			if c.device() && !st.Execution { // a box action (the block list) is not stopped by the switch (INV-9)
				return no(fail(http.StatusConflict, "execution_off", offMsg))
			}
			if w := maintenanceNow(st, s.now()); w != nil {
				return no(fail(http.StatusConflict, "maintenance", "Held: maintenance window \""+oneLine(w.Name, 80)+"\" is active. Nothing was requested."))
			}
			if st.BreakerTrippedAt != nil {
				return no(fail(http.StatusConflict, "circuit_open", breakerMsg))
			}
			cs, err := s.loadConns(ctx)
			if err != nil {
				return err
			}
			never, nt, err := s.neverTouchOrRefusal(ctx, tx)
			if err != nil {
				return err
			}
			if nt != nil {
				return no(nt)
			}
			pl, f := s.planIncident(c, inc, src, cats, cs, never)
			if f != nil {
				return no(planRefusal(f))
			}
			open, err := openKeys(ctx, tx, s.now())
			if err != nil {
				return err
			}
			if open[pl.key] {
				return no(fail(http.StatusConflict, "already_requested", "This action already has an open request or is in force for this address."))
			}
			if tripped, err := s.checkBreaker(ctx, tx, &st, 1, &fx); err != nil {
				return err
			} else if tripped {
				return no(fail(http.StatusConflict, "circuit_open", breakerMsg))
			}
			item := pl.rec
			item.ID = newID("it")
			out, err = s.createRequest(ctx, tx, st, reqInit{Source: sourcePerson, Actor: who.Email + " (app)", ProposalID: target, TriggerSummary: incidentWhy(inc),
				AssetID: deref2(src.AssetID), AssetName: firstNonEmpty(deref2(src.Device), src.IP), Title: item.Title, Recs: []itemRec{item}}, &fx)
			return err
		})
	}()
	if err != nil {
		return ActionRequest{}, err
	}
	s.run(ctx, &fx)
	if refusal != nil {
		return ActionRequest{}, s.refuse(ctx, refusal, target, who.Email)
	}
	if now, err := s.get(ctx, out.ID); err == nil {
		return now, nil
	}
	return out.view(), nil
}
