package response

import (
	"context"
	"database/sql"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// Connection kinds (D-58): generic kinds only, no vendor.
func isHTTPKind(k string) bool { return k == "http" || k == "netconf-restconf" || k == "automation" }
func isMCP(k string) bool      { return k == "mcp-http" || k == "mcp-stdio" }

// kindFields says which template fields a connection kind uses.
var kindFields = map[string][]string{
	"http": {"method", "path", "headers", "body"}, "netconf-restconf": {"method", "path", "headers", "body"}, "automation": {"method", "path", "headers", "body"},
	"ssh": {"cli"}, "mcp-http": {"body"}, "mcp-stdio": {"body"},
}

const readOnlyText = "Read-only: this connection has no write tools"

// kindProblem is "" when the template only uses the fields of the kind.
func kindProblem(kind string, t Tpl, what string) string {
	var extra []string
	for _, f := range []struct{ name, v string }{{"cli", t.CLI}, {"method", t.Method}, {"path", t.Path}, {"body", t.Body}, {"headers", t.Headers}} {
		if !slices.Contains(kindFields[kind], f.name) && strings.TrimSpace(f.v) != "" {
			extra = append(extra, f.name)
		}
	}
	if len(extra) > 0 {
		return what + ": " + strings.Join(extra, ", ") + " does not apply to this kind of connection and must be empty."
	}
	return ""
}

// conns reads the connections once for a call.
type conns struct {
	list []ConnectionInfo
	by   map[string]ConnectionInfo
}

func (s *Service) loadConns(ctx context.Context) (conns, error) {
	c := conns{by: map[string]ConnectionInfo{}}
	if s.cfg.Connections == nil {
		return c, nil
	}
	l, err := s.cfg.Connections.List(ctx)
	if err != nil {
		return c, err
	}
	for _, x := range l {
		if x.WriteTools == nil {
			x.WriteTools = []string{}
		}
		x.ReadOnly = len(x.WriteTools) == 0
		c.list = append(c.list, x)
		c.by[x.ID] = x
	}
	return c, nil
}

func (c conns) get(id string) (ConnectionInfo, bool) {
	x, ok := c.by[id]
	return x, ok && id != ""
}

// fits checks that the connection kind can carry the action: an API call, a command or an MCP tool call.
func fits(c catRow, conn ConnectionInfo) string {
	api, cli := c.Run.Method != "" && c.Run.Path != "", strings.TrimSpace(c.Run.CLI) != ""
	switch {
	case isMCP(conn.Kind):
		if c.Tool != "" {
			return ""
		}
		return "This action is an API call or a command. Choose an API or SSH connection, not an MCP server."
	case conn.Kind == "ssh":
		if cli {
			return ""
		}
		return "This action is an API call. Choose an API connection, not an SSH one."
	}
	if api {
		return ""
	}
	return "This action is an SSH command. Choose an SSH connection."
}

// unavailable is "" when the action can run now, otherwise why not (plain words).
func unavailable(c catRow, cs conns) string {
	if !c.device() {
		return ""
	}
	conn, ok := cs.get(c.ConnectionID)
	switch {
	case !ok:
		return "No connection is chosen for this action."
	case !conn.Enabled:
		return "The connection " + conn.Name + " is turned off in Settings, AI assistant."
	case conn.ReadOnly:
		return conn.Name + ": " + readOnlyText + "."
	case c.Tool != "" && !isMCP(conn.Kind):
		return "Not available: this action names a write tool, which only an MCP server has, and " + conn.Name + " is not one."
	case c.Tool != "" && !slices.Contains(conn.WriteTools, c.Tool):
		return "The write tool " + c.Tool + " on " + conn.Name + " is turned off or missing."
	case conn.NotReady != "":
		return conn.Name + ": " + strings.TrimRight(conn.NotReady, ".") + "."
	}
	if why := fits(c, conn); why != "" {
		return why
	}
	if r := c.needsDeviceRead(); r != "" {
		return "Not available yet: this action needs a value that is read from the device while it runs ({" + r + "}), and Vedette cannot read that yet."
	}
	if needsPrecheck(c.Run, c.Rollback, c.Verify, c.Precheck, c.PrecheckRefuse, !c.Builtin) {
		return "Not available: an action that can name a port needs a check before it, with at least one text that makes it refuse (so a trunk or uplink port is never touched)."
	}
	if isMCP(conn.Kind) && (!c.Precheck.Empty() || !c.Verify.Empty()) {
		return "Not available yet: the check before and the read-back of this action need a read tool, and Vedette cannot name one for " + conn.Name + " yet."
	}
	if why := stepFits(c.Precheck, conn, "check before"); why != "" {
		return why
	}
	return ""
}

// stepFits is "" when the step (a template) has a form that the connection kind can run: a command for SSH, an API call for the HTTP
// kinds. An empty step needs nothing. An action that carries both forms (as the FortiGate ones do) fits both kinds.
func stepFits(t Tpl, conn ConnectionInfo, what string) string {
	if t.Empty() || isMCP(conn.Kind) {
		return ""
	}
	if conn.Kind == "ssh" && strings.TrimSpace(t.CLI) == "" {
		return "Not available: the " + what + " of this action is an API call, and " + conn.Name + " is an SSH connection."
	}
	if conn.Kind != "ssh" && (t.Method == "" || t.Path == "") {
		return "Not available: the " + what + " of this action is a command, and " + conn.Name + " is an API connection."
	}
	return ""
}

// needsDeviceRead is the first value a template uses that only the device can give while the action runs ({seq}, {previous_vlan},
// {found_id}, {rules_before}, {timeout}), or "". Reading it from the output is a later version (13c, action-templates 12.1); until then
// the action is not available. {expiry_s}, the time to live, is worked out without the device.
func (c catRow) needsDeviceRead() string {
	for _, r := range RuntimeValues {
		if r == "expiry_s" {
			continue
		}
		for _, t := range []Tpl{c.Run, c.Rollback, c.Verify, c.Precheck} {
			if slices.ContainsFunc([]string{t.CLI, t.Path, t.Body, t.Headers, t.Expect}, func(x string) bool { return strings.Contains(x, "{"+r+"}") }) {
				return r
			}
		}
	}
	return ""
}

func (c catRow) view(cs conns) CatalogAction {
	v := CatalogAction{ID: c.ID, Builtin: c.Builtin, Pack: c.Pack, Name: c.Name, Description: c.Description, Run: c.Run, Rollback: c.Rollback, Verify: c.Verify, Precheck: c.Precheck, PrecheckRefuse: nonNilStrings(c.PrecheckRefuse), PrecheckExpect: c.PrecheckExpect,
		Params: c.params(), Risk: c.Risk, Enabled: c.Enabled, Reversible: c.reversible(), AIMayPropose: c.AIMayPropose, Device: c.device(),
		ConnectionID: ptrOrNil(c.ConnectionID), Tool: ptrOrNil(c.Tool), RollbackTool: ptrOrNil(c.RollbackTool)}
	if conn, ok := cs.get(c.ConnectionID); ok {
		v.Connection, v.ConnectionKind = strp(conn.Name), strp(conn.Kind)
	}
	if why := unavailable(c, cs); why != "" {
		v.UnavailableReason = &why
	} else {
		v.Available = true
	}
	return v
}

var catTextRE = regexp.MustCompile(`^[A-Za-z0-9 _.,:'()/-]{1,80}$`)

// checkCatalog validates the fields of a custom action (everything a client may set). The templates must fit the kind
// of the chosen connection, which must have an enabled write tool (INV-14c, PRE-4). The returned row has no id.
func checkCatalog(in CatalogInput, cs conns) (catRow, error) {
	bad := func(msg string) (catRow, error) { return catRow{}, fail(http.StatusBadRequest, "invalid", msg) }
	switch {
	case !catTextRE.MatchString(in.Name):
		return bad("Name: 1 to 80 letters, numbers, spaces and . , : ' ( ) / -")
	case len(in.Description) > 300:
		return bad("Description: up to 300 characters.")
	case !in.Risk.valid():
		return bad("Risk must be low, medium or high.")
	}
	conn, ok := cs.get(in.ConnectionID)
	if !ok {
		return bad("Choose one of your connections (Settings, AI assistant).")
	}
	if conn.ReadOnly {
		return catRow{}, fail(http.StatusConflict, "read_only", conn.Name+": "+readOnlyText+".")
	}
	if _, known := kindFields[conn.Kind]; !known {
		return bad("Unknown connection kind.")
	}
	refuse := nonNilStrings(in.PrecheckRefuse)
	for _, t := range []struct {
		what string
		t    Tpl
	}{{"Action", in.Run}, {"Rollback", in.Rollback}, {"Check before", in.Precheck}} {
		if t.t.Expect != "" {
			return bad(t.what + ": the text to look for belongs to the read-back only.")
		}
	}
	if in.Verify.Empty() && in.Verify.Expect != "" {
		return bad("Read-back: give the read-back command or API call before the text to look for.")
	}
	for _, t := range []struct {
		what string
		t    Tpl
		opt  bool
	}{{"Action", in.Run, false}, {"Rollback", in.Rollback, false}, {"Read-back", in.Verify, true}, {"Check before", in.Precheck, true}} {
		if t.opt && t.t.Empty() {
			continue
		}
		if p := kindProblem(conn.Kind, t.t, t.what); p != "" {
			return bad(p)
		}
	}
	c := catRow{Name: in.Name, Description: in.Description, ConnectionID: conn.ID, Run: in.Run, Rollback: in.Rollback, Verify: in.Verify, Precheck: in.Precheck, PrecheckRefuse: refuse, PrecheckExpect: in.PrecheckExpect,
		Risk: in.Risk, Enabled: in.Enabled, AIMayPropose: in.AIMayPropose, Pack: "generic", Kind: "device"}
	if isMCP(conn.Kind) {
		c.Tool, c.RollbackTool = deref2(in.Tool), deref2(in.RollbackTool)
		if c.Tool == "" || !slices.Contains(conn.WriteTools, c.Tool) {
			return bad("Pick one of the write tools of " + conn.Name + ".")
		}
		if c.RollbackTool == "" || !slices.Contains(conn.WriteTools, c.RollbackTool) {
			return bad("Rollback: pick one of the write tools of " + conn.Name + " that undoes the action.")
		}
		for what, t := range map[string]Tpl{"Action": in.Run, "Rollback": in.Rollback} {
			t.Method, t.Path = "POST", "/mcp"
			if why := ValidateTpl(t, what); why != "" {
				return bad(why)
			}
		}
		if !in.Verify.Empty() {
			return bad("Read-back: not available for MCP servers.")
		}
		if !in.Precheck.Empty() || len(refuse) > 0 || in.PrecheckExpect != "" {
			return bad("Check before: not available for MCP servers.")
		}
	} else {
		if in.Tool != nil && *in.Tool != "" {
			return bad("A tool is only chosen for an MCP server.")
		}
		for _, t := range []struct {
			what string
			t    Tpl
			opt  bool
		}{{"Action", in.Run, false}, {"Rollback", in.Rollback, false}, {"Read-back", in.Verify, true}} {
			if t.opt && t.t.Empty() {
				continue
			}
			if why := ValidateTpl(t.t, t.what); why != "" {
				return bad(why)
			}
		}
		if why := readBackProblem(in.Verify); why != "" {
			return bad(why)
		}
		if why := precheckProblem(in.Precheck, refuse, in.PrecheckExpect); why != "" {
			return bad(why)
		}
	}
	if why := cliProblem(stepSet{in.Run, in.Rollback, in.Verify, in.Precheck}, true); why != "" {
		return bad(why)
	}
	used := tplParams(in.Run)
	if len(used) == 0 {
		return bad("Action: use at least one placeholder, for example {ip}, {domain} or {interface}.")
	}
	for _, p := range tplParams(in.Rollback, in.Verify, in.Precheck) {
		if !slices.Contains(used, p) {
			return bad("Rollback, read-back or check before uses {" + string(p) + "}, which the action does not have, so it could not be filled in.")
		}
	}
	if needsPrecheck(in.Run, in.Rollback, in.Verify, in.Precheck, refuse, true) {
		if isMCP(conn.Kind) {
			return bad("Action: {interface} needs a check before it, and an MCP server cannot run one yet.")
		}
		return bad("Action: a command or API path that uses {interface}, {port}, {id} or {name} can name a port, so it needs a check before it, with at least one text that makes it refuse (a trunk or uplink port must never be touched). {interface} is the placeholder for a port name; {port} is a TCP or UDP number, {id} a whole number and {name} a free name, and they cannot be told apart from a port in a command.")
	}
	if conn.Kind != "ssh" {
		// The output of an API or MCP call is JSON, compacted before it is compared (D-95 (1c)): a text that is a piece of JSON (it holds a
		// double quote) is saved in the same form, so what an admin reads is what is compared. A plain word or phrase keeps its spaces.
		c.PrecheckRefuse = slices.Clone(c.PrecheckRefuse)
		for i := range c.PrecheckRefuse {
			c.PrecheckRefuse[i] = savedPattern(c.PrecheckRefuse[i])
		}
		c.PrecheckExpect = savedPattern(c.PrecheckExpect)
		c.Verify.Expect = savedPattern(c.Verify.Expect)
	}
	return c, nil
}

// savedPattern is the form in which a refusal or expect text of an API or MCP action is stored.
func savedPattern(text string) string {
	if strings.Contains(text, `"`) {
		return normalizePattern(text, true)
	}
	return collapseSpaces(text)
}

func deref2(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// inputOf turns a stored custom action back into the input shape, so an update is validated like a create.
func inputOf(c catRow) CatalogInput {
	return CatalogInput{Name: c.Name, Description: c.Description, ConnectionID: c.ConnectionID, Tool: ptrOrNil(c.Tool), RollbackTool: ptrOrNil(c.RollbackTool),
		Run: c.Run, Rollback: c.Rollback, Verify: c.Verify, Precheck: c.Precheck, PrecheckRefuse: c.PrecheckRefuse, PrecheckExpect: c.PrecheckExpect, Risk: c.Risk, Enabled: c.Enabled, AIMayPropose: c.AIMayPropose}
}

// ---- reads and writes of the catalog (admin) ----

// Catalog is GET /response/catalog. The header lines of a template can carry an authorisation value, so the values are hidden
// from everyone but an admin (full): GET is open to viewers (CONTRACT), who see the header names only.
func (s *Service) Catalog(ctx context.Context, full bool) (Catalog, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return Catalog{}, err
	}
	rows, err := loadCatalog(ctx, s.cfg.DB.Reader())
	if err != nil {
		return Catalog{}, err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return Catalog{}, err
	}
	out := Catalog{Items: make([]CatalogAction, len(rows)), Connections: make([]Connection, len(cs.list))}
	for i, r := range rows {
		out.Items[i] = r.view(cs)
		if !full {
			out.Items[i].Run.Headers, out.Items[i].Rollback.Headers, out.Items[i].Verify.Headers, out.Items[i].Precheck.Headers = maskHeaders(r.Run.Headers), maskHeaders(r.Rollback.Headers), maskHeaders(r.Verify.Headers), maskHeaders(r.Precheck.Headers)
		}
	}
	for i, c := range cs.list {
		out.Connections[i] = c.Connection
	}
	return out, nil
}

// maskHeaders keeps the names of the header lines and hides the values.
func maskHeaders(h string) string {
	if h == "" {
		return ""
	}
	lines := strings.Split(h, "\n")
	for i, l := range lines {
		name, _, _ := strings.Cut(l, ":")
		lines[i] = name + ": (hidden)"
	}
	return strings.Join(lines, "\n")
}

const maxCatalog = 50

// AddAction is POST /response/catalog: a custom action.
func (s *Service) AddAction(ctx context.Context, who Actor, in CatalogInput) (CatalogAction, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return CatalogAction{}, err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return CatalogAction{}, err
	}
	c, err := checkCatalog(in, cs)
	if err != nil {
		return CatalogAction{}, s.refuse(ctx, err, "response.catalog", who.Email)
	}
	c.ID, c.Builtin = newID("ca"), false
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM resp_catalog`).Scan(&n); err != nil {
			return err
		}
		if n >= maxCatalog {
			return fail(http.StatusConflict, "limit", "Up to 50 actions.")
		}
		if err := saveCat(ctx, tx, c, 1000+n); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.catalog.add", c.ID, LogSettings, "Custom action added: "+c.Name+" ("+string(c.Risk)+" risk, "+onOff(c.Enabled, "enabled", "disabled")+flagIf(c.AIMayPropose, ", AI may propose")+")", who.Email)
	})
	if err != nil {
		return CatalogAction{}, s.refuse(ctx, err, "response.catalog", who.Email)
	}
	return c.view(cs), nil
}

func onOff(b bool, on, off string) string {
	if b {
		return on
	}
	return off
}

func flagIf(b bool, s string) string {
	if b {
		return s
	}
	return ""
}

// ChangeAction is PUT /response/catalog/{id}. A built-in action takes only enabled, ai_may_propose and connection_id.
func (s *Service) ChangeAction(ctx context.Context, who Actor, id string, u CatalogUpdate) (CatalogAction, error) {
	if err := s.ensureSeeded(ctx); err != nil {
		return CatalogAction{}, err
	}
	cs, err := s.loadConns(ctx)
	if err != nil {
		return CatalogAction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out catRow
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		old, ok, err := loadCat(ctx, tx, id)
		if err != nil {
			return err
		}
		if !ok {
			return fail(http.StatusNotFound, "not_found", "No such action.")
		}
		n := old
		if old.Builtin {
			if u.Enabled != nil {
				n.Enabled = *u.Enabled
			}
			if u.AIMayPropose != nil {
				n.AIMayPropose = *u.AIMayPropose
			}
			if u.Present["connection_id"] && old.device() {
				if u.ConnectionID == nil {
					n.ConnectionID = ""
				} else {
					conn, ok := cs.get(*u.ConnectionID)
					if !ok {
						return fail(http.StatusBadRequest, "invalid", "Choose one of your connections.")
					}
					probe := old
					probe.ConnectionID = conn.ID
					if why := unavailable(probe, cs); why != "" && (conn.ReadOnly || strings.HasPrefix(why, "This action is")) {
						if conn.ReadOnly {
							return fail(http.StatusConflict, "read_only", why)
						}
						return fail(http.StatusBadRequest, "wrong_kind", why)
					}
					n.ConnectionID = conn.ID
				}
			}
		} else {
			in := inputOf(old)
			if u.Name != nil {
				in.Name = *u.Name
			}
			if u.Description != nil {
				in.Description = *u.Description
			}
			if u.Present["connection_id"] && u.ConnectionID != nil {
				in.ConnectionID = *u.ConnectionID
			}
			if u.Present["tool"] {
				in.Tool = u.Tool
			}
			if u.Present["rollback_tool"] {
				in.RollbackTool = u.RollbackTool
			}
			if u.Run != nil {
				in.Run = *u.Run
			}
			if u.Rollback != nil {
				in.Rollback = *u.Rollback
			}
			if u.Verify != nil {
				in.Verify = *u.Verify
			}
			if u.Precheck != nil {
				in.Precheck = *u.Precheck
			}
			if u.PrecheckRefuse != nil {
				in.PrecheckRefuse = *u.PrecheckRefuse
			}
			if u.PrecheckExpect != nil {
				in.PrecheckExpect = *u.PrecheckExpect
			}
			if u.Risk != nil {
				in.Risk = *u.Risk
			}
			if u.Enabled != nil {
				in.Enabled = *u.Enabled
			}
			if u.AIMayPropose != nil {
				in.AIMayPropose = *u.AIMayPropose
			}
			c, err := checkCatalog(in, cs)
			if err != nil {
				return err
			}
			n = c
			n.ID, n.Builtin = old.ID, false
		}
		if err := saveCat(ctx, tx, n, 0); err != nil {
			return err
		}
		if !old.Builtin && (old.Run != n.Run || old.Rollback != n.Rollback || old.Verify != n.Verify || old.Precheck != n.Precheck || !slices.Equal(old.PrecheckRefuse, n.PrecheckRefuse) || old.PrecheckExpect != n.PrecheckExpect || old.Risk != n.Risk || old.Tool != n.Tool || old.RollbackTool != n.RollbackTool) {
			if err := s.revokePreApprovals(ctx, tx, n, who.Email); err != nil {
				return err
			}
			if err := s.cancelOpenRequests(ctx, tx, n, who.Email); err != nil {
				return err
			}
		}
		out = n
		return s.step(ctx, tx, "response.catalog.change", n.ID, LogSettings, "Action "+onOff(n.Enabled, "enabled", "disabled")+": "+n.Name+" ("+string(n.Risk)+" risk"+flagIf(n.AIMayPropose, ", AI may propose")+")", who.Email)
	})
	if err != nil {
		return CatalogAction{}, s.refuse(ctx, err, id, who.Email)
	}
	return out.view(cs), nil
}

// revokePreApprovals switches pre-approval off on every rule that uses an action whose templates or risk were just edited: what
// an admin confirmed for the old action is not what the rule would now run without asking. Each rule is logged; an admin
// confirms it again by saving the rule (INV-5).
func (s *Service) revokePreApprovals(ctx context.Context, tx *sql.Tx, c catRow, actor string) error {
	rules, err := loadRules(ctx, tx)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if !r.PreApproved || !slices.ContainsFunc(r.Actions, func(a RuleAction) bool { return a.ActionID == c.ID }) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE resp_rules SET pre_approved = 0 WHERE id = ?`, r.ID); err != nil {
			return err
		}
		if err := s.step(ctx, tx, "response.rule.change", r.ID, LogSettings, "Pre-approval switched off for rule \""+oneLine(r.Name, 80)+"\": its action \""+oneLine(c.Name, 80)+"\" was edited. An admin must confirm it again.", actor); err != nil {
			return err
		}
	}
	return nil
}

// cancelOpenRequests cancels the pending requests that hold an item of the edited custom action: they were made, and are shown to the
// approvers, with the old template and the old risk. Each is logged. (A request already approved is stopped at its run by the
// fingerprint of the action, actionFP.)
func (s *Service) cancelOpenRequests(ctx context.Context, tx *sql.Tx, c catRow, actor string) error {
	pending, err := loadReqs(ctx, tx, `WHERE status = 'pending'`)
	if err != nil {
		return err
	}
	for _, r := range pending {
		if !slices.ContainsFunc(r.recs, func(i itemRec) bool { return i.ActionID == c.ID }) {
			continue
		}
		r.Status, r.DecidedAt, r.Note = StatusRejected, strp(s.ts()), strp("Cancelled: the action \""+oneLine(c.Name, 80)+"\" was edited after the request was made. Ask again.")
		for i := range r.recs {
			r.recs[i].Status = ItemSkipped
		}
		if err := s.step(ctx, tx, "response.reject", r.ID, LogRejected, r.Title+": cancelled because its action \""+oneLine(c.Name, 80)+"\" was edited by "+actor, actor+" (app)"); err != nil {
			return err
		}
		if err := updateReq(ctx, tx, r); err != nil {
			return err
		}
	}
	return nil
}

// DeleteAction is DELETE /response/catalog/{id}: a custom action that no rule uses.
func (s *Service) DeleteAction(ctx context.Context, who Actor, id string) error {
	if err := s.ensureSeeded(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		old, ok, err := loadCat(ctx, tx, id)
		if err != nil {
			return err
		}
		if !ok {
			return fail(http.StatusNotFound, "not_found", "No such action.")
		}
		if old.Builtin {
			return fail(http.StatusConflict, "builtin", "Built-in actions cannot be deleted. Disable it instead.")
		}
		rules, err := loadRules(ctx, tx)
		if err != nil {
			return err
		}
		for _, r := range rules {
			for _, a := range r.Actions {
				if a.ActionID == id {
					return fail(http.StatusConflict, "in_use", "The rule \""+oneLine(r.Name, 80)+"\" uses this action. Change or delete the rule first.")
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resp_catalog WHERE id = ?`, id); err != nil {
			return err
		}
		return s.step(ctx, tx, "response.catalog.delete", id, LogSettings, "Custom action deleted: "+old.Name, who.Email)
	})
	if err != nil {
		return s.refuse(ctx, err, id, who.Email)
	}
	return nil
}

// ---- the exact change of one action ----

// callOf is the API call of a step as the approver sees it and as it is sent: it is the rendering of the step itself (stepOf), so the two
// cannot differ. ttlMin gives {expiry_s} its number.
func (s *Service) callOf(conn *ConnectionInfo, t Tpl, vals Values, ttlMin *int) (*RestCall, error) {
	if conn == nil || !isHTTPKind(conn.Kind) || t.Method == "" || t.Path == "" {
		return nil, nil
	}
	st, err := s.stepOf(t, conn, "", vals, ttlMin)
	if err != nil {
		return nil, err
	}
	rc := &RestCall{Method: st.Method, URL: st.URL, Headers: st.Headers}
	if rc.Headers == nil {
		rc.Headers = map[string]string{}
	}
	if st.Body != "" {
		rc.Body = &st.Body
	}
	return rc, nil
}

func (s *Service) cliOf(conn *ConnectionInfo, t Tpl, tool string, vals Values, ttlMin *int) (string, error) {
	switch {
	case conn != nil && isMCP(conn.Kind):
		body := ""
		if t.Body != "" {
			b, err := fillExec(t.Body, vals, TJSON, ttlMin)
			if err != nil {
				return "", err
			}
			body = b
		}
		return tool + "(" + body + ")", nil
	case conn == nil || conn.Kind == "ssh":
		return fillExec(t.CLI, vals, TCLI, ttlMin)
	case isHTTPKind(conn.Kind) && t.Method != "" && t.Path != "":
		return "", nil
	}
	return fillExec(t.CLI, vals, TCLI, ttlMin)
}

// buildChange renders the exact change of one catalog action from its stored templates and checked values. Each value
// is escaped for the place it lands in (INV-14b). why is shown as the reason of a block list entry.
func (s *Service) buildChange(c catRow, vals Values, conn *ConnectionInfo, why string, ttlMin *int) (Change, error) {
	var what []string
	for _, p := range c.params() {
		what = append(what, string(p)+" "+vals[p])
	}
	w := strings.Join(what, ", ")
	cli, err := s.cliOf(conn, c.Run, c.Tool, vals, ttlMin)
	if err != nil {
		return Change{}, err
	}
	rest, err := s.callOf(conn, c.Run, vals, ttlMin)
	if err != nil {
		return Change{}, err
	}
	ch := Change{CLI: cli, Rest: rest}
	if ch.Verify, err = readStepText(c.Verify, conn, vals, ttlMin); err != nil {
		return Change{}, err
	}
	if ch.Precheck, err = readStepText(c.Precheck, conn, vals, ttlMin); err != nil {
		return Change{}, err
	}
	ch.PrecheckRules = precheckRules(c)
	if c.Verify.Expect != "" {
		e, err := Fill(c.Verify.Expect, vals, TCLI) // the placeholders of expect are typed values; {expiry_s} does not occur in it
		if err != nil {
			return Change{}, err
		}
		ch.VerifyRule = "After the change the read-back must contain \"" + oneLine(e, 200) + "\"; after the undo it must not."
	}
	switch {
	case c.ID == "blocklist_add":
		ch.Before = vals[PIP] + " is not on the block list."
		ch.After = vals[PIP] + " is published on the block list your firewall pulls. Reason: " + oneLine(why, 200)
	case !c.device():
		ch.Before, ch.After = "Nothing changes on any device.", c.Name+" ("+w+"). "+c.Description
	default:
		ch.Before, ch.After = "The current state is read from the device when the action runs.", c.Name+" ("+w+"). "+c.Description
	}
	ch.Rollback = RollbackChange{Title: "This action cannot be undone"}
	if c.reversible() {
		rb, err := s.cliOf(conn, c.Rollback, c.RollbackTool, vals, ttlMin)
		if err != nil {
			return Change{}, err
		}
		rr, err := s.callOf(conn, c.Rollback, vals, ttlMin)
		if err != nil {
			return Change{}, err
		}
		ch.Rollback = RollbackChange{Title: "Undo: " + c.Name + " (" + w + ")", CLI: rb, Rest: rr}
	}
	return ch, nil
}

// readStepText is the exact read-only step as the approver sees it: the stored method and URL of an API call, or the command lines.
// Empty when the action has no such step.
func readStepText(t Tpl, conn *ConnectionInfo, vals Values, ttlMin *int) (string, error) {
	if t.Empty() {
		return "", nil
	}
	if t.Method != "" && t.Path != "" && conn != nil && isHTTPKind(conn.Kind) {
		p, err := fillExec(t.Path, vals, TURL, ttlMin)
		if err != nil {
			return "", err
		}
		return t.Method + " " + conn.Target + p, nil
	}
	if strings.TrimSpace(t.CLI) == "" {
		return "", nil
	}
	return fillExec(t.CLI, vals, TCLI, ttlMin)
}

// precheckRules says in plain words when the check before refuses the action.
func precheckRules(c catRow) string {
	if c.Precheck.Empty() {
		return ""
	}
	var parts []string
	if len(c.PrecheckRefuse) > 0 {
		q := make([]string, len(c.PrecheckRefuse))
		for i, r := range c.PrecheckRefuse {
			q[i] = "\"" + r + "\""
		}
		parts = append(parts, "Nothing is changed if its output contains "+strings.Join(q, ", "))
	}
	if c.PrecheckExpect != "" {
		parts = append(parts, "nothing is changed unless its output contains \""+c.PrecheckExpect+"\"")
	}
	parts = append(parts, "nothing is changed if it prints nothing")
	return strings.Join(parts, "; ") + "."
}

func callText(rest *RestCall, cli string) string {
	if rest != nil {
		b := ""
		if rest.Body != nil {
			b = " " + *rest.Body
		}
		return strings.TrimSpace(rest.Method + " " + rest.URL + b)
	}
	return "command: " + escapeLines(cli)
}

// escapeLines puts a multi-line command on one line without losing where the lines end: each break becomes the two characters \n, which
// a template cannot contain (a backslash is refused), so the text is read back unambiguously. The log rows of a request and of its
// execution carry the whole call this way (D-175).
func escapeLines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", `\n`)
}

// callFirstLine is the short form of a call for a line that only names it (a dry run's "would").
func callFirstLine(rest *RestCall, cli string) string {
	if rest != nil {
		return callText(rest, cli)
	}
	first, _, _ := strings.Cut(cli, "\n")
	return "command: " + first
}
