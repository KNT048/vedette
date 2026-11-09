package response

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	case c.Tool != "" && !slices.Contains(conn.WriteTools, c.Tool):
		return "The write tool " + c.Tool + " on " + conn.Name + " is turned off or missing."
	}
	return fits(c, conn)
}

func (c catRow) view(cs conns) CatalogAction {
	v := CatalogAction{ID: c.ID, Builtin: c.Builtin, Pack: c.Pack, Name: c.Name, Description: c.Description, Run: c.Run, Rollback: c.Rollback, Verify: c.Verify,
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
	for _, t := range []struct {
		what string
		t    Tpl
		opt  bool
	}{{"Action", in.Run, false}, {"Rollback", in.Rollback, false}, {"Read-back", in.Verify, true}} {
		if t.opt && t.t.Empty() {
			continue
		}
		if p := kindProblem(conn.Kind, t.t, t.what); p != "" {
			return bad(p)
		}
	}
	c := catRow{Name: in.Name, Description: in.Description, ConnectionID: conn.ID, Run: in.Run, Rollback: in.Rollback, Verify: in.Verify, Risk: in.Risk, Enabled: in.Enabled,
		AIMayPropose: in.AIMayPropose, Pack: "generic", Kind: "device"}
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
	}
	used := tplParams(in.Run)
	if len(used) == 0 {
		return bad("Action: use at least one placeholder, for example {ip}, {domain} or {interface}.")
	}
	for _, p := range tplParams(in.Rollback, in.Verify) {
		if !slices.Contains(used, p) {
			return bad("Rollback or read-back uses {" + string(p) + "}, which the action does not have, so it could not be filled in.")
		}
	}
	return c, nil
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
		Run: c.Run, Rollback: c.Rollback, Verify: c.Verify, Risk: c.Risk, Enabled: c.Enabled, AIMayPropose: c.AIMayPropose}
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
			out.Items[i].Run.Headers, out.Items[i].Rollback.Headers, out.Items[i].Verify.Headers = maskHeaders(r.Run.Headers), maskHeaders(r.Rollback.Headers), maskHeaders(r.Verify.Headers)
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
		if !old.Builtin && (old.Run != n.Run || old.Rollback != n.Rollback || old.Verify != n.Verify || old.Risk != n.Risk || old.Tool != n.Tool || old.RollbackTool != n.RollbackTool) {
			if err := s.revokePreApprovals(ctx, tx, n, who.Email); err != nil {
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

func (s *Service) callOf(conn *ConnectionInfo, t Tpl, vals Values) (*RestCall, error) {
	if conn == nil || !isHTTPKind(conn.Kind) || t.Method == "" || t.Path == "" {
		return nil, nil
	}
	path, err := Fill(t.Path, vals, TURL)
	if err != nil {
		return nil, err
	}
	rc := &RestCall{Method: t.Method, URL: conn.Target + path}
	if t.Body != "" {
		b, err := Fill(t.Body, vals, TJSON)
		if err != nil {
			return nil, err
		}
		chk := b
		for _, r := range RuntimeValues {
			chk = strings.ReplaceAll(chk, "<"+r+">", "0") // the display form of a value read at run time
		}
		if !json.Valid([]byte(chk)) { // a value in a bare position, or a template that is not JSON once filled
			return nil, errors.New("response: the filled body is not JSON")
		}
		rc.Body = &b
	}
	return rc, nil
}

func (s *Service) cliOf(conn *ConnectionInfo, t Tpl, tool string, vals Values) (string, error) {
	switch {
	case conn != nil && isMCP(conn.Kind):
		body := ""
		if t.Body != "" {
			b, err := Fill(t.Body, vals, TJSON)
			if err != nil {
				return "", err
			}
			body = b
		}
		return tool + "(" + body + ")", nil
	case conn == nil || conn.Kind == "ssh":
		return Fill(t.CLI, vals, TCLI)
	case isHTTPKind(conn.Kind) && t.Method != "" && t.Path != "":
		return "", nil
	}
	return Fill(t.CLI, vals, TCLI)
}

// buildChange renders the exact change of one catalog action from its stored templates and checked values. Each value
// is escaped for the place it lands in (INV-14b). why is shown as the reason of a block list entry.
func (s *Service) buildChange(c catRow, vals Values, conn *ConnectionInfo, why string) (Change, error) {
	var what []string
	for _, p := range c.params() {
		what = append(what, string(p)+" "+vals[p])
	}
	w := strings.Join(what, ", ")
	cli, err := s.cliOf(conn, c.Run, c.Tool, vals)
	if err != nil {
		return Change{}, err
	}
	rest, err := s.callOf(conn, c.Run, vals)
	if err != nil {
		return Change{}, err
	}
	ch := Change{CLI: cli, Rest: rest}
	if c.Verify.Method != "" && c.Verify.Path != "" && conn != nil && isHTTPKind(conn.Kind) {
		p, err := Fill(c.Verify.Path, vals, TURL)
		if err != nil {
			return Change{}, err
		}
		ch.Verify = "GET " + conn.Target + p
	} else if c.Verify.CLI != "" {
		if ch.Verify, err = Fill(c.Verify.CLI, vals, TCLI); err != nil {
			return Change{}, err
		}
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
		rb, err := s.cliOf(conn, c.Rollback, c.RollbackTool, vals)
		if err != nil {
			return Change{}, err
		}
		rr, err := s.callOf(conn, c.Rollback, vals)
		if err != nil {
			return Change{}, err
		}
		ch.Rollback = RollbackChange{Title: "Undo: " + c.Name + " (" + w + ")", CLI: rb, Rest: rr}
	}
	return ch, nil
}

func callText(rest *RestCall, cli string) string {
	if rest != nil {
		b := ""
		if rest.Body != nil {
			b = " " + *rest.Body
		}
		return strings.TrimSpace(rest.Method + " " + rest.URL + b)
	}
	first, _, _ := strings.Cut(cli, "\n")
	return "command: " + first
}
