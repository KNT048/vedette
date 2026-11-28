package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn/read"
)

// What each job may do (OWASP LLM01: least privilege; the "rule of two": a job that reads untrusted text and private data must not
// also send by itself). One table, read by the tool loop on every offer and every call, so no job can reach a tool its row does not
// name, whatever its prompt or its data say. The model never gets a write tool (INV-14), no job writes a finding, a rule or a setting
// from an answer, and every state an answer leads to passes a deterministic check or a person (the writes column says which).

// toolClass is what a tool reaches with the arguments the model writes.
type toolClass string

const (
	toolBox     toolClass = "box"      // reads the box's own data; nothing leaves the box
	toolConnLAN toolClass = "conn-lan" // sends its arguments to a connection inside the network (a literal private address)
	toolConnOut toolClass = "conn-out" // sends them to a connection outside the network: only one an administrator allowed for Ask
	toolPage    toolClass = "page"     // the box fetches the public HTTPS page the model names (GET, no cookies, public hosts only)
)

// power is the row of one job.
type power struct {
	// classes are the classes of tool the model may call; none = one call without tools.
	classes []toolClass
	// boxTools names the tools of the box it may call (toolBox).
	boxTools []string
	// writes is what an answer may change, and the check or the person in front of it.
	writes string
	// egress is where the job sends anything besides the AI provider of its profile.
	egress string
}

// jobPowers is the table. A job missing from it can do nothing but answer.
var jobPowers = map[Job]power{
	JobAskMyData: {
		classes:  []toolClass{toolBox, toolConnLAN, toolConnOut},
		boxTools: []string{"device_updates", "get_finding", "list_findings", "lookup_cve", "lookup_ioc", "search_assets"},
		writes:   "its own answer; memory suggestions, which an administrator accepts or not",
		egress:   "the read tools of connections: inside the network, or outside it only for a connection an administrator allowed for Ask",
	},
	JobLogInvestigate: {
		classes:  []toolClass{toolBox},
		boxTools: []string{"events_around", "lookup_cve", "lookup_ioc", "search_assets"},
		writes:   "the stored log digest; memory suggestions, which an administrator accepts or not",
		egress:   "none",
	},
	JobLogDigest: {writes: "the stored log digest; memory suggestions, which an administrator accepts or not", egress: "none"},
	JobExplainFinding: {
		writes: "the stored explanation; a product for a program, only one of the candidates the box offered (it opens findings a person " +
			"can undo, never closes one)",
		egress: "none (the box fetches the public pages itself, before the call)",
	},
	JobMitigationConfig:  {writes: "a draft configuration a person reviews, each risky line marked, never applied by the box", egress: "none"},
	JobCVENews:           {writes: "the stored news summary", egress: "none (the box fetches the public sources itself, before the call)"},
	JobWeeklyReport:      {writes: "report commentary", egress: "none"},
	JobPDPLAssessment:    {writes: "report commentary", egress: "none"},
	JobTranslateAdvisory: {writes: "a translation shown as text", egress: "none"},
	JobResponsePlan: {writes: "a plan whose actions response turns into approval requests a person decides, never run by the AI",
		egress: "none"},
	JobResearchCVEs: {
		classes:  []toolClass{toolPage},
		boxTools: []string{"fetch_page"},
		writes: "a reading of the line that findings keeps only as far as the box checks it: its quote looked up in what the research read, " +
			"its basis decided by the box, its address only a page the research read; affected opens a finding a person can reject, not " +
			"affected is only a proposal a person confirms or rejects in the review queue (it never closes anything)",
		egress: "public pages the model names whose address is in the job's data or linked from a page read from it, fetched by the box " +
			"(or the provider's own web tools on a profile that has them)",
	},
}

// permits says whether the job may call a tool of this class and name.
func (p power) permits(class toolClass, name string) bool {
	if !slices.Contains(p.classes, class) {
		return false
	}
	return class != toolBox && class != toolPage || slices.Contains(p.boxTools, name)
}

// ---- connections outside the network in Ask

// askConnSetting is ai_setting key `ask_connections`: per connection id, whether an administrator allowed Ask to use that connection
// although it is outside the network, and the address it pointed to then. No entry, or an entry for another address (the connection
// was moved since), = not decided = not allowed.
type askConnSetting struct {
	Connections map[string]askConnChoice `json:"connections"`
}

type askConnChoice struct {
	Allowed bool   `json:"allowed"`
	Address string `json:"address"`
}

// choice is the decision for the connection at its current address: decided only when it was made for that address.
func (v askConnSetting) choice(id, address string) (allowed, decided bool) {
	c, ok := v.Connections[id]
	if !ok || c.Address != address {
		return false, false
	}
	return c.Allowed, true
}

func (s *Service) askConnections(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}) (askConnSetting, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT value FROM ai_setting WHERE key = 'ask_connections'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return askConnSetting{Connections: map[string]askConnChoice{}}, nil
	}
	if err != nil {
		return askConnSetting{}, fmt.Errorf("ai: ask connections: %w", err)
	}
	var v askConnSetting
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return askConnSetting{}, fmt.Errorf("ai: ask connections: %w", err)
	}
	if v.Connections == nil {
		v.Connections = map[string]askConnChoice{}
	}
	return v, nil
}

// askAllows reports whether Ask may use the connection outside the network now, at the address it points to now; a setting or an
// address that cannot be read allows nothing.
func (s *Service) askAllows(ctx context.Context, connID string) bool {
	if s.cfg.ConnTargets == nil {
		return false
	}
	targets, err := s.cfg.ConnTargets(ctx)
	if err != nil {
		return false
	}
	v, err := s.askConnections(ctx, s.cfg.DB.Reader())
	allowed, _ := v.choice(connID, targets[connID])
	return err == nil && allowed
}

// AskConnection is one connection outside the network that has read tools, with whether Ask may use it.
type AskConnection struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Allowed bool   `json:"allowed"`
	Decided bool   `json:"decided"`
	target  string // the address as core/conn has it, unclipped: what a decision is for
}

// AskConnectionsView is GET /ai/ask/connections. Notice is set while a connection outside the network has not been decided: the page
// says once that Ask no longer uses such a connection until an administrator allows it.
type AskConnectionsView struct {
	Items  []AskConnection `json:"items"`
	Notice bool            `json:"notice"`
}

// outsideConnections lists the connections outside the network that have read tools: their id, name and address.
func (s *Service) outsideConnections(ctx context.Context) ([]AskConnection, error) {
	cr := s.cfg.Conns
	if cr == nil {
		return nil, nil
	}
	lctx, cancel := context.WithTimeout(ctx, read.ListBudget+2*time.Second)
	defer cancel()
	list, err := cr.ListReadTools(lctx)
	if err != nil {
		return nil, fmt.Errorf("ai: list the read tools of the connections: %w", err)
	}
	targets := map[string]string{}
	if s.cfg.ConnTargets != nil {
		if targets, err = s.cfg.ConnTargets(ctx); err != nil {
			return nil, fmt.Errorf("ai: read the addresses of the connections: %w", err)
		}
	}
	seen := map[string]bool{}
	var out []AskConnection
	for _, rt := range list {
		if rt.ConnectionID == "" || seen[rt.ConnectionID] || internalTarget(targets[rt.ConnectionID]) {
			continue
		}
		seen[rt.ConnectionID] = true
		out = append(out, AskConnection{ID: rt.ConnectionID, Name: clip(rt.ConnectionName, 60), Address: clip(targets[rt.ConnectionID], 200), target: targets[rt.ConnectionID]})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name || out[i].Name == out[j].Name && out[i].ID < out[j].ID
	})
	return out, nil
}

// AskConnections is GET /ai/ask/connections (admin).
func (s *Service) AskConnections(ctx context.Context) (AskConnectionsView, error) {
	list, err := s.outsideConnections(ctx)
	if err != nil {
		return AskConnectionsView{}, err
	}
	set, err := s.askConnections(ctx, s.cfg.DB.Reader())
	if err != nil {
		return AskConnectionsView{}, err
	}
	v := AskConnectionsView{Items: []AskConnection{}}
	for _, c := range list {
		c.Allowed, c.Decided = set.choice(c.ID, c.target)
		v.Notice = v.Notice || !c.Decided
		v.Items = append(v.Items, c)
	}
	return v, nil
}

// SetAskConnection allows or forbids Ask to use one connection outside the network (PUT /ai/ask/connections/{id}, admin, audited). A
// connection that is not outside the network, or has no read tool, is 404: there is nothing to decide for it.
func (s *Service) SetAskConnection(ctx context.Context, who, id string, allowed bool) (AskConnection, error) {
	list, err := s.outsideConnections(ctx)
	if err != nil {
		return AskConnection{}, err
	}
	i := slices.IndexFunc(list, func(c AskConnection) bool { return c.ID == id })
	if i < 0 {
		return AskConnection{}, apierr.New(http.StatusNotFound, "not_found", "No connection outside the network with read tools has this id.")
	}
	state := "not allowed"
	if allowed {
		state = "allowed"
	}
	err = s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		set, err := s.askConnections(ctx, tx)
		if err != nil {
			return err
		}
		set.Connections[id] = askConnChoice{Allowed: allowed, Address: list[i].target}
		if err := upsertSetting(ctx, tx, "ask_connections", set, s.cfg.Clock(), who); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, who, "ai.ask.connection", id, state)
	})
	if err != nil {
		return AskConnection{}, err
	}
	c := list[i]
	c.Allowed, c.Decided = allowed, true
	return c, nil
}
