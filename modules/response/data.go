package response

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/apierr"
)

// The action templates, the rule templates and the trigger catalog are DATA (D-58, D-88): no vendor or device
// knowledge lives in Go. The files under data/ are the shipped library; customers add their own actions through the
// catalog. A template loaded from the library goes through the same validation as one a customer saves.

//go:embed data/*.json
var dataFiles embed.FS

//go:embed migrations/sqlite/*.sql
var migrationFiles embed.FS

// Migrations holds the SQLite migrations of the module. Pass it to store.Migrate(ctx, db, "response", response.Migrations).
var Migrations = mustSub(migrationFiles, "migrations/sqlite")

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("response: embedded migrations: " + err.Error()) // dir is a constant; cannot fail
	}
	return sub
}

type builtinDef struct {
	ID           string `json:"id"`
	Pack         string `json:"pack"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Tool         string `json:"tool"`
	RollbackTool string `json:"rollback_tool"`
	Run          Tpl    `json:"run"`
	Rollback     Tpl    `json:"rollback"`
	Verify       Tpl    `json:"verify"`
	// Precheck and PrecheckRefuse are the check before the action (D-95): a read-only template and the texts that make it refuse.
	Precheck       Tpl      `json:"precheck"`
	PrecheckRefuse []string `json:"precheck_refuse"`
	PrecheckExpect string   `json:"precheck_expect"`
	Risk           Risk     `json:"risk"`
	Enabled        bool     `json:"enabled"`
	AIMayPropose   bool     `json:"ai_may_propose"`
	Unverified     bool     `json:"unverified"`
}

type triggerDef struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Fields      []TriggerField `json:"fields"`
	// AIEvidence are the kinds of evidence that prove the trigger to the AI (finding, ioc_hit, config_read). None = no evidence can show it
	// happened, so the AI may not use the trigger (D-119).
	AIEvidence []string `json:"ai_evidence"`
}

type templateDef struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Rule        RuleInput `json:"rule"`
}

var builtinIDRE = regexp.MustCompile(`^[a-z0-9_]{2,48}$`)

func (s *Service) loadData() error {
	read := func(name string, into any) error {
		b, err := dataFiles.ReadFile("data/" + name)
		if err != nil {
			return fmt.Errorf("response: read %s: %w", name, err)
		}
		if err := json.Unmarshal(b, into); err != nil {
			return fmt.Errorf("response: parse %s: %w", name, err)
		}
		return nil
	}
	var lib struct {
		Unverified string       `json:"unverified_note"`
		Actions    []builtinDef `json:"actions"`
	}
	if err := read("action-templates.json", &lib); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, a := range lib.Actions {
		if !builtinIDRE.MatchString(a.ID) || seen[a.ID] {
			return fmt.Errorf("response: action-templates.json: bad or duplicate id %q", a.ID)
		}
		seen[a.ID] = true
		if a.Kind != "box" && a.Kind != "device" || !a.Risk.valid() {
			return fmt.Errorf("response: action-templates.json: %s has a bad kind or risk", a.ID)
		}
		if err := checkBuiltinTpls(a); err != nil {
			return err
		}
	}
	s.cat, s.catNote = lib.Actions, lib.Unverified

	var tl struct {
		Templates []templateDef `json:"templates"`
	}
	if err := read("rule-templates.json", &tl); err != nil {
		return err
	}
	var tr struct {
		Triggers []triggerDef `json:"triggers"`
		Kinds    []string     `json:"device_kinds"`
	}
	if err := read("triggers.json", &tr); err != nil {
		return err
	}
	s.triggers, s.kinds = tr.Triggers, tr.Kinds
	for _, t := range tl.Templates {
		for _, a := range t.Rule.Actions {
			if !seen[a.ActionID] {
				return fmt.Errorf("response: rule-templates.json: %q uses unknown action %s", t.Name, a.ActionID)
			}
		}
		if t.Rule.Trigger == "" || s.trigger(t.Rule.Trigger) == nil {
			return fmt.Errorf("response: rule-templates.json: %q has an unknown trigger", t.Name)
		}
	}
	s.templates = tl.Templates
	return nil
}

// checkBuiltinTpls validates the templates of a library action the way a customer's would be. A box action may use {text}
// (a message), and its commands are display text for the log: they are never sent to a shell. The read-back text belongs to the
// read-back only, the check before and its refusal texts go together, and a device action that names a port has them (D-95).
func checkBuiltinTpls(a builtinDef) error {
	for what, t := range map[string]Tpl{"run": a.Run, "rollback": a.Rollback, "verify": a.Verify} {
		if what != "run" && t.Empty() {
			if t.Expect != "" {
				return fmt.Errorf("response: action-templates.json: %s %s has a text to look for and no read-back", a.ID, what)
			}
			continue
		}
		if what != "verify" && t.Expect != "" {
			return fmt.Errorf("response: action-templates.json: %s %s: the text to look for belongs to the read-back only", a.ID, what)
		}
		if a.Kind == "box" {
			t.CLI = strings.ReplaceAll(t.CLI, "{text}", "{name}")
		}
		if why := ValidateTpl(t, a.ID+" "+what); why != "" {
			return fmt.Errorf("response: action-templates.json: %s", why)
		}
	}
	if why := readBackProblem(a.Verify); why != "" {
		return fmt.Errorf("response: action-templates.json: %s: %s", a.ID, why)
	}
	if why := cliProblem(stepSet{a.Run, a.Rollback, a.Verify, a.Precheck}, false); why != "" {
		return fmt.Errorf("response: action-templates.json: %s: %s", a.ID, why)
	}
	if why := precheckProblem(a.Precheck, a.PrecheckRefuse, a.PrecheckExpect); why != "" {
		return fmt.Errorf("response: action-templates.json: %s: %s", a.ID, why)
	}
	if a.Kind == "box" && !a.Precheck.Empty() {
		return fmt.Errorf("response: action-templates.json: %s: a box action has no check before", a.ID)
	}
	if a.Kind == "device" && needsPrecheck(a.Run, a.Rollback, a.Verify, a.Precheck, a.PrecheckRefuse, false) {
		return fmt.Errorf("response: action-templates.json: %s names a port and has no check before with a refusal text", a.ID)
	}
	return nil
}

func (s *Service) trigger(id string) *triggerDef {
	for i := range s.triggers {
		if s.triggers[i].ID == id {
			return &s.triggers[i]
		}
	}
	return nil
}

func (s *Service) isDeviceKind(k string) bool {
	for _, x := range s.kinds {
		if x == k {
			return true
		}
	}
	return false
}

// seedCatalog writes the library into resp_catalog: a new action is inserted with the defaults of the file, an existing one
// gets its template, name, risk and description refreshed (an update of the library ships with the box) and keeps
// enabled, ai_may_propose and connection_id, which belong to the user. The sample connection ids of the file are not
// copied: a built-in device action starts with no connection and the customer picks one.
func (s *Service) seedCatalog(ctx context.Context, tx *sql.Tx) error {
	// One statement for every action: SQLite parses it once instead of once per action.
	st, err := tx.PrepareContext(ctx, `INSERT INTO resp_catalog (id, builtin, pack, kind, name, description, connection_id, tool, rollback_tool, run, rollback, verify, precheck, precheck_refuse, precheck_expect, risk, enabled, ai_may_propose, position)
VALUES (?, 1, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET pack = excluded.pack, kind = excluded.kind, name = excluded.name, description = excluded.description,
  tool = excluded.tool, rollback_tool = excluded.rollback_tool, run = excluded.run, rollback = excluded.rollback, verify = excluded.verify,
  precheck = excluded.precheck, precheck_refuse = excluded.precheck_refuse, precheck_expect = excluded.precheck_expect, risk = excluded.risk, position = excluded.position
WHERE resp_catalog.builtin = 1`)
	if err != nil {
		return fmt.Errorf("response: seed the catalog: %w", err)
	}
	defer func() { _ = st.Close() }()
	for i, a := range s.cat {
		desc := a.Description
		if a.Unverified {
			desc += " " + s.catNote + "."
		}
		run, rollback, verify, pre, refuse := mustJSON(a.Run), mustJSON(a.Rollback), mustJSON(a.Verify), mustJSON(a.Precheck), mustJSON(nonNilStrings(a.PrecheckRefuse))
		_, err = st.ExecContext(ctx,
			a.ID, a.Pack, a.Kind, a.Name, desc, nullable(a.Tool), nullable(a.RollbackTool), run, rollback, verify, pre, refuse, a.PrecheckExpect, string(a.Risk), boolInt(a.Enabled), boolInt(a.AIMayPropose), i)
		if err != nil {
			return fmt.Errorf("response: seed action %s: %w", a.ID, err)
		}
	}
	return nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("response: marshal: " + err.Error()) // only plain structs go through here
	}
	return string(b)
}

// interfaceAddrs reads the addresses of the box's network interfaces. A failed read is an error, never an empty list: the
// caller must not go on as if the box had no address (the box's own addresses are never-touch and never a webhook target).
func interfaceAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("response: read the box addresses: %w", err)
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(p.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out, nil
}

func asAPI(err error) (*apierr.Error, bool) { return apierr.As(err) }

func fail(status int, code, msg string) *apierr.Error { return apierr.New(status, code, msg) }
