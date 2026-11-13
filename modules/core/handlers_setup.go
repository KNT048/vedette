package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// Module bundles of the first-run setup (spec A6 step 3). Keep them equal to web/src/features/core/bundles.ts:
// TestBundlesMatchTheWebList fails when they drift.
var (
	bundleSMB = []string{"core", "feeds", "inventory", "notify", "sensor-passive", "findings", "mitigation", "honeypot", "reports"}
	bundleMid = append(slices.Clone(bundleSMB), "sensor-active", "scan", "exposure", "logs", "ai")
)

// Error codes of the setup operations, besides those of core/auth and modreg.
const (
	CodeAlreadySetup      = "already_setup"
	CodeInvalidOrg        = "invalid_org"
	CodeInvalidLan        = "invalid_lan"
	CodePublicRange       = "public_range"
	CodeOverlapRange      = "overlap_range"
	CodeInvalidBundle     = "invalid_bundle"
	CodeInvalidModule     = "invalid_module"
	CodeSampleUnavailable = "sample_unavailable"
)

const defaultTimezone = "Asia/Ho_Chi_Minh" // the column default of core_org.timezone

func alreadySetup() *apierr.Error {
	return apierr.New(409, CodeAlreadySetup, "This box is already set up. Sign in with the administrator account.")
}

// CoreGetSetup implements GET /setup (public): whether first-run setup is done. Before setup there is no org row.
func (h *APIHandlers) CoreGetSetup(ctx context.Context) (*oas.CoreGetSetupOK, error) {
	org, err := coredb.New(h.db.Reader()).GetOrg(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return &oas.CoreGetSetupOK{Complete: false, Org: "", DataMode: oas.CoreGetSetupOKDataModeClean}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("core: read org: %w", err)
	}
	return &oas.CoreGetSetupOK{Complete: org.SetupComplete != 0, Org: org.Name, DataMode: oas.CoreGetSetupOKDataMode(org.DataMode)}, nil
}

// CoreGetCoreSetupModules implements GET /core/setup/modules (public): module ids, tiers and dependencies
// for the bundle step. It does not say which modules are on. While setup is open it offers the box's own network
// (lan) as the first range of the network step (D-405); once setup is done lan is null, so the public page tells
// nobody the box's network afterwards.
func (h *APIHandlers) CoreGetCoreSetupModules(ctx context.Context) (*oas.CoreGetCoreSetupModulesOK, error) {
	states := h.reg.List()
	out := &oas.CoreGetCoreSetupModulesOK{Modules: make([]oas.CoreGetCoreSetupModulesOKModulesItem, 0, len(states))}
	for _, s := range states {
		it := oas.CoreGetCoreSetupModulesOKModulesItem{
			ID:        oas.CoreGetCoreSetupModulesOKModulesItemID(s.ID),
			Tier:      oas.CoreGetCoreSetupModulesOKModulesItemTier(s.Tier),
			Depends:   make([]oas.CoreGetCoreSetupModulesOKModulesItemDependsItem, 0, len(s.Depends)),
			Available: s.Available,
		}
		for _, d := range s.Depends {
			it.Depends = append(it.Depends, oas.CoreGetCoreSetupModulesOKModulesItemDependsItem(d))
		}
		out.Modules = append(out.Modules, it)
	}
	out.Install = oas.CoreGetCoreSetupModulesOKInstall(installKind(h.reg))
	out.Lan = oas.NilString{Null: true}
	if h.boxLAN != nil {
		if done, err := h.setupDone(ctx); err == nil && !done {
			if p, ok := h.boxLAN(ctx); ok && isPrivateLAN(p) && p.Bits() >= 16 { // a flat /8 or /12 is not offered as a whole scan scope
				out.Lan = oas.NewNilString(p.Masked().String())
			}
		}
	}
	return out, nil
}

// privateNets are the ranges a LAN range may lie in: 10/8, 172.16/12, 192.168/16 (the rule of the inventory
// module). A prefix shorter than these (10.0.0.0/0) covers the Internet and is refused.
var privateNets = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}

// isPrivateLAN is the rule of parseLan for one IPv4 prefix: inside a private network, not wider than it.
func isPrivateLAN(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && slices.ContainsFunc(privateNets, func(n netip.Prefix) bool { return n.Bits() <= p.Bits() && n.Contains(p.Addr()) })
}

// parseLan checks the LAN ranges of the setup form (1 to 16 IPv4 ranges inside the private networks) and
// returns them in canonical form (host bits cleared).
func parseLan(in []string) ([]string, *apierr.Error) {
	var raw []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			raw = append(raw, s)
		}
	}
	if len(raw) < 1 || len(raw) > 16 {
		return nil, apierr.New(400, CodeInvalidLan, "Enter 1 to 16 LAN ranges, for example 192.168.10.0/24.")
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() || p.Addr().Zone() != "" || strings.Contains(s, "%") {
			return nil, apierr.New(400, CodeInvalidLan, fmt.Sprintf("The range %q is not valid. Write it like 192.168.10.0/24.", clip(s)))
		}
		if !isPrivateLAN(p) {
			return nil, apierr.New(400, CodePublicRange, fmt.Sprintf("%s is not a private range (10.x, 172.16-31.x, 192.168.x). Add public addresses later under External exposure.", clip(s)))
		}
		if m := p.Masked().String(); !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	// The ranges become the inventory's scope (INV-15), so they obey its rule here too, before anything is written: no two overlap
	// (inventory INV-6; same code and words as Devices -> Scope and sensors, D-298).
	for i, a := range out {
		for j, b := range out {
			if i != j && netip.MustParsePrefix(a).Overlaps(netip.MustParsePrefix(b)) {
				return nil, apierr.New(400, CodeOverlapRange, "Range "+a+" overlaps "+b+". Keep the larger range and drop the smaller one.")
			}
		}
	}
	return out, nil
}

// clip shortens text a client sent before it goes into a message.
func clip(s string) string {
	if utf8.RuneCountInString(s) > 40 {
		return string([]rune(s)[:40]) + "…"
	}
	return s
}

func validOrgName(s string) bool {
	n := utf8.RuneCountInString(s)
	return n >= 2 && n <= 80 && utf8.ValidString(s) && !auth.HasInvisible(s)
}

// runnable leaves out of a bundle the modules this install cannot run (D-381): a container-only install has no
// honeypot, and a bundle does not promise one. A custom choice that names one is refused by the registry instead.
func runnable(bundle []string, known map[string]modreg.State) []string {
	return slices.DeleteFunc(slices.Clone(bundle), func(id string) bool { s, ok := known[id]; return ok && !s.Available })
}

// wantedModules turns the bundle choice of the setup form into the set of modules that must be on.
func (h *APIHandlers) wantedModules(req *oas.CorePostCoreSetupReq) (map[string]bool, *apierr.Error) {
	states := h.reg.List()
	known := make(map[string]modreg.State, len(states))
	for _, s := range states {
		known[s.ID] = s
	}
	var ids []string
	switch oas.CorePostCoreSetupReqBundle(req.Bundle.Or("")) {
	case "smb":
		ids = runnable(bundleSMB, known)
	case "mid":
		ids = runnable(bundleMid, known)
	case "custom":
		ids = []string{"core"}
		for _, m := range req.Modules {
			id := string(m)
			if _, ok := known[id]; !ok {
				return nil, apierr.New(400, CodeInvalidModule, fmt.Sprintf("No module %q.", clip(id)))
			}
			ids = append(ids, id)
		}
	default:
		return nil, apierr.New(400, CodeInvalidBundle, "Choose a module bundle: smb, mid or custom.")
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	for _, id := range ids {
		var lacking []string
		for _, d := range known[id].Depends {
			if !want[d] {
				lacking = append(lacking, d)
			}
		}
		if len(lacking) > 0 {
			return nil, apierr.New(400, apierr.CodeMissingDeps, fmt.Sprintf("Module %s also needs: %s.", id, strings.Join(lacking, ", "))).With("missing", lacking)
		}
	}
	return want, nil
}

// CorePostCoreSetup implements POST /core/setup (public): first-run setup. It creates the organization, the
// first administrator and a session for them (the response sets the session and CSRF cookies, as a sign-in does; no device cookie), turns the chosen bundle on and writes core_audit, all in one
// transaction, and only while setup is not done (INV-15). Creating the administrator needs the one-time
// setup code from the box's log (D-75). Order of refusals: already set up (also for sample data), the build has no
// sample data, setup code, then the fields in the order of the form.
func (h *APIHandlers) CorePostCoreSetup(ctx context.Context, req *oas.CorePostCoreSetupReq) (*oas.CorePostCoreSetupOK, error) {
	if done, err := h.setupDone(ctx); err != nil {
		return nil, err
	} else if done {
		return nil, alreadySetup()
	}
	if req.Sample.Or(false) {
		// INV-15: sample data exists only in builds with data_mode=sample; this build has none.
		return nil, apierr.New(400, CodeSampleUnavailable, "This build has no sample data. Fill in the setup form instead.")
	}
	x, ip, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	refund, werr := h.auth.BeginSetupAttempt(ip)
	if werr != nil {
		return nil, werr
	}
	want, ok, err := h.storedSetupCode(ctx)
	if err != nil {
		refund() // not a guess: nothing was judged
		return nil, err
	}
	if !ok {
		// No code is stored: setup finished between the check above and the read (the winner deleted it),
		// or this box has not made one yet. The loser of a race is told the truth and keeps its guess.
		if done, err := h.setupDone(ctx); err != nil {
			refund()
			return nil, err
		} else if done {
			refund()
			return nil, alreadySetup()
		}
		return nil, invalidSetupCode()
	}
	if !setupCodesEqual(req.SetupCode.Or(""), want) {
		return nil, invalidSetupCode()
	}
	refund() // the right code gives its count back

	org := strings.TrimSpace(req.Org.Or(""))
	if !validOrgName(org) {
		return nil, apierr.New(400, CodeInvalidOrg, "The organization name is 2 to 80 characters.")
	}
	adm := req.Admin.Or(oas.CorePostCoreSetupReqAdmin{})
	name := strings.TrimSpace(adm.Name)
	email, verr := auth.ValidateUserFields(name, adm.Email, routes.Admin)
	if verr != nil {
		return nil, verr
	}
	if verr := auth.ValidatePassword(adm.Password, email); verr != nil {
		return nil, verr
	}
	lan, lerr := parseLan(req.Lan)
	if lerr != nil {
		return nil, lerr
	}
	wantMods, merr := h.wantedModules(req)
	if merr != nil {
		return nil, merr
	}
	hash, err := h.auth.HashPassword(ctx, adm.Password, email)
	if err != nil {
		return nil, err
	}

	var (
		sess    auth.Issued
		changes []modreg.Change
		scopeTx *sql.Tx // the transaction the inventory wrote the scope in, settled once it is over
	)
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		q := coredb.New(tx)
		if _, err := q.GetOrg(ctx); err == nil {
			return alreadySetup() // another request finished setup while this one hashed
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("core: read org: %w", err)
		}
		if err := q.InsertOrg(ctx, coredb.InsertOrgParams{Name: org, Timezone: defaultTimezone, DataMode: "clean", InstallID: store.NewID("ins")}); err != nil {
			return fmt.Errorf("core: insert org: %w", err)
		}
		u, err := h.auth.CreateUser(ctx, tx, email, auth.NewUser{Name: name, Email: email, Role: routes.Admin, PasswordHash: hash})
		if err != nil {
			return err
		}
		for _, s := range h.reg.List() {
			if s.Tier == modreg.TierCore || s.Enabled == wantMods[s.ID] {
				continue
			}
			var ch modreg.Change
			if wantMods[s.ID] {
				ch, err = h.reg.Enable(ctx, tx, email, s.ID, true)
			} else {
				ch, err = h.reg.Disable(ctx, tx, email, s.ID)
			}
			if err != nil {
				return err
			}
			changes = append(changes, ch)
		}
		scope, err := json.Marshal(map[string]any{"lan": lan, "commitment": req.Commitment.Or(false)})
		if err != nil {
			return fmt.Errorf("core: encode setup scope: %w", err)
		}
		now := store.FormatTS(h.now())
		if err := q.UpsertSetting(ctx, coredb.UpsertSettingParams{Key: "setup.scope", Value: string(scope), UpdatedAt: now, UpdatedBy: email}); err != nil {
			return fmt.Errorf("core: store setup scope: %w", err)
		}
		// The ranges and the commitment are the inventory's scope (Devices -> Scope and sensors) from now on, in this same commit (#350).
		if h.scope != nil {
			scopeTx = tx
			if err := h.scope.SetupScope(ctx, tx, email, lan, req.Commitment.Or(false)); err != nil {
				return err
			}
		}
		if err := q.UpdateUserLastLogin(ctx, coredb.UpdateUserLastLoginParams{LastLogin: &now, ID: u.ID}); err != nil {
			return fmt.Errorf("core: set last_login: %w", err)
		}
		sess, err = h.auth.Sessions.Create(ctx, tx, u.ID, x.R.UserAgent(), ip)
		if err != nil {
			return err
		}
		// The administrator is signed in as a password sign-in does (same session, same audit row).
		if err := h.audit.Append(ctx, tx, audit.Entry{User: email, Action: "auth.login", Target: email}); err != nil {
			return err
		}
		detail := fmt.Sprintf("bundle %s, %d ranges", req.Bundle.Or(""), len(lan))
		if req.Commitment.Or(false) {
			detail += ", active-scan commitment confirmed"
		}
		if err := h.audit.Append(ctx, tx, audit.Entry{User: email, Action: "core.setup", Target: org, Detail: detail}); err != nil {
			return err
		}
		return h.dropSetupCode(ctx, tx)
	})
	if err != nil {
		if scopeTx != nil {
			h.scope.Settle(context.WithoutCancel(ctx), scopeTx, false)
		}
		return nil, err
	}
	for _, ch := range changes {
		h.reg.Publish(ch)
	}
	// After the modules of the bundle are on, so that their listeners of inventory.settings.changed take it.
	if scopeTx != nil {
		h.scope.Settle(context.WithoutCancel(ctx), scopeTx, true)
	}
	setSession(x, sess, "")
	return &oas.CorePostCoreSetupOK{Ok: true}, nil
}

// SetupDone reports whether first-run setup has finished (an organization exists and is set up). cmd/vedette asks it before
// it starts a module's container (D-405): nothing beyond core runs on a box before its first administrator exists.
func (h *APIHandlers) SetupDone(ctx context.Context) (bool, error) { return h.setupDone(ctx) }

func (h *APIHandlers) setupDone(ctx context.Context) (bool, error) {
	org, err := coredb.New(h.db.Reader()).GetOrg(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("core: read org: %w", err)
	}
	return org.SetupComplete != 0, nil
}
