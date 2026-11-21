package agentintake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
)

// AdminHandlers implement the token operations and the page of the Agents section (CONTRACT "Endpoints owned"). The route table requires the
// admin role for all of them; the server answers 404 while the module is off (SYS-5).
type AdminHandlers struct{ s *Service }

// NewAdminHandlers wraps the service; nil gives 501 for every operation, like a module that is not wired.
func NewAdminHandlers(s *Service) *AdminHandlers { return &AdminHandlers{s: s} }

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// nilTime is a time of the service as the contract has it: the zero time is null.
func nilTime(t time.Time) oas.NilDateTime {
	if t.IsZero() {
		return oas.NilDateTime{Null: true}
	}
	return oas.NewNilDateTime(t)
}

// InventoryGetInventoryAgents implements GET /inventory/agents: the tokens (last four characters only), the Wazuh card, and what the install
// box needs: the scripts as the box serves them to the very address this request came in at, and their SHA-256.
func (h *AdminHandlers) InventoryGetInventoryAgents(ctx context.Context) (*oas.InventoryGetInventoryAgentsOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	if _, err := adminActor(ctx); err != nil {
		return nil, err
	}
	x, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	list, err := h.s.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	sh, ps1, err := h.s.installFor(ctx, x.R.Host, true)
	if err != nil {
		return nil, fmt.Errorf("agentintake: the box certificate: %w", err)
	}
	box := h.s.boxURL(x.R.Host)
	out := &oas.InventoryGetInventoryAgentsOK{
		ServerURL: box,
		Tokens:    make([]oas.InventoryGetInventoryAgentsOKTokensItem, 0, len(list)),
		Wazuh:     oas.NilInventoryGetInventoryAgentsOKWazuh{Null: true},
	}
	out.Install.OsqueryVersion = OsqueryVersion
	out.Install.Linux = oas.InventoryGetInventoryAgentsOKInstallLinux{URL: box + "/api/v1/install/osquery.sh", SHA256: sha256Hex(sh), Script: sh}
	out.Install.Windows = oas.InventoryGetInventoryAgentsOKInstallWindows{URL: box + "/api/v1/install/osquery.ps1", SHA256: sha256Hex(ps1), Script: ps1}
	out.Install.Packages = h.s.packages(ctx)
	for _, t := range list {
		out.Tokens = append(out.Tokens, oas.InventoryGetInventoryAgentsOKTokensItem{
			ID: t.ID, Name: t.Name, Kind: oas.InventoryGetInventoryAgentsOKTokensItemKindOsquery, Last4: t.Last4, CreatedAt: t.CreatedAt, Hosts: t.Hosts, CreatedBy: nilStr(t.CreatedBy),
			DeviceID:     nilStr(t.DeviceID),
			ExpiresAt:    nilTime(t.ExpiresAt),
			LastReceived: nilTime(t.LastReceived),
		})
	}
	nodes, err := h.s.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	out.Nodes = make([]oas.InventoryGetInventoryAgentsOKNodesItem, 0, len(nodes))
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, oas.InventoryGetInventoryAgentsOKNodesItem{
			ID: n.ID, TokenID: n.TokenID, Host: n.Host, Os: oas.InventoryGetInventoryAgentsOKNodesItemOs(n.OS), State: oas.InventoryGetInventoryAgentsOKNodesItemState(n.State),
			EnrolledAt: n.EnrolledAt, LastSeen: n.LastSeen, LastResultAt: nilTime(n.LastResult), QuietSince: nilTime(n.QuietSince), RhythmS: seconds(n.Rhythm),
		})
	}
	w, err := h.s.Wazuh(ctx)
	if err != nil {
		return nil, err
	}
	if w != nil {
		c := oas.InventoryGetInventoryAgentsOKWazuh{
			URL: w.URL, Username: w.Username, PasswordLast4: w.PasswordLast4, IntervalMinutes: w.IntervalMinutes,
			Status: oas.InventoryGetInventoryAgentsOKWazuhStatus(w.Status), Agents: w.Agents, Packages: w.Packages,
			LastSync: nilTime(w.LastSync), Error: oas.NilString{Null: true},
		}
		if w.Error != "" {
			c.Error = oas.NewNilString(w.Error)
		}
		out.Wazuh = oas.NewNilInventoryGetInventoryAgentsOKWazuh(c)
	}
	return out, nil
}

// InventoryPostInventoryAgentsTokens implements POST /inventory/agents/tokens: the secret is in this answer and nowhere else, and never in the
// audit line or the log (INV-3, INV-4). The default expiry is 7 days.
func (h *AdminHandlers) InventoryPostInventoryAgentsTokens(ctx context.Context, req *oas.InventoryPostInventoryAgentsTokensReq) (*oas.InventoryPostInventoryAgentsTokensCreated, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return nil, err
	}
	device := req.DeviceID.Or("")
	if device != "" && !validDeviceID(device) {
		return nil, apierr.NotFound()
	}
	t, secret, err := h.s.IssueTokenFor(ctx, who, req.Name, req.ExpiresInDays.Or(7), device)
	if err != nil {
		return nil, err
	}
	tok := oas.InventoryPostInventoryAgentsTokensCreatedToken{
		ID: t.ID, Name: t.Name, Kind: oas.InventoryPostInventoryAgentsTokensCreatedTokenKindOsquery, Last4: t.Last4, CreatedAt: t.CreatedAt,
		ExpiresAt: oas.NilDateTime{Null: true}, LastReceived: oas.NilDateTime{Null: true}, CreatedBy: nilStr(t.CreatedBy), DeviceID: nilStr(t.DeviceID),
	}
	if !t.ExpiresAt.IsZero() {
		tok.ExpiresAt = oas.NewNilDateTime(t.ExpiresAt)
	}
	return &oas.InventoryPostInventoryAgentsTokensCreated{Token: tok, Secret: secret}, nil
}

// InventoryDeleteInventoryAgentsTokensID implements DELETE /inventory/agents/tokens/{id}: the token goes with its nodes (POST-3); what they
// already delivered stays in the inventory.
func (h *AdminHandlers) InventoryDeleteInventoryAgentsTokensID(ctx context.Context, params oas.InventoryDeleteInventoryAgentsTokensIDParams) error {
	if h.s == nil {
		return apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return err
	}
	return h.s.RevokeToken(ctx, who, params.ID)
}

// InventoryDeleteInventoryAgentsNodesID implements DELETE /inventory/agents/nodes/{id}: one stale agent record goes, its device is released.
func (h *AdminHandlers) InventoryDeleteInventoryAgentsNodesID(ctx context.Context, params oas.InventoryDeleteInventoryAgentsNodesIDParams) error {
	if h.s == nil {
		return apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return err
	}
	return h.s.RemoveNode(ctx, who, params.ID)
}

// reportWire is the wire form of a ReportState (GET and POST answer the same shape): a zero time and a zero interval are null.
type reportWire struct {
	asked, again, seen, quiet oas.NilDateTime
	minutes, rhythm           oas.NilInt
}

func toWire(st ReportState) reportWire {
	w := reportWire{asked: nilTime(st.AskedAt), again: nilTime(st.AskAgainAt), seen: nilTime(st.LastSeen), quiet: nilTime(st.QuietSince), minutes: oas.NilInt{Null: true}, rhythm: oas.NilInt{Null: true}}
	if st.WazuhMinutes > 0 {
		w.minutes = oas.NewNilInt(st.WazuhMinutes)
	}
	if st.Rhythm > 0 {
		w.rhythm = oas.NewNilInt(seconds(st.Rhythm))
	}
	return w
}

// seconds is a duration in whole seconds, as the contract gives intervals.
func seconds(d time.Duration) int { return int(d / time.Second) }

// validDeviceID is the shape of an inventory id at the boundary (inv_asset.id is 1..96 characters); anything else is no device.
func validDeviceID(id string) bool { return id != "" && len(id) <= 96 }

// InventoryGetInventoryAgentsDevicesIDReport implements GET /inventory/agents/devices/{id}/report (viewer): which agent of this box
// reads the device and the open ask of "I updated it" (report.go).
func (h *AdminHandlers) InventoryGetInventoryAgentsDevicesIDReport(ctx context.Context, params oas.InventoryGetInventoryAgentsDevicesIDReportParams) (*oas.InventoryGetInventoryAgentsDevicesIDReportOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	if !validDeviceID(params.ID) {
		return nil, apierr.NotFound()
	}
	st, err := h.s.ReportState(ctx, params.ID)
	if err != nil {
		return nil, err
	}
	w := toWire(st)
	out := &oas.InventoryGetInventoryAgentsDevicesIDReportOK{Agent: oas.InventoryGetInventoryAgentsDevicesIDReportOKAgent(st.Agent), AskedAt: w.asked, AskAgainAt: w.again,
		LastSeen: w.seen, QuietSince: w.quiet, Stale: st.Stale, WazuhIntervalMinutes: w.minutes, RhythmS: w.rhythm, Off: st.Off,
		State: oas.NilInventoryGetInventoryAgentsDevicesIDReportOKState{Null: true}, Os: oas.NilInventoryGetInventoryAgentsDevicesIDReportOKOs{Null: true}}
	if st.State != "" {
		out.State = oas.NewNilInventoryGetInventoryAgentsDevicesIDReportOKState(oas.InventoryGetInventoryAgentsDevicesIDReportOKState(st.State))
	}
	if st.OS != "" {
		out.Os = oas.NewNilInventoryGetInventoryAgentsDevicesIDReportOKOs(oas.InventoryGetInventoryAgentsDevicesIDReportOKOs(st.OS))
	}
	return out, nil
}

// InventoryPostInventoryAgentsDevicesIDReport implements POST /inventory/agents/devices/{id}/report (operator, audited): "I updated it:
// ask the agent now" (report.go AskReport).
func (h *AdminHandlers) InventoryPostInventoryAgentsDevicesIDReport(ctx context.Context, params oas.InventoryPostInventoryAgentsDevicesIDReportParams) (*oas.InventoryPostInventoryAgentsDevicesIDReportOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return nil, err
	}
	if !validDeviceID(params.ID) {
		return nil, apierr.NotFound()
	}
	st, err := h.s.AskReport(ctx, who, params.ID)
	if err != nil {
		return nil, err
	}
	w := toWire(st)
	out := &oas.InventoryPostInventoryAgentsDevicesIDReportOK{Agent: oas.InventoryPostInventoryAgentsDevicesIDReportOKAgent(st.Agent), AskedAt: w.asked, AskAgainAt: w.again,
		LastSeen: w.seen, QuietSince: w.quiet, Stale: st.Stale, WazuhIntervalMinutes: w.minutes, RhythmS: w.rhythm, Off: st.Off,
		State: oas.NilInventoryPostInventoryAgentsDevicesIDReportOKState{Null: true}, Os: oas.NilInventoryPostInventoryAgentsDevicesIDReportOKOs{Null: true}}
	if st.State != "" {
		out.State = oas.NewNilInventoryPostInventoryAgentsDevicesIDReportOKState(oas.InventoryPostInventoryAgentsDevicesIDReportOKState(st.State))
	}
	if st.OS != "" {
		out.Os = oas.NewNilInventoryPostInventoryAgentsDevicesIDReportOKOs(oas.InventoryPostInventoryAgentsDevicesIDReportOKOs(st.OS))
	}
	return out, nil
}

// InventoryPostInventoryAgentsTokensRemoveUnused implements POST /inventory/agents/tokens/remove-unused: every token no machine enrolled with
// goes (audited); tokens with machines stay.
func (h *AdminHandlers) InventoryPostInventoryAgentsTokensRemoveUnused(ctx context.Context) (*oas.InventoryPostInventoryAgentsTokensRemoveUnusedOK, error) {
	if h.s == nil {
		return nil, apierr.NotImplemented()
	}
	who, err := adminActor(ctx)
	if err != nil {
		return nil, err
	}
	n, err := h.s.RemoveUnusedTokens(ctx, who)
	if err != nil {
		return nil, err
	}
	return &oas.InventoryPostInventoryAgentsTokensRemoveUnusedOK{Removed: n}, nil
}

// nilStr is a string as the contract has it: empty is null.
func nilStr(s string) oas.NilString {
	if s == "" {
		return oas.NilString{Null: true}
	}
	return oas.NewNilString(s)
}
