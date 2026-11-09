package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/go-faster/jx"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// PrivacyFacts answers the three "is it set up" questions of the Privacy page that belong to other modules.
// Core must not read their tables, so the binary supplies this port (cmd/vedette). A nil port, or a module
// without a backend yet, gives the truth of today: no AI provider, default NTP servers, no OIDC issuer.
type PrivacyFacts interface {
	AIConfigured(ctx context.Context) bool   // flow 3: a provider is configured
	NTPPublic(ctx context.Context) bool      // flow 10: time requests leave the LAN
	OIDCConfigured(ctx context.Context) bool // flow 11: an issuer is configured
}

// The two switches are on when absent from the stored setting.
func (p privacySetting) updateCheck() bool { return p.UpdateCheck == nil || *p.UpdateCheck }
func (p privacySetting) telemetry() bool   { return p.Telemetry == nil || *p.Telemetry }

func (h *APIHandlers) privacySetting(ctx context.Context, q *coredb.Queries) (privacySetting, error) {
	var p privacySetting
	raw, err := q.GetSetting(ctx, keyPrivacy)
	if isNoRows(err) {
		return p, nil
	}
	if err != nil {
		return p, fmt.Errorf("core: read setting %s: %w", keyPrivacy, err)
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, fmt.Errorf("core: setting %s is not valid: %w", keyPrivacy, err)
	}
	return p, nil
}

func (h *APIHandlers) privacyFlows(ctx context.Context, p privacySetting) []oas.CoreGetCorePrivacyOKFlowsItem {
	aiConf, ntpPub, oidcConf := false, true, false
	if h.facts != nil {
		aiConf, ntpPub, oidcConf = h.facts.AIConfigured(ctx), h.facts.NTPPublic(ctx), h.facts.OIDCConfigured(ctx)
	}
	state := func(on bool) oas.CoreGetCorePrivacyOKFlowsItemState {
		if on {
			return oas.CoreGetCorePrivacyOKFlowsItemStateOn
		}
		return oas.CoreGetCorePrivacyOKFlowsItemStateOff
	}
	cond := func(on bool) oas.CoreGetCorePrivacyOKFlowsItemState {
		if on {
			return oas.CoreGetCorePrivacyOKFlowsItemStateConditional
		}
		return oas.CoreGetCorePrivacyOKFlowsItemStateOff
	}
	const (
		sw = oas.CoreGetCorePrivacyOKFlowsItemControlSwitch
		rs = oas.CoreGetCorePrivacyOKFlowsItemControlReason
	)
	ai := aiConf && h.reg.Enabled("ai")
	always := oas.CoreGetCorePrivacyOKFlowsItemStateConditional
	return []oas.CoreGetCorePrivacyOKFlowsItem{
		{ID: 1, State: oas.CoreGetCorePrivacyOKFlowsItemStateOn, Control: rs},
		{ID: 2, State: state(p.telemetry()), Control: sw},
		{ID: 3, State: state(ai), Control: rs, Configured: oas.NewOptBool(ai)},
		{ID: 4, State: always, Control: rs},
		{ID: 5, State: always, Control: rs},
		{ID: 6, State: state(p.updateCheck()), Control: sw},
		{ID: 7, State: always, Control: rs},
		{ID: 8, State: cond(h.reg.Enabled("ai")), Control: rs},
		{ID: 9, State: state(h.reg.Enabled("exposure")), Control: rs},
		{ID: 10, State: state(ntpPub), Control: rs},
		{ID: 11, State: cond(h.reg.Enabled("auth-oidc") && oidcConf), Control: rs},
	}
}

// privacyView builds the answer of GET and PATCH /core/privacy. D-82: the anonymous signal is never sent, so
// last_sent is null and the payload is empty whatever the switch says.
func (h *APIHandlers) privacyView(ctx context.Context, p privacySetting) *oas.CoreGetCorePrivacyOK {
	return &oas.CoreGetCorePrivacyOK{
		Flows:       h.privacyFlows(ctx, p),
		Telemetry:   oas.CoreGetCorePrivacyOKTelemetry{Enabled: p.telemetry(), LastSent: oas.NilDateTime{Null: true}, Payload: oas.CoreGetCorePrivacyOKTelemetryPayload{}},
		UpdateCheck: p.updateCheck(),
	}
}

// CoreGetCorePrivacy implements GET /core/privacy (viewer).
func (h *APIHandlers) CoreGetCorePrivacy(ctx context.Context) (*oas.CoreGetCorePrivacyOK, error) {
	p, err := h.privacySetting(ctx, coredb.New(h.db.Reader()))
	if err != nil {
		return nil, err
	}
	return h.privacyView(ctx, p), nil
}

// CorePatchCorePrivacy implements PATCH /core/privacy (admin): turns the two switches on or off; an absent
// field is left alone. One audit row per switch in the body.
func (h *APIHandlers) CorePatchCorePrivacy(ctx context.Context, req *oas.CorePatchCorePrivacyReq) (*oas.CorePatchCorePrivacyOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	var p privacySetting
	err = h.db.Write(ctx, func(tx *sql.Tx) error {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		q := coredb.New(tx)
		cur, err := h.privacySetting(ctx, q)
		if err != nil {
			return err
		}
		onOff := map[bool]string{true: "on", false: "off"}
		if v, ok := req.Telemetry.Get(); ok {
			cur.Telemetry = &v
			if err := h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: "privacy.telemetry", Target: "anonymous signal", Detail: onOff[v]}); err != nil {
				return err
			}
		}
		if v, ok := req.UpdateCheck.Get(); ok {
			cur.UpdateCheck = &v
			if err := h.audit.Append(ctx, tx, audit.Entry{User: c.Email, Action: "privacy.update_check", Target: "update check", Detail: onOff[v]}); err != nil {
				return err
			}
		}
		b, err := json.Marshal(cur)
		if err != nil {
			return fmt.Errorf("core: encode setting %s: %w", keyPrivacy, err)
		}
		if err := q.UpsertSetting(ctx, coredb.UpsertSettingParams{Key: keyPrivacy, Value: string(b), UpdatedAt: store.FormatTS(h.now()), UpdatedBy: c.Email}); err != nil {
			return fmt.Errorf("core: write setting %s: %w", keyPrivacy, err)
		}
		p = cur
		return nil
	})
	if err != nil {
		return nil, err
	}
	v := h.privacyView(ctx, p)
	out := &oas.CorePatchCorePrivacyOK{
		Flows:       make([]oas.CorePatchCorePrivacyOKFlowsItem, len(v.Flows)),
		Telemetry:   oas.CorePatchCorePrivacyOKTelemetry{Enabled: v.Telemetry.Enabled, LastSent: v.Telemetry.LastSent, Payload: oas.CorePatchCorePrivacyOKTelemetryPayload(map[string]jx.Raw{})},
		UpdateCheck: v.UpdateCheck,
	}
	for i, f := range v.Flows {
		out.Flows[i] = oas.CorePatchCorePrivacyOKFlowsItem{ID: f.ID, Configured: f.Configured, State: oas.CorePatchCorePrivacyOKFlowsItemState(f.State), Control: oas.CorePatchCorePrivacyOKFlowsItemControl(f.Control)}
	}
	return out, nil
}
