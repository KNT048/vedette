package core

import (
	"context"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
)

// CoreGetCoreAccount implements GET /core/account (viewer): my profile, whether the email method of
// two-step sign-in can be chosen, and my live sessions with the current one marked.
func (h *APIHandlers) CoreGetCoreAccount(ctx context.Context) (*oas.CoreGetCoreAccountOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	u, err := h.auth.GetUser(ctx, c.ID)
	if err != nil {
		return nil, meError(err)
	}
	list, err := h.auth.Sessions.List(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	out := &oas.CoreGetCoreAccountOK{Sessions: make([]oas.CoreGetCoreAccountOKSessionsItem, 0, len(list))}
	for _, s := range list {
		out.Sessions = append(out.Sessions, oas.CoreGetCoreAccountOKSessionsItem{
			ID: s.ID, Device: s.Device, IP: s.IP, StartedAt: s.StartedAt, LastSeen: s.LastSeen, Current: s.ID == c.SessionID,
		})
	}
	out.User = oas.CoreGetCoreAccountOKUser{
		ID: u.ID, Name: u.Name, Email: u.Email, Role: oas.CoreGetCoreAccountOKUserRole(u.Role), Twofa: u.TwofaMethod != "",
		CreatedAt: u.CreatedAt, LastLogin: nilTime(u.LastLogin),
	}
	if u.TwofaMethod != "" {
		out.User.TwofaMethod = oas.NewNilCoreGetCoreAccountOKUserTwofaMethod(oas.CoreGetCoreAccountOKUserTwofaMethod(u.TwofaMethod))
	} else {
		out.User.TwofaMethod = oas.NilCoreGetCoreAccountOKUserTwofaMethod{Null: true}
	}
	out.TwofaEmail = oas.CoreGetCoreAccountOKTwofaEmail{SentTo: auth.MaskEmail(u.Email), Reason: oas.NilCoreGetCoreAccountOKTwofaEmailReason{Null: true}}
	switch {
	case !h.reg.Enabled("notify"):
		out.TwofaEmail.Reason = oas.NewNilCoreGetCoreAccountOKTwofaEmailReason(oas.CoreGetCoreAccountOKTwofaEmailReasonModuleOff)
	case !h.auth.Codes.Available(ctx):
		out.TwofaEmail.Reason = oas.NewNilCoreGetCoreAccountOKTwofaEmailReason(oas.CoreGetCoreAccountOKTwofaEmailReasonChannelNotReady)
	default:
		out.TwofaEmail.Available = true
	}
	return out, nil
}

// CorePatchCoreAccount implements PATCH /core/account (viewer): the display name.
func (h *APIHandlers) CorePatchCoreAccount(ctx context.Context, req *oas.CorePatchCoreAccountReq) (*oas.CorePatchCoreAccountOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.auth.UpdateOwnName(ctx, c.ID, c.SessionID, req.Name); err != nil {
		return nil, err
	}
	return &oas.CorePatchCoreAccountOK{Ok: true}, nil
}

// CorePostCoreAccountPassword implements POST /core/account/password (viewer): every session ends and the
// response sets new session and CSRF cookies for this browser.
func (h *APIHandlers) CorePostCoreAccountPassword(ctx context.Context, req *oas.CorePostCoreAccountPasswordReq) (*oas.CorePostCoreAccountPasswordOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	// A password change kills every device cookie of the account (cred_version). The owner has just proved the
	// current password in this browser, which is what a sign-in proves, so this browser gets a device cookie for
	// the new password as a sign-in would give it (D-77). The old cookie cannot be checked here: its path is
	// /api/v1/auth/, so the browser does not send it to this endpoint.
	fresh, err := h.auth.ChangeOwnPassword(ctx, c.ID, c.SessionID, req.Current, req.Next)
	if err != nil {
		return nil, err
	}
	if err := renewSession(ctx, fresh, h.auth.NewDevice(ctx, c.ID)); err != nil {
		return nil, err
	}
	return &oas.CorePostCoreAccountPasswordOK{Ok: true}, nil
}

// CorePostCoreAccount2FAStart implements POST /core/account/2fa/start (viewer): needs the current password (D-76).
func (h *APIHandlers) CorePostCoreAccount2FAStart(ctx context.Context, req *oas.CorePostCoreAccount2FAStartReq) (*oas.CorePostCoreAccount2FAStartOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	s, err := h.auth.StartTOTP(ctx, c.ID, c.SessionID, req.Password)
	if err != nil {
		return nil, err
	}
	return &oas.CorePostCoreAccount2FAStartOK{Secret: s.Secret, Otpauth: s.URI}, nil
}

// CorePostCoreAccount2FAConfirm implements POST /core/account/2fa/confirm (viewer).
func (h *APIHandlers) CorePostCoreAccount2FAConfirm(ctx context.Context, req *oas.CorePostCoreAccount2FAConfirmReq) (*oas.CorePostCoreAccount2FAConfirmOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	fresh, err := h.auth.ConfirmTOTP(ctx, c.ID, c.SessionID, req.Code)
	if err != nil {
		return nil, err
	}
	if err := renewSession(ctx, fresh, ""); err != nil {
		return nil, err
	}
	return &oas.CorePostCoreAccount2FAConfirmOK{Ok: true}, nil
}

// CorePostCoreAccount2FAEmailStart implements POST /core/account/2fa/email/start (viewer): needs the current password (D-76).
func (h *APIHandlers) CorePostCoreAccount2FAEmailStart(ctx context.Context, req *oas.CorePostCoreAccount2FAEmailStartReq) (*oas.CorePostCoreAccount2FAEmailStartOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	s, err := h.auth.StartEmail2FA(ctx, c.ID, c.SessionID, req.Password)
	if err != nil {
		return nil, err
	}
	return &oas.CorePostCoreAccount2FAEmailStartOK{SentTo: s.SentTo, ResendAfter: s.ResendAfter}, nil
}

// CorePostCoreAccount2FAEmailConfirm implements POST /core/account/2fa/email/confirm (viewer).
func (h *APIHandlers) CorePostCoreAccount2FAEmailConfirm(ctx context.Context, req *oas.CorePostCoreAccount2FAEmailConfirmReq) (*oas.CorePostCoreAccount2FAEmailConfirmOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	fresh, err := h.auth.ConfirmEmail2FA(ctx, c.ID, c.SessionID, req.Code)
	if err != nil {
		return nil, err
	}
	if err := renewSession(ctx, fresh, ""); err != nil {
		return nil, err
	}
	return &oas.CorePostCoreAccount2FAEmailConfirmOK{Ok: true}, nil
}

// CorePostCoreAccount2FADisable implements POST /core/account/2fa/disable (viewer): needs the password.
func (h *APIHandlers) CorePostCoreAccount2FADisable(ctx context.Context, req *oas.CorePostCoreAccount2FADisableReq) (*oas.CorePostCoreAccount2FADisableOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	fresh, err := h.auth.DisableTwoFA(ctx, c.ID, c.SessionID, req.Password)
	if err != nil {
		return nil, err
	}
	if err := renewSession(ctx, fresh, ""); err != nil {
		return nil, err
	}
	return &oas.CorePostCoreAccount2FADisableOK{Ok: true}, nil
}

// CoreDeleteCoreAccountSessionsID implements DELETE /core/account/sessions/{id} (viewer): one of my other
// sessions; the one I am using is 400 current_session (sign out instead).
func (h *APIHandlers) CoreDeleteCoreAccountSessionsID(ctx context.Context, params oas.CoreDeleteCoreAccountSessionsIDParams) error {
	c, err := h.caller(ctx)
	if err != nil {
		return err
	}
	if params.ID == c.SessionID {
		return apierr.New(400, "current_session", `This is the session you are using. Use "Sign out" in the account menu.`)
	}
	return h.auth.Sessions.Revoke(ctx, c.Email, c.ID, params.ID)
}

// CorePostCoreAccountSessionsRevokeOthers implements POST /core/account/sessions/revoke-others (viewer).
func (h *APIHandlers) CorePostCoreAccountSessionsRevokeOthers(ctx context.Context) (*oas.CorePostCoreAccountSessionsRevokeOthersOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	n, err := h.auth.Sessions.RevokeOthers(ctx, c.Email, c.ID, c.SessionID)
	if err != nil {
		return nil, err
	}
	return &oas.CorePostCoreAccountSessionsRevokeOthersOK{Ok: true, Revoked: float64(n)}, nil
}
