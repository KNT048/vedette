package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store/coredb"
)

// deviceCookieValue is the value of the device cookie the browser sent, "" when there is none.
func deviceCookieValue(x server.Exchange) string {
	c, err := x.R.Cookie(auth.CookieDevice)
	if err != nil {
		return ""
	}
	return c.Value
}

// CorePostAuthLogin implements POST /auth/login (public): core INV-8. On success it sets the session, CSRF
// and device cookies; the body only says ok.
func (h *Handlers) CorePostAuthLogin(ctx context.Context, req *oas.CorePostAuthLoginReq) (*oas.CorePostAuthLoginOK, error) {
	x, ip, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	res, err := h.auth.Login(ctx, auth.LoginRequest{
		Email: req.Email, Password: req.Password, Code: req.Code.Or(""),
		IP: ip, UserAgent: x.R.UserAgent(), DeviceCookie: deviceCookieValue(x),
	})
	if err != nil {
		return nil, err
	}
	setSession(x, res.Session, res.Device)
	return &oas.CorePostAuthLoginOK{Ok: true}, nil
}

// CorePostAuthLoginResendCode implements POST /auth/login/resend-code (public): the password is needed again.
func (h *Handlers) CorePostAuthLoginResendCode(ctx context.Context, req *oas.CorePostAuthLoginResendCodeReq) (*oas.CorePostAuthLoginResendCodeOK, error) {
	x, ip, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	sent, err := h.auth.ResendCode(ctx, req.Email, req.Password, ip, deviceCookieValue(x))
	if err != nil {
		return nil, err
	}
	return &oas.CorePostAuthLoginResendCodeOK{SentTo: sent.SentTo, ResendAfter: sent.ResendAfter}, nil
}

// CorePostAuthLogout implements POST /auth/logout (public): ends the session of the cookie, if any, and
// clears both cookies. It is 204 whether or not there was a live session.
func (h *Handlers) CorePostAuthLogout(ctx context.Context) error {
	x, ok := server.ExchangeFrom(ctx)
	if !ok {
		return errors.New("core: no HTTP exchange in the request context")
	}
	if c, err := x.R.Cookie(auth.CookieSession); err == nil {
		if err := h.auth.Sessions.Logout(ctx, c.Value); err != nil {
			return err
		}
	}
	for _, c := range auth.ClearCookies() {
		x.SetCookie(c)
	}
	return nil
}

// CoreGetCoreAuthOptions implements GET /core/auth-options (public): the SSO button exists only with the
// auth-oidc module, which is not built yet.
func (h *Handlers) CoreGetCoreAuthOptions(context.Context) (*oas.CoreGetCoreAuthOptionsOK, error) {
	return &oas.CoreGetCoreAuthOptionsOK{Oidc: false}, nil
}

// CoreGetMe implements GET /me (viewer).
func (h *Handlers) CoreGetMe(ctx context.Context) (*oas.CoreGetMeOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	u, err := h.auth.GetUser(ctx, p.ID)
	if err != nil {
		return nil, meError(err)
	}
	org, err := h.orgName(ctx)
	if err != nil {
		return nil, err
	}
	out := &oas.CoreGetMeOK{ID: u.ID, Name: u.Name, Email: u.Email, Role: oas.CoreGetMeOKRole(u.Role), Org: org, Twofa: u.TwofaMethod != ""}
	if u.TwofaMethod != "" {
		out.TwofaMethod = oas.NewNilCoreGetMeOKTwofaMethod(oas.CoreGetMeOKTwofaMethod(u.TwofaMethod))
	} else {
		out.TwofaMethod = oas.NilCoreGetMeOKTwofaMethod{Null: true}
	}
	return out, nil
}

// meError: a session whose user row is gone cannot happen (core_session cascades), and means signed out.
func meError(err error) error {
	if e, ok := apierr.As(err); ok && e.Status == 404 {
		return apierr.Unauthenticated()
	}
	return err
}

// orgName is the organization name, "" before setup.
func (h *Handlers) orgName(ctx context.Context) (string, error) {
	org, err := coredb.New(h.db.Reader()).GetOrg(ctx)
	if err != nil {
		if isNoRows(err) {
			return "", nil
		}
		return "", fmt.Errorf("core: read org: %w", err)
	}
	return org.Name, nil
}
