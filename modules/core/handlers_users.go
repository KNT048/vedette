package core

import (
	"context"
	"database/sql"
	"strings"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/auth"
)

// methodOf returns the two-step method of a user and whether there is one: the generated response types
// differ per operation, so each conversion builds its own nullable field from this.
func methodOf(u auth.User) (string, bool) { return u.TwofaMethod, u.TwofaMethod != "" }

// CoreGetCoreUsers implements GET /core/users (admin).
func (h *APIHandlers) CoreGetCoreUsers(ctx context.Context) (*oas.CoreGetCoreUsersOK, error) {
	list, err := h.auth.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := &oas.CoreGetCoreUsersOK{Items: make([]oas.CoreGetCoreUsersOKItemsItem, 0, len(list))}
	for _, u := range list {
		it := oas.CoreGetCoreUsersOKItemsItem{
			ID: u.ID, Name: u.Name, Email: u.Email, Role: oas.CoreGetCoreUsersOKItemsItemRole(u.Role), Twofa: u.TwofaMethod != "",
			Disabled: u.Disabled, CreatedAt: u.CreatedAt, LastLogin: nilTime(u.LastLogin), SSO: u.SSO,
			TwofaMethod: oas.NilCoreGetCoreUsersOKItemsItemTwofaMethod{Null: true},
		}
		if m, ok := methodOf(u); ok {
			it.TwofaMethod = oas.NewNilCoreGetCoreUsersOKItemsItemTwofaMethod(oas.CoreGetCoreUsersOKItemsItemTwofaMethod(m))
		}
		out.Items = append(out.Items, it)
	}
	return out, nil
}

// CorePostCoreUsers implements POST /core/users (admin): creates the account with a random temporary
// password that is returned once, in this response, and stored only as a hash.
func (h *APIHandlers) CorePostCoreUsers(ctx context.Context, req *oas.CorePostCoreUsersReq) (*oas.CorePostCoreUsersCreated, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	role := routes.Role(req.Role)
	if _, verr := auth.ValidateUserFields(name, req.Email, role); verr != nil {
		return nil, verr
	}
	temp, hash, err := h.auth.NewTempCredential(ctx)
	if err != nil {
		return nil, err
	}
	var u auth.User
	err = h.db.Write(ctx, func(tx *sql.Tx) (err error) {
		if err := h.auth.CheckAdmin(ctx, tx, c.ID, c.SessionID); err != nil {
			return err
		}
		u, err = h.auth.CreateUser(ctx, tx, c.Email, auth.NewUser{Name: name, Email: req.Email, Role: role, PasswordHash: hash, Temporary: true})
		return err
	})
	if err != nil {
		return nil, err
	}
	out := &oas.CorePostCoreUsersCreated{TempPassword: temp, User: oas.CorePostCoreUsersCreatedUser{
		ID: u.ID, Name: u.Name, Email: u.Email, Role: oas.CorePostCoreUsersCreatedUserRole(u.Role), Twofa: false, Disabled: false,
		CreatedAt: u.CreatedAt, LastLogin: oas.NilDateTime{Null: true}, TwofaMethod: oas.NilCorePostCoreUsersCreatedUserTwofaMethod{Null: true},
	}}
	return out, nil
}

// CorePatchCoreUsersID implements PATCH /core/users/{id} (admin): role and/or disabled (INV-7).
func (h *APIHandlers) CorePatchCoreUsersID(ctx context.Context, req *oas.CorePatchCoreUsersIDReq, params oas.CorePatchCoreUsersIDParams) (*oas.CorePatchCoreUsersIDOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	var p auth.UserPatch
	if r, ok := req.Role.Get(); ok {
		role := routes.Role(r)
		p.Role = &role
	}
	if d, ok := req.Disabled.Get(); ok {
		p.Disabled = &d
	}
	u, err := h.auth.UpdateUser(ctx, c.ID, c.Email, c.SessionID, params.ID, p)
	if err != nil {
		return nil, err
	}
	it := oas.CorePatchCoreUsersIDOKUser{
		ID: u.ID, Name: u.Name, Email: u.Email, Role: oas.CorePatchCoreUsersIDOKUserRole(u.Role), Twofa: u.TwofaMethod != "",
		Disabled: u.Disabled, CreatedAt: u.CreatedAt, LastLogin: nilTime(u.LastLogin), SSO: u.SSO,
		TwofaMethod: oas.NilCorePatchCoreUsersIDOKUserTwofaMethod{Null: true},
	}
	if m, ok := methodOf(u); ok {
		it.TwofaMethod = oas.NewNilCorePatchCoreUsersIDOKUserTwofaMethod(oas.CorePatchCoreUsersIDOKUserTwofaMethod(m))
	}
	return &oas.CorePatchCoreUsersIDOK{User: it}, nil
}

// CorePostCoreUsersIDResetPassword implements POST /core/users/{id}/reset-password (admin): a temporary
// password, returned once; every session of that user ends.
func (h *APIHandlers) CorePostCoreUsersIDResetPassword(ctx context.Context, params oas.CorePostCoreUsersIDResetPasswordParams) (*oas.CorePostCoreUsersIDResetPasswordOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	temp, err := h.auth.ResetPassword(ctx, c.ID, c.Email, c.SessionID, params.ID)
	if err != nil {
		return nil, err
	}
	return &oas.CorePostCoreUsersIDResetPasswordOK{TempPassword: temp}, nil
}

// CorePostCoreUsersID2FAReset implements POST /core/users/{id}/2fa/reset (admin): not for yourself.
func (h *APIHandlers) CorePostCoreUsersID2FAReset(ctx context.Context, params oas.CorePostCoreUsersID2FAResetParams) (*oas.CorePostCoreUsersID2FAResetOK, error) {
	c, err := h.caller(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.auth.ResetTwoFA(ctx, c.ID, c.Email, c.SessionID, params.ID); err != nil {
		return nil, err
	}
	return &oas.CorePostCoreUsersID2FAResetOK{Ok: true}, nil
}
