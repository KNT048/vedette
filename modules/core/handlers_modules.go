package core

import (
	"context"
	"database/sql"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/store"
)

// ModuleHandlers implements GET /modules and PATCH /modules/{id} (S-CORE-1). Embed it in the composite
// handler; it implements no other operation.
type ModuleHandlers struct {
	db  *store.DB
	reg *modreg.Registry
}

// NewModuleHandlers returns the handlers for the module list and switch.
func NewModuleHandlers(db *store.DB, reg *modreg.Registry) *ModuleHandlers {
	return &ModuleHandlers{db: db, reg: reg}
}

// CoreGetModules implements core_get_modules: the state of every module (viewer).
func (h *ModuleHandlers) CoreGetModules(context.Context) (*oas.CoreGetModulesOK, error) {
	states := h.reg.List()
	items := make([]oas.CoreGetModulesOKModulesItem, 0, len(states))
	for _, s := range states {
		it := oas.CoreGetModulesOKModulesItem{
			ID:        oas.CoreGetModulesOKModulesItemID(s.ID),
			Tier:      oas.CoreGetModulesOKModulesItemTier(s.Tier),
			Enabled:   s.Enabled,
			EnabledAt: nilTime(s.EnabledAt),
			Depends:   make([]oas.CoreGetModulesOKModulesItemDependsItem, 0, len(s.Depends)),
		}
		for _, d := range s.Depends {
			it.Depends = append(it.Depends, oas.CoreGetModulesOKModulesItemDependsItem(d))
		}
		items = append(items, it)
	}
	return &oas.CoreGetModulesOK{Modules: items}, nil
}

// CorePatchModulesID implements core_patch_modules_id (admin): turn a module on or off.
// The registry change and its core_audit row share one transaction; the in-memory state, and with it
// the routes and the jobs of the module, switches right after the commit, in this request (POST-2).
func (h *ModuleHandlers) CorePatchModulesID(ctx context.Context, req *oas.CorePatchModulesIDReq, params oas.CorePatchModulesIDParams) (*oas.CorePatchModulesIDOK, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.Unauthenticated()
	}
	var ch modreg.Change
	err := h.db.Write(ctx, func(tx *sql.Tx) error {
		var err error
		if req.Enabled {
			ch, err = h.reg.Enable(ctx, tx, p.Email, params.ID, req.WithDependencies.Or(false))
		} else {
			ch, err = h.reg.Disable(ctx, tx, p.Email, params.ID)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	h.reg.Publish(ch)

	states := h.reg.List()
	out := &oas.CorePatchModulesIDOK{
		Modules:  make([]oas.CorePatchModulesIDOKModulesItem, 0, len(states)),
		Affected: make([]oas.CorePatchModulesIDOKAffectedItem, 0, len(ch.Affected)),
	}
	for _, s := range states {
		it := oas.CorePatchModulesIDOKModulesItem{
			ID:        oas.CorePatchModulesIDOKModulesItemID(s.ID),
			Tier:      oas.CorePatchModulesIDOKModulesItemTier(s.Tier),
			Enabled:   s.Enabled,
			EnabledAt: nilTime(s.EnabledAt),
			Depends:   make([]oas.CorePatchModulesIDOKModulesItemDependsItem, 0, len(s.Depends)),
		}
		for _, d := range s.Depends {
			it.Depends = append(it.Depends, oas.CorePatchModulesIDOKModulesItemDependsItem(d))
		}
		out.Modules = append(out.Modules, it)
	}
	for _, a := range ch.Affected {
		out.Affected = append(out.Affected, oas.CorePatchModulesIDOKAffectedItem(a))
	}
	return out, nil
}

func nilTime(t *time.Time) oas.NilDateTime {
	if t == nil {
		return oas.NilDateTime{Null: true}
	}
	return oas.NewNilDateTime(*t)
}
