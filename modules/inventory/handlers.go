package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// Handlers implements the 17 operations of the inventory module. Embed it in the composite handler of
// cmd/vedette. The role of each route comes from the route table, so nothing here checks roles.
//
// ogen generates a separate struct per operation for the same schema, so the answers are built from the
// domain types (their JSON names are the wire names) and decoded into the generated ones.
type Handlers struct{ svc *Service }

// NewHandlers returns the handlers of the module.
func NewHandlers(svc *Service) *Handlers { return &Handlers{svc: svc} }

// convert re-reads v, through its JSON form, as the generated type T.
func convert[T any](v any) (*T, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("inventory: encode response: %w", err)
	}
	out := new(T)
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("inventory: build response: %w", err)
	}
	return out, nil
}

// actor is the signed-in user's email; the route table guarantees a principal on these routes.
func actor(ctx context.Context) (string, error) {
	p, ok := server.PrincipalFrom(ctx)
	if !ok {
		return "", apierr.Unauthenticated()
	}
	return p.Email, nil
}

// fail turns the service's ErrNotFound into the API answer.
func fail(err error) error {
	if errors.Is(err, ErrNotFound) {
		return notFoundDevice()
	}
	return err
}

// InventoryGetInventoryDevices implements GET /inventory/devices (viewer).
func (h *Handlers) InventoryGetInventoryDevices(ctx context.Context) (*oas.InventoryGetInventoryDevicesOK, error) {
	l, err := h.svc.DevicesPage(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryGetInventoryDevicesOK](l)
}

// InventoryGetInventoryDevicesID implements GET /inventory/devices/{id} (viewer).
func (h *Handlers) InventoryGetInventoryDevicesID(ctx context.Context, params oas.InventoryGetInventoryDevicesIDParams) (*oas.InventoryGetInventoryDevicesIDOK, error) {
	d, err := h.svc.DetailPage(ctx, params.ID)
	if err != nil {
		return nil, fail(err)
	}
	return convert[oas.InventoryGetInventoryDevicesIDOK](d)
}

// InventoryGetInventoryCatalog implements GET /inventory/catalog (viewer).
func (h *Handlers) InventoryGetInventoryCatalog(ctx context.Context, params oas.InventoryGetInventoryCatalogParams) (*oas.InventoryGetInventoryCatalogOK, error) {
	r, err := h.svc.SearchCatalog(ctx, params.Q)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryGetInventoryCatalogOK](r)
}

// InventoryPostInventoryDevices implements POST /inventory/devices (operator).
func (h *Handlers) InventoryPostInventoryDevices(ctx context.Context, req *oas.InventoryPostInventoryDevicesReq) (*oas.InventoryPostInventoryDevicesCreated, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.AddDevice(ctx, who, AddInput{
		CatalogID: req.CatalogID.Or(""), Vendor: req.Vendor.Or(""), Product: req.Product.Or(""), Version: req.Version.Or(""), Name: req.Name.Or(""), IP: req.IP.Or(""),
	})
	if err != nil {
		return nil, err
	}
	return &oas.InventoryPostInventoryDevicesCreated{ID: r.ID, Display: r.Display, KevCves: r.KevCVEs}, nil
}

// InventoryPatchInventoryDevicesID implements PATCH /inventory/devices/{id} (operator).
func (h *Handlers) InventoryPatchInventoryDevicesID(ctx context.Context, req *oas.InventoryPatchInventoryDevicesIDReq, params oas.InventoryPatchInventoryDevicesIDParams) (*oas.InventoryPatchInventoryDevicesIDOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var p Patch
	if v, ok := req.Kind.Get(); ok {
		k := string(v)
		p.Kind = &k
	}
	if v, ok := req.Fragile.Get(); ok {
		p.Fragile = &v
	}
	if v, ok := req.RegularScan.Get(); ok {
		r := string(v)
		p.RegularScan = &r
	}
	if v, ok := req.Notes.Get(); ok {
		p.Notes = &v
	}
	if err := h.svc.PatchDevice(ctx, who, params.ID, p); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPatchInventoryDevicesIDOK{Ok: true}, nil
}

// InventoryDeleteInventoryDevicesID implements DELETE /inventory/devices/{id} (operator).
func (h *Handlers) InventoryDeleteInventoryDevicesID(ctx context.Context, params oas.InventoryDeleteInventoryDevicesIDParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return fail(h.svc.DeleteDevice(ctx, who, params.ID))
}

// InventoryPostInventoryDevicesIDApprove implements POST /inventory/devices/{id}/approve (operator).
func (h *Handlers) InventoryPostInventoryDevicesIDApprove(ctx context.Context, params oas.InventoryPostInventoryDevicesIDApproveParams) (*oas.InventoryPostInventoryDevicesIDApproveOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.Approve(ctx, who, params.ID); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDApproveOK{Ok: true}, nil
}

// InventoryPostInventoryDevicesIDSuspicious implements POST /inventory/devices/{id}/suspicious (operator).
func (h *Handlers) InventoryPostInventoryDevicesIDSuspicious(ctx context.Context, req *oas.InventoryPostInventoryDevicesIDSuspiciousReq, params oas.InventoryPostInventoryDevicesIDSuspiciousParams) (*oas.InventoryPostInventoryDevicesIDSuspiciousOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.SetSuspicious(ctx, who, params.ID, req.Suspicious); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDSuspiciousOK{Ok: true}, nil
}

// InventoryPostInventoryDevicesIDSoftware implements POST /inventory/devices/{id}/software (operator).
func (h *Handlers) InventoryPostInventoryDevicesIDSoftware(ctx context.Context, req *oas.InventoryPostInventoryDevicesIDSoftwareReq, params oas.InventoryPostInventoryDevicesIDSoftwareParams) (*oas.InventoryPostInventoryDevicesIDSoftwareCreated, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	n, err := h.svc.AddSoftware(ctx, who, params.ID, AddInput{CatalogID: req.CatalogID.Or(""), Vendor: req.Vendor.Or(""), Product: req.Product.Or(""), Version: req.Version.Or("")})
	if err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDSoftwareCreated{KevCves: n}, nil
}

// InventoryPatchInventoryDevicesIDSoftwareSid implements PATCH /inventory/devices/{id}/software/{sid} (operator, D-471).
func (h *Handlers) InventoryPatchInventoryDevicesIDSoftwareSid(ctx context.Context, req *oas.InventoryPatchInventoryDevicesIDSoftwareSidReq, params oas.InventoryPatchInventoryDevicesIDSoftwareSidParams) (*oas.InventoryPatchInventoryDevicesIDSoftwareSidOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.SetSoftwareVersion(ctx, who, params.ID, params.Sid, req.Version); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPatchInventoryDevicesIDSoftwareSidOK{Ok: true}, nil
}

// InventoryDeleteInventoryDevicesIDSoftwareSid implements DELETE /inventory/devices/{id}/software/{sid} (operator).
func (h *Handlers) InventoryDeleteInventoryDevicesIDSoftwareSid(ctx context.Context, params oas.InventoryDeleteInventoryDevicesIDSoftwareSidParams) error {
	who, err := actor(ctx)
	if err != nil {
		return err
	}
	return fail(h.svc.RemoveSoftware(ctx, who, params.ID, params.Sid))
}

// InventoryPutInventoryNotifyNew implements PUT /inventory/notify-new (operator).
func (h *Handlers) InventoryPutInventoryNotifyNew(ctx context.Context, req *oas.InventoryPutInventoryNotifyNewReq) (*oas.InventoryPutInventoryNotifyNewOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.SetNotifyNew(ctx, who, req.Enabled); err != nil {
		return nil, err
	}
	return &oas.InventoryPutInventoryNotifyNewOK{Enabled: req.Enabled}, nil
}

// InventoryGetInventoryExportCsv implements GET /inventory/export.csv (viewer).
func (h *Handlers) InventoryGetInventoryExportCsv(ctx context.Context) (oas.InventoryGetInventoryExportCsvOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return oas.InventoryGetInventoryExportCsvOK{}, err
	}
	r, err := h.svc.ExportCSV(ctx, who)
	if err != nil {
		return oas.InventoryGetInventoryExportCsvOK{}, err
	}
	csvDownload(ctx, "vedette-devices-"+h.svc.clock().UTC().Format("20060102")+".csv")
	return oas.InventoryGetInventoryExportCsvOK{Data: r}, nil
}

// InventoryGetInventoryImportTemplateCsv implements GET /inventory/import-template.csv (viewer).
func (h *Handlers) InventoryGetInventoryImportTemplateCsv(ctx context.Context) (oas.InventoryGetInventoryImportTemplateCsvOK, error) {
	csvDownload(ctx, "vedette-devices-template.csv")
	return oas.InventoryGetInventoryImportTemplateCsvOK{Data: ImportTemplate()}, nil
}

// csvDownload makes the response a CSV file download (API_CONVENTIONS §7, §11): the generated file encoder says octet-stream and
// names no file. Called only on success.
func csvDownload(ctx context.Context, name string) {
	if x, ok := server.ExchangeFrom(ctx); ok {
		hd := x.W.Header()
		hd.Set("Content-Disposition", `attachment; filename="`+name+`"`)
		hd.Set("Cache-Control", "no-store")
		x.SetContentType("text/csv; charset=utf-8")
	}
}

// InventoryPostInventoryImport implements POST /inventory/import (operator).
func (h *Handlers) InventoryPostInventoryImport(ctx context.Context, req *oas.InventoryPostInventoryImportReq) (*oas.InventoryPostInventoryImportOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.svc.Import(ctx, who, req.Filename, req.Text)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryPostInventoryImportOK](r)
}

// InventoryGetInventorySettings implements GET /inventory/settings (admin).
func (h *Handlers) InventoryGetInventorySettings(ctx context.Context) (*oas.InventoryGetInventorySettingsOK, error) {
	st, err := h.svc.Settings(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryGetInventorySettingsOK](st)
}

// InventoryPutInventorySettings implements PUT /inventory/settings (admin).
func (h *Handlers) InventoryPutInventorySettings(ctx context.Context, req *oas.InventoryPutInventorySettingsReq) (*oas.InventoryPutInventorySettingsOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	in, err := convert[SettingsInput](req)
	if err != nil {
		return nil, apierr.Invalid("The settings are not valid.")
	}
	st, err := h.svc.SaveSettings(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryPutInventorySettingsOK](st)
}
