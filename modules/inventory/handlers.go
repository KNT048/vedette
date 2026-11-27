package inventory

import (
	"context"
	"errors"
	"strings"

	"github.com/knt048/vedette/core/api/apijson"
	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
)

// Handlers implements the 21 operations of the inventory module. Embed it in the composite handler of
// cmd/vedette. The role of each route comes from the route table, so nothing here checks roles.
//
// ogen generates a separate struct per operation for the same schema, so the answers are built from the
// domain types (their JSON names are the wire names) and decoded into the generated ones.
type Handlers struct{ svc *Service }

// NewHandlers returns the handlers of the module.
func NewHandlers(svc *Service) *Handlers { return &Handlers{svc: svc} }

// convert re-reads v, through its JSON form, as the generated type T.
func convert[T any](v any) (*T, error) { return apijson.Into[T](v) }

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

// InventoryGetInventoryDevices implements GET /inventory/devices (viewer): the devices the search keeps (#849).
func (h *Handlers) InventoryGetInventoryDevices(ctx context.Context, p oas.InventoryGetInventoryDevicesParams) (*oas.InventoryGetInventoryDevicesOK, error) {
	f, err := ParseDeviceSearch(string(p.Approved.Value), string(p.Fragile.Value), string(p.HasFindings.Value), string(p.Ignored.Value), p.Type.Value, p.Source.Value, p.Risk.Value, p.Q.Value)
	if err != nil {
		return nil, err
	}
	if f.Software, err = SoftwareWords(p.Software.Value); err != nil {
		return nil, err
	}
	l, err := h.svc.DevicesPage(ctx, f)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryGetInventoryDevicesOK](listPage(l, f.Software))
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
	if v, ok := req.Name.Get(); ok {
		p.Name = &v
	}
	if v, ok := req.Os.Get(); ok {
		p.OS = &v
	}
	if err := h.svc.PatchDevice(ctx, who, params.ID, p); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPatchInventoryDevicesIDOK{Ok: true}, nil
}

// InventoryGetInventoryDevicesIDSources implements GET /inventory/devices/{id}/sources (viewer): the device's three source rows.
func (h *Handlers) InventoryGetInventoryDevicesIDSources(ctx context.Context, params oas.InventoryGetInventoryDevicesIDSourcesParams) (*oas.InventoryGetInventoryDevicesIDSourcesOK, error) {
	v, err := h.svc.DeviceSources(ctx, params.ID)
	if err != nil {
		return nil, fail(err)
	}
	// The token Show setup shows is an administrator's (the tokens list is admin only): the others get the row's state and button only.
	if p, ok := server.PrincipalFrom(ctx); !ok || p.Role != routes.Admin {
		for i := range v.Rows {
			v.Rows[i].Token = nil
		}
	}
	return convert[oas.InventoryGetInventoryDevicesIDSourcesOK](v)
}

// InventoryPostInventoryBoxCheck implements POST /inventory/box/check (operator): the box's own agent reads its packages and ports now.
func (h *Handlers) InventoryPostInventoryBoxCheck(ctx context.Context) (*oas.InventoryPostInventoryBoxCheckOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.svc.CheckBox(ctx, who)
	if err != nil {
		return nil, fail(err)
	}
	if p, ok := server.PrincipalFrom(ctx); !ok || p.Role != routes.Admin { // as GET .../sources: the tokens are an administrator's
		for i := range v.Rows {
			v.Rows[i].Token = nil
		}
	}
	return convert[oas.InventoryPostInventoryBoxCheckOK](v)
}

// InventoryPutInventoryDevicesIDSources implements PUT /inventory/devices/{id}/sources (admin).
func (h *Handlers) InventoryPutInventoryDevicesIDSources(ctx context.Context, req *oas.InventoryPutInventoryDevicesIDSourcesReq, params oas.InventoryPutInventoryDevicesIDSourcesParams) (*oas.InventoryPutInventoryDevicesIDSourcesOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var ch SourcesChange
	if v, ok := req.Scan.Get(); ok {
		ch.Scan = ptrTo(string(v))
	}
	if v, ok := req.Snmp.Get(); ok {
		ch.SNMP = ptrTo(string(v))
	}
	if v, ok := req.Agent.Get(); ok {
		ch.Agent = ptrTo(string(v))
	}
	r, err := h.svc.ChangeSources(ctx, who, params.ID, ch)
	if err != nil {
		return nil, fail(err)
	}
	return convert[oas.InventoryPutInventoryDevicesIDSourcesOK](r)
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

// InventoryGetInventoryPossibleSame implements GET /inventory/possible-same (viewer).
func (h *Handlers) InventoryGetInventoryPossibleSame(ctx context.Context) (*oas.InventoryGetInventoryPossibleSameOK, error) {
	l, err := h.svc.PossibleSamePairs(ctx)
	if err != nil {
		return nil, err
	}
	return convert[oas.InventoryGetInventoryPossibleSameOK](l)
}

// InventoryPostInventoryDevicesIDMerge implements POST /inventory/devices/{id}/merge (admin): every device of body.from goes into id.
func (h *Handlers) InventoryPostInventoryDevicesIDMerge(ctx context.Context, req *oas.InventoryPostInventoryDevicesIDMergeReq, params oas.InventoryPostInventoryDevicesIDMergeParams) (*oas.InventoryPostInventoryDevicesIDMergeOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	var choice MergeChoice
	if f, ok := req.Fields.Get(); ok {
		if v, ok := f.Name.Get(); ok {
			choice.Name = &v
		}
		if v, ok := f.Kind.Get(); ok {
			k := string(v)
			choice.Kind = &k
		}
		if v, ok := f.Os.Get(); ok {
			choice.OS = &v
		}
	}
	if err := h.svc.MergeMany(ctx, who, params.ID, req.From, choice); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDMergeOK{ID: params.ID}, nil
}

// InventoryGetInventoryDevicesIDMergePreview implements GET /inventory/devices/{id}/merge-preview (admin).
func (h *Handlers) InventoryGetInventoryDevicesIDMergePreview(ctx context.Context, params oas.InventoryGetInventoryDevicesIDMergePreviewParams) (*oas.InventoryGetInventoryDevicesIDMergePreviewOK, error) {
	var from []string
	for _, f := range strings.Split(params.From, ",") {
		if f = strings.TrimSpace(f); f != "" {
			from = append(from, f)
		}
	}
	p, err := h.svc.MergePreview(ctx, params.ID, from)
	if err != nil {
		return nil, fail(err)
	}
	return convert[oas.InventoryGetInventoryDevicesIDMergePreviewOK](p)
}

// InventoryPostInventoryDevicesIDSplit implements POST /inventory/devices/{id}/split (admin): the address becomes a device of its own.
func (h *Handlers) InventoryPostInventoryDevicesIDSplit(ctx context.Context, req *oas.InventoryPostInventoryDevicesIDSplitReq, params oas.InventoryPostInventoryDevicesIDSplitParams) (*oas.InventoryPostInventoryDevicesIDSplitOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	id, err := h.svc.Split(ctx, who, params.ID, req.Address)
	if err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDSplitOK{ID: id}, nil
}

// InventoryPostInventoryDevicesIDKeepSeparate implements POST /inventory/devices/{id}/keep-separate (admin).
func (h *Handlers) InventoryPostInventoryDevicesIDKeepSeparate(ctx context.Context, req *oas.InventoryPostInventoryDevicesIDKeepSeparateReq, params oas.InventoryPostInventoryDevicesIDKeepSeparateParams) (*oas.InventoryPostInventoryDevicesIDKeepSeparateOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.KeepSeparate(ctx, who, params.ID, req.Other); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDKeepSeparateOK{Ok: true}, nil
}

// InventoryPostInventoryDevicesIDIgnore implements POST /inventory/devices/{id}/ignore (operator).
func (h *Handlers) InventoryPostInventoryDevicesIDIgnore(ctx context.Context, req *oas.InventoryPostInventoryDevicesIDIgnoreReq, params oas.InventoryPostInventoryDevicesIDIgnoreParams) (*oas.InventoryPostInventoryDevicesIDIgnoreOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.SetIgnored(ctx, who, params.ID, req.Ignored); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDIgnoreOK{Ok: true}, nil
}

// InventoryPostInventoryDevicesIDDiffersFieldUse implements POST /inventory/devices/{id}/differs/{field}/use (operator).
func (h *Handlers) InventoryPostInventoryDevicesIDDiffersFieldUse(ctx context.Context, req *oas.InventoryPostInventoryDevicesIDDiffersFieldUseReq, params oas.InventoryPostInventoryDevicesIDDiffersFieldUseParams) (*oas.InventoryPostInventoryDevicesIDDiffersFieldUseOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.UseDetected(ctx, who, params.ID, string(params.Field), req.Detected); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDDiffersFieldUseOK{Ok: true}, nil
}

// InventoryPostInventoryDevicesIDDiffersFieldKeep implements POST /inventory/devices/{id}/differs/{field}/keep (operator).
func (h *Handlers) InventoryPostInventoryDevicesIDDiffersFieldKeep(ctx context.Context, req *oas.InventoryPostInventoryDevicesIDDiffersFieldKeepReq, params oas.InventoryPostInventoryDevicesIDDiffersFieldKeepParams) (*oas.InventoryPostInventoryDevicesIDDiffersFieldKeepOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.svc.KeepEntered(ctx, who, params.ID, string(params.Field), req.Detected); err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPostInventoryDevicesIDDiffersFieldKeepOK{Ok: true}, nil
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

// InventoryPatchInventoryDevicesIDSoftwareSid implements PATCH /inventory/devices/{id}/software/{sid} (operator, INV-41).
func (h *Handlers) InventoryPatchInventoryDevicesIDSoftwareSid(ctx context.Context, req *oas.InventoryPatchInventoryDevicesIDSoftwareSidReq, params oas.InventoryPatchInventoryDevicesIDSoftwareSidParams) (*oas.InventoryPatchInventoryDevicesIDSoftwareSidOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	e := SoftwareEdit{CatalogID: req.CatalogID.Or(""), Vendor: req.Vendor.Or(""), Product: req.Product.Or(""), NotInstalled: req.NotInstalled.Or(false),
		Confirm: req.Confirm.Or(false)}
	if v, ok := req.Version.Get(); ok {
		e.Version = &v
	}
	if v, ok := req.PkgVersion.Get(); ok {
		e.PkgVersion = &v
	}
	changed, err := h.svc.Edit(ctx, who, params.ID, params.Sid, e)
	if err != nil {
		return nil, fail(err)
	}
	return &oas.InventoryPatchInventoryDevicesIDSoftwareSidOK{Ok: true, Changed: changed}, nil
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

// InventoryGetInventoryExportCsv implements GET /inventory/export.csv (viewer): the devices the search keeps, as the page shows them.
func (h *Handlers) InventoryGetInventoryExportCsv(ctx context.Context, p oas.InventoryGetInventoryExportCsvParams) (oas.InventoryGetInventoryExportCsvOK, error) {
	who, err := actor(ctx)
	if err != nil {
		return oas.InventoryGetInventoryExportCsvOK{}, err
	}
	f, err := ParseDeviceSearch(string(p.Approved.Value), string(p.Fragile.Value), string(p.HasFindings.Value), string(p.Ignored.Value), p.Type.Value, p.Source.Value, p.Risk.Value, p.Q.Value)
	if err != nil {
		return oas.InventoryGetInventoryExportCsvOK{}, err
	}
	if f.Software, err = SoftwareWords(p.Software.Value); err != nil {
		return oas.InventoryGetInventoryExportCsvOK{}, err
	}
	r, err := h.svc.ExportCSV(ctx, who, f)
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

// csvDownload makes the response a CSV file download (API_CONVENTIONS §11): the generated file encoder says octet-stream and
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
	st.Active.CheckRate = 0 // not part of this contract: /scanning/safety and /scans/config carry it (INV-32)
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
	in.Active.CheckRate = 0 // not part of this contract: the stored values stay (INV-32)
	st, err := h.svc.SaveSettings(ctx, who, *in)
	if err != nil {
		return nil, err
	}
	st.Active.CheckRate = 0
	return convert[oas.InventoryPutInventorySettingsOK](st)
}
