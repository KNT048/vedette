package main

import (
	"context"
	"errors"
	"strings"

	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// auditNamer is core.AuditNamer over inventory and findings (D-416): Settings → Audit log shows a device or finding by name, its id
// below. It reads the services lazily from deps: core is built before them.
type auditNamer struct{ d *deps }

// AuditNames names the device (a-…) and finding (f-…) ids it knows; others are left out. A device is its host name, else its IP, else
// what the box knows of it (inventory's display); a finding is "<CVE> on <device>", or the CVE when the device is gone.
func (n auditNamer) AuditNames(ctx context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	var assetIDs []string
	found := map[string]findings.Record{}
	for _, id := range ids {
		switch {
		case strings.HasPrefix(id, "a-"):
			assetIDs = append(assetIDs, id)
		case strings.HasPrefix(id, "f-") && n.d.Findings != nil:
			r, err := n.d.Findings.Get(ctx, id)
			if errors.Is(err, findings.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			found[id] = r
			assetIDs = append(assetIDs, r.AssetID)
		}
	}
	refs := map[string]inventory.DeviceRef{}
	if n.d.Inventory != nil && len(assetIDs) > 0 {
		var err error
		if refs, err = n.d.Inventory.DeviceRefs(ctx, assetIDs); err != nil {
			return nil, err
		}
	}
	for id, ref := range refs {
		out[id] = deviceName(ref)
	}
	for id, r := range found {
		if ref, ok := refs[r.AssetID]; ok {
			out[id] = r.CVE + " on " + deviceName(ref)
		} else {
			out[id] = r.CVE
		}
	}
	return out, nil
}

func deviceName(r inventory.DeviceRef) string {
	switch {
	case r.Hostname != nil && *r.Hostname != "":
		return *r.Hostname
	case r.IP != "" && r.IP != "—":
		return r.IP
	}
	return r.Display
}
