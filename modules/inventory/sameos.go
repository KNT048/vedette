package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/productid"
)

// A device a person added by hand with no address at all ("esxi-01", VMware ESXi 8.0.3 build 24022510) is often a machine the scan
// finds too: nothing on the wire ties the two rows, so they stay two devices and every finding of the machine is counted twice. The
// operating system or firmware a machine runs, at the same release, is what both rows state: when a hand-added row without an
// address and a found device run the same OS product at the same version or build, the pair is offered as possibly one machine
// (ReasonSameOS). A person decides; the join rules never take such a pair.

// machineProducts are the products that are a whole machine's OS or firmware: the catalog's OS products (osProducts) and every
// curated product it names with an OS CPE (o:vmware:esxi).
var machineProducts = func() map[string]bool {
	out := map[string]bool{}
	for k := range osProducts {
		out[k] = true
	}
	var curated []struct {
		Vendor, Product string
		CPE             []string `json:"cpe"`
	}
	if err := json.Unmarshal(catalogdata.Curated, &curated); err != nil {
		panic(fmt.Sprintf("inventory: curated.json: %v", err)) // embedded data, read by NewCatalog's tests too
	}
	for _, r := range curated {
		if slices.ContainsFunc(r.CPE, func(c string) bool { return strings.HasPrefix(c, "o:") }) {
			out[productid.Key(r.Vendor, r.Product)] = true
		}
	}
	return out
}()

// buildRE finds a build number in a version or a name: "8.0.3 build 24022510", "VMware ESXi 8.0 Update 3 (build 24022510)".
var buildRE = regexp.MustCompile(`(?i)\bbuild[\s:#-]*([0-9]{5,})\b`)

// osCPE says whether a CPE names an operating system or firmware (part o).
func osCPE(cpe string) bool {
	return strings.HasPrefix(cpe, "cpe:2.3:o:") || strings.HasPrefix(cpe, "cpe:/o:")
}

// machineKeys are the keys a software line gives the same-OS signal: its product with its build number and with its version, so a
// hand-typed "8.0.3 build 24022510" meets a banner's "8.0" named "(build 24022510)", and "8.0 U3" meets "8.0 U3". None for a line
// of a product that is not a machine's OS or firmware, or that names no release.
func machineKeys(productKey, version, display, cpe string) []string {
	if !machineProducts[productKey] && !osCPE(cpe) {
		return nil
	}
	var out []string
	if m := buildRE.FindStringSubmatch(version + " " + display); m != nil {
		out = append(out, productKey+"#build "+m[1])
	}
	if v := strings.Join(strings.Fields(strings.ToLower(version)), " "); v != "" {
		out = append(out, productKey+"#"+v)
	}
	return out
}

// osLines reads the machine keys of the devices' present software lines (every device when ids is nil), with the line's name for
// the reason: an nmap OS fingerprint guess is no statement and gives none.
func osLines(ctx context.Context, q querier, ids []string) (map[string]map[string]string, error) {
	where, args := "", []any{}
	if ids != nil {
		where = " AND s.asset_id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
		for _, id := range ids {
			args = append(args, id)
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT s.asset_id, s.product_key, ifnull(s.version, ''), s.display, ifnull(s.cpe, '') FROM inv_software s
		WHERE s.state = 'present' AND NOT `+guessLine+where, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read software: %w", err)
	}
	out := map[string]map[string]string{}
	for rows.Next() {
		var id, key, version, display, cpe string
		if err := rows.Scan(&id, &key, &version, &display, &cpe); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read software: %w", err)
		}
		for _, k := range machineKeys(key, version, display, cpe) {
			if out[id] == nil {
				out[id] = map[string]string{}
			}
			if out[id][k] == "" {
				out[id][k] = strings.TrimSpace(display + " " + versionNotIn(version, display))
			}
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read software: %w", err)
	}
	return out, nil
}

// versionNotIn is version unless the name already says it, in those words or by its build number ("VMware ESXi 8.0 Update 3 (build
// 24022510)" filed under 8.0.3).
func versionNotIn(version, display string) string {
	if version == "" || strings.Contains(strings.ToLower(display), strings.ToLower(version)) || buildRE.MatchString(display) {
		return ""
	}
	return version
}

// addressless reports a row a person added by hand that has no address of any kind: no IP, no MAC, no agent, no MAC seen at it.
func (r *sameRow) addressless() bool {
	return r.origin == "manual" && r.ip == "" && len(r.burned) == 0 && len(r.private) == 0 && len(r.atAddr) == 0 && r.agent == ""
}

// osWhy is the reason to offer x and y as one machine because they run the same OS at the same release: one is a hand-added row
// with no address, the other a device found on the network. Never when two agents report from them or they state another model or
// OS; the person's name for the hand-added row is a label, not the machine's own name, so it is not held against the pair.
func osWhy(ctx context.Context, tx *sql.Tx, x, y *sameRow, key string) (string, error) {
	if y.addressless() {
		x, y = y, x
	}
	if !x.addressless() || y.addressless() || y.origin == "manual" {
		return "", nil
	}
	fx, err := facts(ctx, tx, x.id)
	if err != nil {
		return "", err
	}
	fy, err := facts(ctx, tx, y.id)
	if err != nil {
		return "", err
	}
	delete(fx, "hostname")
	delete(fy, "hostname")
	if differ(fx, fy) {
		return "", nil
	}
	what := y.osNames[key]
	if what == "" {
		what = x.osNames[key]
	}
	return "Both run " + what + ", and " + deviceName(ctx, tx, x.id) + " was added by hand without an address: it may be this device.", nil
}
