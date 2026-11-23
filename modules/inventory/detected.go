package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
)

// A value a person entered always wins (INV-1). When a trusted source reads something else, the device page says so and the person
// chooses: use what was detected, or keep their own (INV-47).

// detectedFields are the fields a person can enter that a source can read too, in the order the page lists them.
var detectedFields = []string{"hostname", "vendor", "model", "os", "kind"}

// Differs is a field where what a person entered and what a trusted source reads are two different things (contract.ts
// DetectedDiffers). The person's value is the one shown everywhere.
type Differs struct {
	Field    string `json:"field"`
	Entered  string `json:"entered"`
	Detected string `json:"detected"`
	// Source is where the detected value comes from: agent, snmp, or passive (a device's own LLDP statement, Basis "stated").
	Source string `json:"source"`
	Basis  string `json:"basis,omitempty"`
	SeenAt string `json:"seen_at"`
}

// trustedRead says whether an observation is a device's own word, not a guess or a hint: an agent installed on it, an SNMP
// read with the person's settings, or a statement the device makes about itself (an LLDP description its own card vouches
// for, an NTLM answer). A scan's fingerprint and a passive hint never count. stated is the observation's LLDP mark (markStated).
func trustedRead(o obs, frameOS map[string]string, mac string) bool {
	switch o.source {
	case "agent", "snmp":
		return true
	case "nmap":
		return o.field == "os" && ntlmAnswer(o.value)
	case "passive":
		switch o.field {
		case "os":
			return o.stated
		case "model":
			return modelBasis(o.source, frameOS[o.seenAt], mac) != ""
		}
	}
	return false
}

// differences lists, for one device's observations (list: every kind, hostname, vendor, model, os and mac row), the fields where
// the person's value and the best trusted reading differ; kept names the (field, detected value) pairs a person chose to keep.
func differences(list []obs, kept map[[2]string]bool) []Differs {
	markStated(list)
	mac := ""
	var best obs
	for _, o := range list {
		if o.field == "mac" && (best.id == "" || better(o, best)) {
			best, mac = o, o.value
		}
	}
	frameOS := map[string]string{}
	for _, o := range list {
		if o.field == "os" && o.source == "passive" {
			frameOS[o.seenAt] = o.value
		}
	}
	var makers []string
	for _, o := range list {
		if o.field == "vendor" {
			makers = append(makers, makerWords(o.value))
		}
	}
	var out []Differs
	for _, field := range detectedFields {
		var entered *obs
		var rest []obs // everything but the person's value of this field: what the page shows after Use detected
		for i := range list {
			o := list[i]
			if o.field == field && o.source == "manual" {
				if entered == nil || better(o, *entered) {
					entered = &list[i]
				}
				continue
			}
			rest = append(rest, o)
		}
		if entered == nil {
			continue
		}
		best := winners(rest)
		dropContradictedOS(rest, best)
		w, ok := best[field]
		// The notice names the value the page will show after Use detected: that winner must be a trusted reading.
		if !ok || !trustedRead(w, frameOS, mac) || sameValue(field, entered.value, w.value, makers) || kept[[2]string{field, w.value}] {
			continue
		}
		d := Differs{Field: field, Entered: entered.value, Detected: w.value, Source: w.source, SeenAt: w.seenAt}
		if w.stated || (field == "model" && w.source == "passive") {
			d.Basis = basisStated
		}
		out = append(out, d)
	}
	return out
}

// sameValue says the two texts name the same thing, so there is nothing to tell the person: the same after trimming and case, a
// host name with or without its domain, a maker with or without "Inc." and the like, a model with or without the maker in front
// or a space where the other has a dash, an OS where one only adds a version after the other's name.
func sameValue(field, a, b string, makers []string) bool {
	switch field {
	case "hostname":
		a, b = strings.Trim(strings.ToLower(strings.TrimSpace(a)), "."), strings.Trim(strings.ToLower(strings.TrimSpace(b)), ".")
		return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".") || uuidName.MatchString(b)
	case "vendor":
		return makerWords(a) == makerWords(b)
	case "model":
		x, y := fold(a), fold(b)
		for _, m := range makers {
			x, y = strings.TrimPrefix(x, m+" "), strings.TrimPrefix(y, m+" ")
		}
		return strings.ReplaceAll(x, " ", "") == strings.ReplaceAll(y, " ", "")
	case "os":
		return !osDiffers(a, b)
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// osDiffers says the person should be asked about two OS texts here. Not when they are the same, when one only adds a version to the
// other ("Alpine Linux" and "Alpine Linux 3.23": a versioned reading already wins, INV-45), or when they plainly disagree: a
// person's OS that the sources contradict already has its own "You set X; the scan reads Y" block (INV-41, osCorrection). What is
// left is a detected name that extends the entered one without being a version ("Windows" and "Windows Server 2022").
func osDiffers(entered, detected string) bool {
	x := fold(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(entered)), "microsoft "))
	y := fold(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(detected)), "microsoft "))
	if x == y || !sameOS(x, y) || strings.HasPrefix(x, y+" ") {
		return false
	}
	return !versionLike(strings.Fields(strings.TrimPrefix(y, x+" "))[0])
}

// versionLike says a word is a version or a build: it starts with a digit, with "v" and a digit, or is "build".
func versionLike(w string) bool {
	return w == "build" || (w != "" && (w[0] >= '0' && w[0] <= '9' || len(w) > 1 && w[0] == 'v' && w[1] >= '0' && w[1] <= '9'))
}

// makerSuffixes are the words that follow a maker's name without naming it: legal forms and generic words. "Fortinet, Inc." is
// "Fortinet"; "Juniper Networks" is "Juniper". Words in the middle stay ("Hewlett Packard Enterprise" is not "Hewlett Packard").
var makerSuffixes = []string{"inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc", "gmbh", "sa", "ag", "plc", "bv", "pte",
	"networks", "network", "technologies", "technology", "systems", "communications"}

// makerWords is a maker folded, with the trailing suffix words dropped (always keeping the first word).
func makerWords(s string) string {
	w := strings.Fields(fold(s))
	for len(w) > 1 && slices.Contains(makerSuffixes, w[len(w)-1]) {
		w = w[:len(w)-1]
	}
	return strings.Join(w, " ")
}

// keptSet reads the (field, detected value) pairs a person kept on the device.
func keptSet(ctx context.Context, q querier, id string) (map[[2]string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT field, detected FROM inv_detected_keep WHERE asset_id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("inventory: read kept values: %w", err)
	}
	defer func() { _ = rows.Close() }()
	kept := map[[2]string]bool{}
	for rows.Next() {
		var f, v string
		if err := rows.Scan(&f, &v); err != nil {
			return nil, fmt.Errorf("inventory: read kept values: %w", err)
		}
		kept[[2]string{f, v}] = true
	}
	return kept, rows.Err()
}

// deviceDifferences reads the device's observations and says where a trusted reading differs from a person's value.
func deviceDifferences(ctx context.Context, q querier, id string) ([]Differs, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, field, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ?
		AND NOT (field = 'mac' AND evidence IS ?) AND source <> 'declared'`, id, chassisEvidence)
	if err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []obs
	for rows.Next() {
		var o obs
		if err := rows.Scan(&o.id, &o.field, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			return nil, fmt.Errorf("inventory: read observations: %w", err)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read observations: %w", err)
	}
	kept, err := keptSet(ctx, q, id)
	if err != nil {
		return nil, err
	}
	return differences(list, kept), nil
}

func detectedGone() error {
	return conflict("detected_changed", "The detected value is no longer different from yours, or it changed. Reload the page to see what the device reads now.")
}

// findDiffers returns the difference of field when it is still the one named by detected (what the person saw), else a 409.
func (s *Service) findDiffers(ctx context.Context, q querier, id, field, detected string) (Differs, error) {
	if !slices.Contains(detectedFields, field) {
		return Differs{}, badRequest("bad_field", "The field is one of hostname, vendor, model, os or kind.")
	}
	list, err := deviceDifferences(ctx, q, id)
	if err != nil {
		return Differs{}, err
	}
	for _, d := range list {
		if d.Field == field && d.Detected == detected {
			return d, nil
		}
	}
	return Differs{}, detectedGone()
}

// UseDetected drops the person's value of a field so the sources' reading wins (INV-47): the device page then shows the detected
// value. detected is the value the person saw; when the sources read another one meanwhile it is 409 detected_changed and nothing
// changes. Audited with the person.
func (s *Service) UseDetected(ctx context.Context, actor, id, field, detected string) error {
	if err := s.requireDevice(ctx, id); err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		d, err := s.findDiffers(ctx, tx, id, field, detected)
		if err != nil {
			return err
		}
		name := deviceName(ctx, tx, id)
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = ? AND source = 'manual'`, id, field); err != nil {
			return fmt.Errorf("inventory: drop the entered value: %w", err)
		}
		if _, err := s.RecomputeAsset(ctx, tx, id); err != nil {
			return err
		}
		if err := s.auditTx(ctx, tx, actor, "inventory.use_detected", name, fieldLabel(field)+": "+d.Entered+" → "+d.Detected); err != nil {
			return err
		}
		// The OS, model, maker and type feed matching; a host name feeds the findings' evidence text.
		o.add(EventAssetUpdated, AssetEvent{AssetID: id, Match: true})
		return nil
	})
}

// KeepEntered records that the person keeps their own value against the detected one (INV-47): the notice stays hidden until the
// sources read another value. Nothing else changes. Audited with the person.
func (s *Service) KeepEntered(ctx context.Context, actor, id, field, detected string) error {
	if err := s.requireDevice(ctx, id); err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		d, err := s.findDiffers(ctx, tx, id, field, detected)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO inv_detected_keep (asset_id, field, detected, kept_at, kept_by) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (asset_id, field, detected) DO NOTHING`, id, field, detected, s.now(), nullStr(actor)); err != nil {
			return fmt.Errorf("inventory: keep the entered value: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.keep_entered", deviceName(ctx, tx, id), fieldLabel(field)+": kept "+d.Entered+", not "+d.Detected)
	})
}

func fieldLabel(field string) string {
	switch field {
	case "hostname":
		return "host name"
	case "vendor":
		return "maker"
	case "kind":
		return "type"
	case "os":
		return "OS"
	}
	return field
}
