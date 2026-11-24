package mitigation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/findings"
)

// W-1: when the device's own agent reported the version, "How to check it yourself" does not ask for it (no About screen),
// says the agent reports the new version by itself and the finding closes by itself. A version from a scan keeps the old steps.
func TestGenericRecheck_AgentVersionIsNotAskedFor(t *testing.T) {
	row := func(agent bool) findings.Row {
		var r findings.Row
		doc := `{"basis":"version","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z","agent":` + map[bool]string{true: "true", false: "false"}[agent] + `},
			"asset":{"id":"a","name":"WIN-LAB","hostname":"WIN-LAB","ip":"10.142.0.128","kind":"server","display":"Windows"},
			"kev":{"display":"Windows","vendor":"Microsoft","product":"Windows","has_template":false}}`
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	got := strings.Join(genericRecheck(row(true), false).Steps, " ")
	if strings.Contains(got, "About screen") || !strings.Contains(got, "the agent on WIN-LAB reports the installed version of Windows") || !strings.Contains(got, "closes this finding by itself") {
		t.Fatalf("agent: %s", got)
	}
	if got := strings.Join(genericRecheck(row(false), false).Steps, " "); !strings.Contains(got, "About screen") {
		t.Fatalf("scan: %s", got)
	}
}

// A product-only match on a row the agent reported with its version does not ask to look the version up either: the agent gave it,
// and the comparison with NVD's data is what failed. A product match on a typed row keeps "Check which version".
func TestGenericRecheck_AgentRowProductMatchDoesNotAskForTheVersion(t *testing.T) {
	row := func(agentRow bool) findings.Row {
		var r findings.Row
		doc := `{"basis":"product","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z","agent_row":` + map[bool]string{true: "true", false: "false"}[agentRow] + `},
			"asset":{"id":"a","name":"srv01","hostname":"srv01","ip":"10.142.0.181","kind":"server","display":"OpenSSL"},
			"kev":{"display":"OpenSSL","vendor":"OpenSSL","product":"OpenSSL","has_template":false}}`
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	got := strings.Join(genericRecheck(row(true), false).Steps, " ")
	if strings.Contains(got, "About screen") || !strings.Contains(got, "Nothing to look up on srv01: its agent reports the installed version of OpenSSL") {
		t.Fatalf("agent row: %s", got)
	}
	if got := strings.Join(genericRecheck(row(false), false).Steps, " "); !strings.Contains(got, "About screen") {
		t.Fatalf("typed row: %s", got)
	}
}

// A version the box has from any source (SNMP, LLDP, a scan, a person, an agent) is never asked for again: the first
// step names the version and who gave it, the second how a newer one reaches Vedette. The device and the software are never glued.
func TestGenericRecheck_M23_KnownVersionFromEverySource(t *testing.T) {
	row := func(basis, ip string, tmpl bool, k *findings.KnownVersion) findings.Row {
		var r findings.Row
		doc := `{"basis":"` + basis + `","evidence":{"summary":"s","checked_at":"2026-11-15T00:00:00Z"},
			"asset":{"id":"a","name":"Juniper Networks EX4200-48T","hostname":null,"ip":"` + ip + `","kind":"switch","display":"Juniper Junos OS"},
			"kev":{"display":"Juniper Junos OS","vendor":"Juniper","product":"Junos OS","has_template":` + map[bool]string{true: "true", false: "false"}[tmpl] + `}}`
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		r.Known = k
		return r
	}
	kv := func(src string) *findings.KnownVersion {
		return &findings.KnownVersion{Software: "Juniper Junos OS", Version: "15.1R7.9", Source: src}
	}
	for _, c := range []struct {
		src, first, again string
	}{
		{findings.VersionBySNMP, "Nothing to look up: Vedette read Juniper Junos OS 15.1R7.9 from Juniper Networks EX4200-48T over SNMP. Vedette compared it", `press "Read with SNMP now" on its device page`},
		{findings.VersionByStated, "Nothing to look up: Juniper Networks EX4200-48T states on the network (LLDP) that it runs Juniper Junos OS 15.1R7.9", "states the new one on the network by itself"},
		{findings.VersionByScan, "Nothing to look up: a network scan read Juniper Junos OS 15.1R7.9 from Juniper Networks EX4200-48T", "rescan it with the button below"},
		{findings.VersionByManual, "Nothing to look up: Juniper Junos OS 15.1R7.9 was entered for Juniper Networks EX4200-48T on the Devices page", `press "I updated Juniper Junos OS" at the top of this page`},
		{findings.VersionByAgent, "Nothing to look up: the agent on Juniper Networks EX4200-48T reports Juniper Junos OS 15.1R7.9", "its agent reports the new one by itself"},
	} {
		steps := genericRecheck(row("version", "10.142.0.47", true, kv(c.src)), false).Steps
		got := strings.Join(steps, " ")
		if len(steps) != 3 || !strings.HasPrefix(steps[0], c.first) || !strings.Contains(steps[1], c.again) || !strings.Contains(steps[1], `it can prove that version fixes. If this one stays open, press "Mark as handled" and choose Patched.`) || !strings.Contains(steps[2], `"Rescan this device" to confirm`) {
			t.Errorf("%s: %q", c.src, steps)
		}
		if strings.Contains(got, "About screen") || strings.Contains(got, "Check which version") || strings.Contains(got, "OS Juniper Networks") {
			t.Errorf("%s asks for the version or glues the names: %s", c.src, got)
		}
	}
	// No template, a product-only match, a scan-read version on a device without an IP.
	steps := genericRecheck(row("product", "—", false, kv(findings.VersionByScan)), false).Steps
	if !strings.Contains(steps[0], "cannot compare it with the versions NVD lists") || !strings.Contains(steps[1], "the next network scan of it reads the new one") || !strings.Contains(steps[2], "concludes from the version alone") {
		t.Errorf("product, no IP, no template: %q", steps)
	}
	// No version known: the old steps, worded without gluing the software to the device.
	if got := genericRecheck(row("version", "10.142.0.47", false, nil), false).Steps[0]; got != "Check which version of Juniper Junos OS runs on Juniper Networks EX4200-48T (in its settings, its admin page or its About screen)." {
		t.Errorf("unknown version: %q", got)
	}
}
