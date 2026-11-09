package response

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/conn/cliban"
)

func libraryActions(t *testing.T) map[string]builtinDef {
	t.Helper()
	b, err := dataFiles.ReadFile("data/action-templates.json")
	if err != nil {
		t.Fatal(err)
	}
	var lib struct {
		Actions []builtinDef `json:"actions"`
	}
	if err := json.Unmarshal(b, &lib); err != nil {
		t.Fatal(err)
	}
	out := map[string]builtinDef{}
	for _, a := range lib.Actions {
		out[a.ID] = a
	}
	return out
}

func TestNormalizeOutput(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"carriage returns":    {"a\r\nb\r\n", "a\nb\n"},
		"ansi colour":         {"\x1b[31mAdmin state is down\x1b[0m", "Admin state is down"},
		"ansi cursor move":    {"a\x1b[2K\x1b[1Gb", "ab"},
		"ansi title (OSC)":    {"\x1b]0;switch\x07port", "port"},
		"control characters":  {"a\x00b\x07c\x08d", "abcd"},
		"runs of spaces":      {"Access  Mode   VLAN:\t\t20", "Access Mode VLAN: 20"},
		"tabs":                {"a\tb", "a b"},
		"pretty JSON":         {"{\n  \"results\": [ { \"action\" : \"deny\",\n \"status\": \"enable\" } ]\n}\n", `{"results":[{"action":"deny","status":"enable"}]}`},
		"JSON array":          {"[ 1, 2 ]", "[1,2]"},
		"not JSON is kept":    {"{ not json", "{ not json"},
		"case is kept":        {"Administrative Mode: Trunk", "Administrative Mode: Trunk"},
		"newlines are kept":   {"a\n\nb", "a\n\nb"},
		"empty":               {"", ""},
		"only noise":          {"\x1b[0m\r\x00", ""},
		"line separator char": {"a b", "ab"},
	} {
		if got := normalizeOutput(c.in); got != c.want {
			t.Errorf("%s: %q -> %q, want %q", name, c.in, got, c.want)
		}
		if again := normalizeOutput(normalizeOutput(c.in)); again != normalizeOutput(c.in) {
			t.Errorf("%s: not idempotent: %q", name, again)
		}
	}
}

func TestPrecheckVerdict(t *testing.T) {
	refuse := []string{"Mode: trunk", "Switchport: Disabled"}
	for name, c := range map[string]struct {
		out, expect string
		refused     bool
	}{
		"clean output":                       {"Administrative Mode: static access\r\n", "Administrative Mode: static access", false},
		"a refusal text":                     {"Administrative Mode: trunk\r\n", "", true},
		"a refusal text with colour":         {"\x1b[1mSwitchport: Disabled\x1b[0m", "", true},
		"a refusal text split by space":      {"Administrative   Mode:\ttrunk", "", true},
		"refusal text is case sensitive":     {"administrative mode: TRUNK", "", false},
		"missing required text":              {"Operational Mode: down", "Administrative Mode: static access", true},
		"required text, other spacing":       {"Administrative  Mode:  static access", "Administrative Mode: static access", false},
		"empty output fails closed":          {"", "", true},
		"blank output fails closed":          {" \r\n\x1b[0m\t", "", true},
		"empty output, with a required text": {"", "x", true},
	} {
		got := precheckVerdict(c.out, refuse, c.expect)
		if (got != "") != c.refused {
			t.Errorf("%s: verdict %q", name, got)
		}
	}
	if precheckVerdict("anything", nil, "") != "" {
		t.Error("a check with no texts refused non-empty output")
	}
}

func TestReadBackHolds(t *testing.T) {
	if !readBackHolds("{\n \"status\" : \"disable\" }", `"status":"disable"`, false) {
		t.Error("the JSON read-back after the action did not hold")
	}
	if readBackHolds(`{"status":"disable"}`, `"status":"disable"`, true) || !readBackHolds(`{"status":"enable"}`, `"status":"disable"`, true) {
		t.Error("after the undo the text must be gone")
	}
	if !readBackHolds("Gi1/0/1 \r\n  disabled  ", "disabled", false) {
		t.Error("an SSH read-back with a carriage return did not hold")
	}
}

// M5: both port-shut built-ins promise "undo leaves it shut", but nothing reads the old state yet and the undo is a plain "no shutdown".
// The check before must refuse a port that is already down, or the undo (which runs without approval) would turn on a port an
// administrator shut.
func TestBuiltinPortShutRefusesAPortThatIsAlreadyDown(t *testing.T) {
	lib := libraryActions(t)
	cisco, aoscx := lib["cisco_port_shut"], lib["aoscx_port_shut"]
	// what the shipped check prints for an access port an administrator shut: both commands, one after the other
	ciscoDown := "Name: Gi1/0/12\r\nSwitchport: Enabled\r\nAdministrative Mode: static access\r\nOperational Mode: down\r\nAccess Mode VLAN: 20 (USERS)\r\n" +
		"GigabitEthernet1/0/12 is administratively down, line protocol is down (disabled)\r\n  Hardware is Gigabit Ethernet\r\n"
	ciscoUp := "Name: Gi1/0/12\r\nSwitchport: Enabled\r\nAdministrative Mode: static access\r\nOperational Mode: static access\r\nAccess Mode VLAN: 20 (USERS)\r\n" +
		"GigabitEthernet1/0/12 is up, line protocol is up (connected)\r\n"
	if v := precheckVerdict(ciscoDown, cisco.PrecheckRefuse, cisco.PrecheckExpect); v == "" {
		t.Error("cisco_port_shut does not refuse a port that is administratively down")
	}
	if v := precheckVerdict(ciscoUp, cisco.PrecheckRefuse, cisco.PrecheckExpect); v != "" {
		t.Errorf("cisco_port_shut refuses a live access port: %s", v)
	}
	if !strings.Contains(cisco.Precheck.CLI, "show interfaces {interface}\n") && !strings.HasSuffix(cisco.Precheck.CLI, "show interfaces {interface}") {
		t.Errorf("the Cisco check does not read the interface state: %q", cisco.Precheck.CLI)
	}
	aoscxDown := "Interface 1/1/12 is down\r\n Admin state is down\r\n State information: Administratively down\r\n VLAN Mode: access\r\n Access VLAN: 20\r\n"
	aoscxUp := "Interface 1/1/12 is up\r\n Admin state is up\r\n VLAN Mode: access\r\n Access VLAN: 20\r\n"
	if v := precheckVerdict(aoscxDown, aoscx.PrecheckRefuse, aoscx.PrecheckExpect); v == "" {
		t.Error("aoscx_port_shut does not refuse a port that is already down")
	}
	if v := precheckVerdict(aoscxUp, aoscx.PrecheckRefuse, aoscx.PrecheckExpect); v != "" {
		t.Errorf("aoscx_port_shut refuses a live access port: %s", v)
	}
}

// M6: the refusal list is a deny list over unparsed output, so the Cisco port actions also require the positive text, and they refuse
// the modes a deny list tends to forget. A bare "trunk" is not a refusal text (it matches a VLAN or a description called trunk).
func TestCiscoPortChecksFailClosedOnUnexpectedOutput(t *testing.T) {
	lib := libraryActions(t)
	for _, id := range []string{"cisco_port_shut", "cisco_port_vlan_quarantine"} {
		a := lib[id]
		if a.PrecheckExpect != "Administrative Mode: static access" {
			t.Errorf("%s expects %q", id, a.PrecheckExpect)
		}
		for _, r := range a.PrecheckRefuse {
			if strings.EqualFold(strings.TrimSpace(r), "trunk") {
				t.Errorf("%s has a bare trunk refusal", id)
			}
		}
		for name, out := range map[string]string{
			"a routed uplink":      "Name: Gi1/0/48\r\nSwitchport: Disabled\r\n",
			"a trunk member":       "Name: Gi1/0/49\r\nSwitchport: Enabled\r\nAdministrative Mode: trunk\r\nOperational Mode: trunk (member of bundle Po1)\r\n",
			"dynamic auto":         "Switchport: Enabled\r\nAdministrative Mode: dynamic auto\r\nOperational Mode: static access\r\n",
			"private vlan trunk":   "Switchport: Enabled\r\nAdministrative Mode: private-vlan trunk promiscuous\r\n",
			"a tunnel port":        "Switchport: Enabled\r\nAdministrative Mode: tunnel\r\nOperational Mode: tunnel\r\n",
			"an unexpected output": "% Invalid input detected at '^' marker.\r\n",
			"an empty output":      "",
		} {
			if precheckVerdict(out, a.PrecheckRefuse, a.PrecheckExpect) == "" {
				t.Errorf("%s does not refuse %s", id, name)
			}
		}
		access := "Name: Gi1/0/12\r\nSwitchport: Enabled\r\nAdministrative Mode: static access\r\nOperational Mode: static access\r\n"
		if v := precheckVerdict(access, a.PrecheckRefuse, a.PrecheckExpect); v != "" && id == "cisco_port_vlan_quarantine" {
			t.Errorf("%s refuses an access port: %s", id, v)
		}
	}
}

// M7: fgt_policy_disable promises to refuse a policy whose action is deny (turning that off opens traffic). The check reads the policy
// and refuses "action":"deny" after the JSON is compacted, or "set action deny" in the command form.
func TestFortiGatePolicyDisableRefusesADenyPolicy(t *testing.T) {
	a := libraryActions(t)["fgt_policy_disable"]
	if !strings.Contains(a.Description, "refuses to turn off a policy whose action is deny") {
		t.Fatal("the description no longer promises the deny check")
	}
	if a.Precheck.Method != "GET" || !strings.Contains(a.Precheck.Path, "{id}") || strings.TrimSpace(a.Precheck.CLI) == "" {
		t.Fatalf("the check reads the policy over the API and by command: %+v", a.Precheck)
	}
	deny := "{\n  \"http_method\": \"GET\",\n  \"results\": [\n    { \"policyid\": 7, \"name\": \"block-guests\", \"action\": \"deny\", \"status\": \"enable\" }\n  ]\n}"
	allow := "{\n  \"results\": [ { \"policyid\": 8, \"name\": \"web\", \"action\": \"accept\", \"status\": \"enable\" } ]\n}"
	if precheckVerdict(deny, a.PrecheckRefuse, a.PrecheckExpect) == "" {
		t.Error("a deny policy (pretty JSON) is not refused")
	}
	if v := precheckVerdict(allow, a.PrecheckRefuse, a.PrecheckExpect); v != "" {
		t.Errorf("an accept policy is refused: %s", v)
	}
	if precheckVerdict("config firewall policy\n    edit 7\n        set name \"block-guests\"\n        set action deny\n    next\nend\n", a.PrecheckRefuse, a.PrecheckExpect) == "" {
		t.Error("a deny policy (command form) is not refused")
	}
}

// M4: the library loader refuses a read-back that writes, and an SSH read-back or check that is a line of the action.
func TestLibraryReadBackAndCheckAreReadOnly(t *testing.T) {
	base := builtinDef{ID: "x_api", Kind: "device", Risk: RiskLow, Run: Tpl{Method: "POST", Path: "/a/{ip}"}, Rollback: Tpl{Method: "DELETE", Path: "/a/{ip}"}}
	for name, mod := range map[string]func(a *builtinDef){
		"DELETE read-back":         func(a *builtinDef) { a.Verify = Tpl{Method: "DELETE", Path: "/a/{ip}", Expect: "{ip}"} },
		"POST read-back":           func(a *builtinDef) { a.Verify = Tpl{Method: "POST", Path: "/a/{ip}", Expect: "{ip}"} },
		"read-back with a body":    func(a *builtinDef) { a.Verify = Tpl{Method: "GET", Path: "/a/{ip}", Body: `{"a":1}`, Expect: "{ip}"} },
		"SSH read-back configures": func(a *builtinDef) { a.Verify = Tpl{CLI: "configure terminal\nshow x {ip}"} },
		"SSH check shares a line": func(a *builtinDef) {
			a.Run, a.Rollback = Tpl{CLI: "block {ip}"}, Tpl{CLI: "unblock {ip}"}
			a.Precheck, a.PrecheckRefuse = Tpl{CLI: "show x {ip}\nblock {ip}"}, []string{"x"}
		},
		"SSH check deletes": func(a *builtinDef) {
			a.Run, a.Rollback = Tpl{CLI: "block {ip}"}, Tpl{CLI: "unblock {ip}"}
			a.Precheck, a.PrecheckRefuse = Tpl{CLI: "delete flash:x {ip}"}, []string{"x"}
		},
	} {
		a := base
		mod(&a)
		if err := checkBuiltinTpls(a); err == nil {
			t.Errorf("%s was accepted by the library loader", name)
		}
	}
	// the shipped library obeys it: every library action loads (the service starts), and its reads share no line with its writes
	for id, a := range libraryActions(t) {
		if err := checkBuiltinTpls(a); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}

// M4: the approval screen shows the stored method of a read step, not a hard-coded GET.
func TestReadStepTextShowsTheStoredMethod(t *testing.T) {
	conn := &ConnectionInfo{Connection: Connection{Kind: "http"}, Target: "https://api.lan"}
	vals := Values{PIP: "198.51.100.7"}
	got, err := readStepText(Tpl{Method: "PUT", Path: "/x/{ip}"}, conn, vals, nil)
	if err != nil || got != "PUT https://api.lan/x/198.51.100.7" {
		t.Errorf("%q, %v", got, err)
	}
	if got, _ := readStepText(Tpl{Method: "GET", Path: "/x/{ip}"}, conn, vals, nil); got != "GET https://api.lan/x/198.51.100.7" {
		t.Errorf("%q", got)
	}
	if got, _ := readStepText(Tpl{CLI: "terminal length 0\nshow x {ip}"}, &ConnectionInfo{Connection: Connection{Kind: "ssh"}}, vals, nil); got != "terminal length 0\nshow x 198.51.100.7" {
		t.Errorf("%q", got)
	}
	if got, _ := readStepText(Tpl{}, conn, vals, nil); got != "" {
		t.Errorf("an empty step shows %q", got)
	}
}

// D-58: the commands a template may not contain are data, not Go literals, and the GUI mock carries the same file.
func TestRefusedCommandListIsDataAndTheMockCopyMatches(t *testing.T) {
	ban, err := banData()
	if err != nil || len(ban.Everywhere) < 10 || len(ban.ReadOnly) < 5 {
		t.Fatalf("the list: %+v, %v", ban, err)
	}
	mock, err := os.ReadFile("../../web/src/features/response/templates/cli-ban.sample.json")
	if err != nil {
		t.Skip("the web tree is not here")
	}
	ours := cliban.JSON()
	if string(mock) != string(ours) {
		t.Error("cli-ban.json differs from the GUI mock copy")
	}
	for l, want := range map[string]bool{"reload": true, "reload in 5": true, "write erase": true, "copy running-config tftp://1.2.3.4/x": true, "copy flash: scp://h/x": true,
		"factory-reset": true, "show reload cause": false, "show running-config": false, "reloading": false, "terminal length 0": false, "no page": false} {
		if got := banHit(cliLines(l), ban.Everywhere) != ""; got != want {
			t.Errorf("everywhere: %q refused = %v", l, got)
		}
	}
	for l, want := range map[string]bool{"configure terminal": true, "conf t": true, "copy running-config startup-config": true, "write memory": true, "shutdown": true, "no shutdown": true,
		"show interfaces x": false, "terminal length 0": false, "no page": false, "show configuration": false} {
		if got := banHit(cliLines(l), ban.ReadOnly) != ""; got != want {
			t.Errorf("read-only steps: %q refused = %v", l, got)
		}
	}
}

// The Go library and the mock library carry the same data for the actions this slice touches (the drift test lists the exceptions).
func TestNoCommandBanLiteralsInGoSource(t *testing.T) {
	for _, f := range []string{"readonly.go", "../../core/conn/cliban/cliban.go", "../../core/conn/write/write.go"} {
		src, err := os.ReadFile(f) //nolint:gosec // our own source files
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range []string{`"reload"`, `"write erase"`, `"configure`, `"conf t"`, `"startup`} {
			if strings.Contains(string(src), w) {
				t.Errorf("%s names %s: the lists belong in core/conn/cliban/cli-ban.json (D-58)", f, w)
			}
		}
	}
}
