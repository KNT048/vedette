package ai

import (
	"encoding/json"
	"math/rand/v2"
	"slices"
	"testing"
)

func schema() json.RawMessage { return json.RawMessage(`{"type":"object","properties":{}}`) }

func TestContract_INV14_NoWriteToolInModelToolList(t *testing.T) {
	t.Parallel()
	tools := []Tool{
		{Name: "search_assets", Description: "Find devices", Access: AccessRead, Enabled: true, Schema: schema()},
		{Name: "lookup_cve", Access: AccessRead, Enabled: true},
		{Name: "disabled_read", Access: AccessRead, Enabled: false},
		{Name: "block_ip", Description: "Add an IP to the firewall blocklist", Access: AccessWrite, Enabled: true},
		{Name: "reboot", Access: AccessWrite, Enabled: false},
		{Name: "ssh_exec", Access: "", Enabled: true},  // unknown access is treated as write
		{Name: "weird", Access: "READ", Enabled: true}, // not exactly "read"
		{Name: "only_digest", Access: AccessRead, Enabled: true, Jobs: []Job{JobLogDigest}},
		{Name: "bad name!", Access: AccessRead, Enabled: true}, // not sendable to a provider
		{Name: "shared", Access: AccessRead, Enabled: true},    // same name as a write tool below
		{Name: "shared", Access: AccessWrite, Enabled: true},
		{Name: "lookup_cve", Access: AccessRead, Enabled: true}, // duplicate read tool: offered once
	}
	names := func(job Job) []string {
		var out []string
		for _, d := range ForModel(job, tools) {
			out = append(out, d.Name)
		}
		return out
	}
	if got := names(JobAskMyData); !slices.Equal(got, []string{"lookup_cve", "search_assets"}) {
		t.Fatalf("ask-my-data: %v", got)
	}
	if got := names(JobLogDigest); !slices.Equal(got, []string{"lookup_cve", "only_digest", "search_assets"}) {
		t.Fatalf("log-digest: %v", got)
	}
	for _, job := range Jobs() {
		for _, n := range names(job) {
			for _, w := range []string{"block_ip", "reboot", "ssh_exec", "shared", "weird"} {
				if n == w {
					t.Fatalf("%s: write or non-read tool %q reached the model", job, n)
				}
			}
		}
	}
	// A model that asks for a tool that was not offered gets nothing to run.
	if _, ok := Offered(JobAskMyData, tools, "block_ip"); ok {
		t.Fatal("write tool is dispatchable")
	}
	if _, ok := Offered(JobAskMyData, tools, "only_digest"); ok {
		t.Fatal("tool of another job is dispatchable")
	}
	if tl, ok := Offered(JobAskMyData, tools, "search_assets"); !ok || tl.Access != AccessRead {
		t.Fatal("read tool must be dispatchable")
	}
	if ForModel(JobAskMyData, nil) != nil {
		t.Fatal("no tools, no list")
	}
}

// The property behind INV-14: for any set of tools, no name in the list belongs to a tool that is not a plain
// enabled read tool, and every write tool name is absent.
func TestToolFilterProperty(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // fixed seed: reproducible test data, not security
	names := []string{"a", "b", "c", "d", "bad name", ""}
	accesses := []Access{AccessRead, AccessWrite, "", "Read", "x"}
	for range 3000 {
		var tools []Tool
		for range rng.IntN(10) {
			tl := Tool{Name: names[rng.IntN(len(names))], Access: accesses[rng.IntN(len(accesses))], Enabled: rng.IntN(2) == 0}
			if rng.IntN(3) == 0 {
				tl.Jobs = []Job{Jobs()[rng.IntN(10)]}
			}
			tools = append(tools, tl)
		}
		checkNoWrite(t, Jobs()[rng.IntN(10)], tools)
	}
}

func checkNoWrite(t *testing.T, job Job, tools []Tool) {
	t.Helper()
	got := ForModel(job, tools)
	seen := map[string]bool{}
	for _, d := range got {
		if seen[d.Name] {
			t.Fatalf("duplicate %q", d.Name)
		}
		seen[d.Name] = true
		ok := false
		for _, tl := range tools {
			if tl.Name != d.Name {
				continue
			}
			if tl.Access != AccessRead {
				t.Fatalf("name %q is offered although a tool of that name has access %q: %+v", d.Name, tl.Access, tools)
			}
			ok = ok || tl.Enabled
		}
		if !ok {
			t.Fatalf("offered %q but no enabled tool has it", d.Name)
		}
	}
}

func FuzzForModel(f *testing.F) {
	f.Add("search_assets", "read", true, "lookup", "write", true, uint8(0))
	f.Add("x", "", true, "x", "read", true, uint8(3))
	f.Fuzz(func(t *testing.T, n1, a1 string, e1 bool, n2, a2 string, e2 bool, job uint8) {
		tools := []Tool{{Name: n1, Access: Access(a1), Enabled: e1}, {Name: n2, Access: Access(a2), Enabled: e2}, {Name: n1, Access: AccessWrite, Enabled: true}}
		checkNoWrite(t, Jobs()[int(job)%10], tools[:2])
		// With a write tool of the same name present, that name must vanish.
		for _, d := range ForModel(Jobs()[int(job)%10], tools) {
			if d.Name == n1 {
				t.Fatalf("%q offered although a write tool has that name", n1)
			}
		}
	})
}
