package sensorlink

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The deep-scan settings of an nmap job (protocol 5): the groups its full shape may run and the ports it skips travel as "narrow",
// absent on every other job so an older worker gets the shape it knows; the worker says it takes them in its heartbeat (nmap.narrow).
func TestNarrowJobRoundTrips(t *testing.T) {
	t.Parallel()
	j := Job{ID: "j1", Kind: KindNmap, Shape: "external_full", Rate: 100, Targets: []string{"8.8.8.8"}, TimeoutS: 60,
		Narrow: &NmapNarrow{Groups: []string{"logins", "change"}, SkipPorts: []int{22, 8080}}}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"narrow":{"groups":["logins","change"],"skip_ports":[22,8080]}`) {
		t.Fatalf("wire: %s", b)
	}
	var back Job
	if err := json.Unmarshal(b, &back); err != nil || back.Narrow == nil || !slices.Equal(back.Narrow.Groups, j.Narrow.Groups) || !slices.Equal(back.Narrow.SkipPorts, j.Narrow.SkipPorts) {
		t.Fatalf("back %+v %v", back.Narrow, err)
	}
	// no groups allowed is a list, not "every group"
	j.Narrow = &NmapNarrow{Groups: []string{}}
	b, _ = json.Marshal(j)
	if !strings.Contains(string(b), `"narrow":{"groups":[]}`) {
		t.Fatalf("no group: %s", b)
	}
	j.Narrow = nil
	if b, _ = json.Marshal(j); strings.Contains(string(b), "narrow") {
		t.Fatalf("a job without settings carries them: %s", b)
	}
	var hb HeartbeatNmap
	if err := json.Unmarshal([]byte(`{"present":true,"version":"7.95","full":true,"narrow":true}`), &hb); err != nil || !hb.Narrow {
		t.Fatalf("heartbeat %+v %v", hb, err)
	}
}
