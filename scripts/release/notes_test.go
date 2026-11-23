package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The manifest's notes are one line a box shows: a box refuses a manifest whose notes hold a control character or exceed 2048 bytes
// (internal/release parseManifest), so the builder refuses them where it first reads them, naming what is wrong. Multi-line text for
// the GitHub release page goes in release_notes, which is not signed into the manifest.
func TestNotesAreOneLineABoxAccepts(t *testing.T) {
	doc := func(notes, releaseNotes string) []byte {
		b, err := json.Marshal(map[string]string{"version": "0.1.0", "channel": "beta", "notes": notes, "release_notes": releaseNotes})
		must(t, err)
		return b
	}
	cases := map[string]struct{ notes, want string }{
		"a newline":           {"Fixes the scan.\nAlso the sensor.", "newline"},
		"a carriage return":   {"Fixes the scan.\r", "newline"},
		"a tab":               {"Fixes\tthe scan.", "control character"},
		"too long":            {strings.Repeat("a", 2049), "2049 bytes"},
		"one line, the limit": {strings.Repeat("a", 2048), ""},
		"non-ASCII text":      {"Sửa lỗi quét — nhanh hơn.", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseInputs(doc(c.notes, ""))
			if c.want == "" {
				must(t, err)
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "release_notes") {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if _, err := BuildManifest(Inputs{Version: "0.1.0", Channel: "beta", InstallModes: []string{"appliance"}, Notes: c.notes}, Env{Now: t1}); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("BuildManifest: %v", err)
			}
		})
	}
	if _, err := ParseInputs(doc("One line.", "## Vedette 0.1.0\n\n- Fixes the scan.\n- Faster sensor.\n")); err != nil {
		t.Errorf("multi-line release_notes: %v", err)
	}
	if _, err := ParseInputs(doc("One line.", "bad \x00 byte")); err == nil {
		t.Error("a NUL in release_notes")
	}
	if _, err := ParseInputs(doc("One line.", strings.Repeat("a", maxReleaseNotes+1))); err == nil {
		t.Error("release_notes above the limit")
	}
}

// release in takes both texts and refuses notes a box would refuse before writing release.in.json.
func TestReleaseInNotes(t *testing.T) {
	if _, err := BuildInputs(context.Background(), nil, &ImagesDoc{Version: "0.1.0"}, inputsOpts{Channel: "beta", RollbackSafe: "false", Notes: "two\nlines"}); err == nil || !strings.Contains(err.Error(), "newline") {
		t.Errorf("release in with multi-line notes: %v", err)
	}
}

// The GitHub release page shows release_notes when given, the manifest's notes otherwise.
func TestPublishUsesReleaseNotes(t *testing.T) {
	r := newRig(t)
	dir, s, in := signedRelease(t, r, "0.2.0", "")
	in.ReleaseNotes = "## Vedette 0.2.0\n\n- Fixes the scan.\n"
	p, err := planPublish(dir, s, in, r.trust)
	must(t, err)
	if p.Notes != strings.TrimRight(in.ReleaseNotes, "\n") {
		t.Errorf("notes %q", p.Notes)
	}
	in.ReleaseNotes = ""
	p, err = planPublish(dir, s, in, r.trust)
	must(t, err)
	if p.Notes != "Test release & <notes>" {
		t.Errorf("notes %q", p.Notes)
	}
}
