package main

import (
	"path/filepath"
	"testing"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/modules/inventory"
)

// D-501, review H1: an operating system nmap only guessed raises no finding. A Windows 10 PC picked in Scan now (the fixture
// prints services without versions and the fingerprint "Microsoft Windows 10 1607") gets its OS recorded and shown, and 0
// findings, although the CISA list has entries for Microsoft Windows; once a person adds Windows 10 with its version on the device
// page, it is matched. Before the fix the guessed row carried the KEV key microsoft|windows: on a real box 175 findings.
func TestNmapOSGuessRaisesNoFindingUntilAPersonConfirmsIt(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.kev("CVE-2026-5001", "Microsoft", "Windows")
	s.kev("CVE-2026-5002", "Microsoft", "Windows")
	fx, err := filepath.Abs(filepath.Join("..", "..", "modules", "sensor-active", "testdata", "windows.xml"))
	if err != nil {
		t.Fatal(err)
	}
	nm := filepath.Join(t.TempDir(), "nmap")
	exectest.WriteScript(t, nm, "#!/bin/sh\ncat "+fx+"\n")
	svc, err := newLocalSensorActive(*s.d, nm)
	if err != nil {
		t.Fatal(err)
	}
	s.saveScope(t)
	id := s.seen(t, "192.168.10.20", "aa:bb:cc:00:00:22", "")
	got, err := svc.IdentifyDevice(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Why != "os_unconfirmed" {
		t.Fatalf("identification = %+v, want os_unconfirmed", got)
	}
	d, err := s.d.Inventory.Detail(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Asset.OS == nil || d.Asset.OS.Value != "Microsoft Windows 10 1607" {
		t.Fatalf("os = %+v, want the guess shown", d.Asset.OS)
	}
	if n := s.nf(id, ""); n != 0 {
		t.Fatalf("%d findings from nmap's OS guess, want 0 until a person confirms it", n)
	}
	if _, err := s.d.Inventory.AddSoftware(t.Context(), "it@acme.example", id, inventory.AddInput{CatalogID: "windows-10", Version: "22H2"}); err != nil {
		t.Fatal(err)
	}
	if n := s.nf(id, ""); n != 2 {
		t.Fatalf("%d findings after the person added Windows 10, want 2", n)
	}
}
