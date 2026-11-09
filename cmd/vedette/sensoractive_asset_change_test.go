package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/modules/inventory"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// A change to the device being scanned right now stops the run (inventory.asset.updated reaches
// sensor-active.AssetChanged): marked fragile, or regular scan set to never. A change to another device does not.
// The stop is ErrStopped, not a failure. The nmap here is a script that sleeps; it never touches a network.
func TestSensorActiveDeviceChangeStopsTheRunningScan(t *testing.T) {
	t.Parallel()
	yes, never := true, "never"
	for name, patch := range map[string]inventory.Patch{
		"marked fragile":     {Fragile: &yes},
		"regular scan never": {RegularScan: &never},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newStack(t)
			s.saveScope(t)
			target := s.seen(t, "192.168.10.20", "aa:bb:cc:00:04:01", "server")
			other := s.seen(t, "192.168.10.21", "aa:bb:cc:00:04:02", "server")
			s.setModule("sensor-active", true)
			dir := t.TempDir()
			started := filepath.Join(dir, "started")
			nmap := filepath.Join(dir, "nmap")
			exectest.WriteScript(t, nmap, fmt.Sprintf("#!/bin/sh\ntouch %q\nexec sleep 30\n", started))
			d := *s.d
			d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) } // Monday 02:00, inside 01:00-05:00
			svc, err := newSensorActive(d, nmap)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- svc.ScanDevice(t.Context(), target, "discovered") }()
			for deadline := time.Now().Add(10 * time.Second); ; <-time.After(20 * time.Millisecond) {
				if _, err := os.Stat(started); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the fake nmap did not start")
				}
			}
			if err := s.d.Inventory.PatchDevice(t.Context(), "it@acme.example", other, patch); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				t.Fatalf("a change to another device ended the run: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			if err := s.d.Inventory.PatchDevice(t.Context(), "it@acme.example", target, patch); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, sensoractive.ErrStopped) {
					t.Errorf("err = %v, want ErrStopped", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the scan of the device went on after the device was changed")
			}
		})
	}
}
