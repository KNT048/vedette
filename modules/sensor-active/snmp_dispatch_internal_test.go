package sensoractive

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// Review #715 L4: an snmp job that waits in its slot is not handed to a worker whose latest heartbeat no longer says snmp (a worker
// replaced by one of protocol 4 between RunSNMP's check and the poll).
func TestSNMPJobWaitsForAWorkerThatSaysSNMP(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		d := NewDispatcher(DispatcherOptions{Tick: 10 * time.Millisecond})
		if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", SNMP: true}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = d.RunSNMP(ctx, sensorlink.SNMPJob{Rate: 10, Credentials: []sensorlink.SNMPCredential{{Version: "v2c", Community: "c"}},
				Targets: []sensorlink.SNMPTarget{{IP: "192.168.10.20", Credentials: []int{0}}}})
		}()
		synctest.Wait() // RunSNMP has put the job in its slot and waits
		d.mu.Lock()
		waiting := d.snmpSlot.pending != nil
		d.mu.Unlock()
		if !waiting {
			t.Fatal("the job does not wait in its slot")
		}
		if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0"}); err != nil {
			t.Fatal(err)
		}
		if rep, _ := d.Jobs(t.Context(), 20*time.Millisecond, nil); len(rep.Jobs) != 0 {
			t.Fatalf("a job went to a worker that runs no snmp: %+v", rep.Jobs)
		}
		cancel()
		<-done
	})
}
