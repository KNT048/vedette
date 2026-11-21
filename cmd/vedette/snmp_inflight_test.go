package main

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// heldWorker stands in for the worker of the scan container: an SNMP job or an nmap command is held until the test lets it go, and is
// sent (recorded in sent) only if its context is still live then. Nothing leaves the machine.
type heldWorker struct {
	started chan struct{} // closed when the first job arrives
	proceed chan struct{} // closed by the test: the worker sends now
	once    sync.Once
	mu      sync.Mutex
	sent    []string // the addresses a secret or a probe went to
}

func newHeldWorker() *heldWorker {
	return &heldWorker{started: make(chan struct{}), proceed: make(chan struct{})}
}

func (w *heldWorker) hold(ctx context.Context, targets ...string) error {
	w.once.Do(func() { close(w.started) })
	<-w.proceed
	if err := ctx.Err(); err != nil { // cancelled before the worker reached the target: nothing sent
		return err
	}
	w.mu.Lock()
	w.sent = append(w.sent, targets...)
	w.mu.Unlock()
	return nil
}

func (w *heldWorker) sentTo() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.sent)
}

func (*heldWorker) SNMPHealth() string { return "" }
func (*heldWorker) NmapHealth() string { return "" }

func (w *heldWorker) RunSNMP(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
	var ips []string
	var answers []sensorlink.SNMPAnswer
	for _, t := range j.Targets {
		ips = append(ips, t.IP)
		answers = append(answers, sensorlink.SNMPAnswer{Target: t.IP, Status: sensorlink.SNMPStatusNoAnswer})
	}
	if err := w.hold(ctx, ips...); err != nil {
		return nil, err
	}
	return answers, nil
}

func (w *heldWorker) Probe(ctx context.Context, argv []string) (sensoractive.Output, error) {
	if err := w.hold(ctx, argv[len(argv)-1]); err != nil {
		return sensoractive.Output{}, err
	}
	return sensoractive.Output{}, errors.New("held worker: no output")
}

// midRun is what happens on the wire while a job for the device at ip (MAC mac) is held: another machine takes the address, or the
// device itself moves to another one (it then left the address, which another machine may take next without any device losing it).
var midRun = map[string]func(s *stack, t *testing.T, ip, mac string){
	"another device takes the address": func(s *stack, t *testing.T, ip, _ string) { s.seen(t, ip, "3c:22:fb:00:09:99", "") },
	"the device moves":                 func(s *stack, t *testing.T, _, mac string) { s.seen(t, "192.168.10.77", mac, "") },
}

// #874, through the real inventory, bus and sensor-active: while a Check now of the approved switch at .205 waits
// for the worker, a new machine (another MAC, nobody approved it) takes .205, or the switch moves away from it. The inventory
// announces the change, the batch is cancelled before the worker sends (the bus is synchronous: Record returns after the reactions
// ran), and the community never reaches .205. A new check is refused too: the switch's read address was its IP, which it no longer
// holds.
func TestWiringSNMPStopsWhenTheDeviceLeavesTheAddress(t *testing.T) {
	t.Parallel()
	for name, happen := range midRun {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newStack(t)
			w := newHeldWorker()
			svc, err := newSensorActive(context.Background(), *s.d, w, nil)
			if err != nil {
				t.Fatal(err)
			}
			s.saveScope(t)
			const ip, mac = "192.168.10.205", "3c:22:fb:00:02:05"
			sw := s.seen(t, ip, mac, "switch")
			if err := s.d.Inventory.Approve(t.Context(), "it@acme.example", sw); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.SetSNMP(t.Context(), "admin@acme.example", sw, sensoractive.SNMPInput{Version: "v2c", Community: secrets.NewValue("community-874")}); err != nil {
				t.Fatal(err)
			}
			type out struct {
				res sensoractive.SNMPCheckResult
				err error
			}
			done := make(chan out, 1)
			go func() {
				res, err := svc.CheckSNMP(context.Background(), "admin@acme.example", sw)
				done <- out{res, err}
			}()
			<-w.started
			happen(s, t, ip, mac)
			close(w.proceed)
			got := <-done
			var ae *apierr.Error
			if !errors.As(got.err, &ae) || ae.Code != "stopped" {
				t.Fatalf("the held test ended with %+v, %v; want 409 stopped", got.res, got.err)
			}
			if sent := w.sentTo(); len(sent) != 0 {
				t.Fatalf("the community went to %v after the switch left the address", sent)
			}
			s.seen(t, ip, "3c:22:fb:00:09:99", "") // a newcomer at .205 (already there in the first case)
			res, err := svc.CheckSNMP(t.Context(), "admin@acme.example", sw)
			if err != nil || res.OK || len(w.sentTo()) != 0 {
				t.Fatalf("a check after the move: %+v, %v, sent %v; want a refusal and nothing sent", res, err, w.sentTo())
			}
		})
	}
}

// #874: the same for an nmap scan of a device: the run stops before the probe goes out.
func TestWiringNmapStopsWhenTheDeviceLeavesTheAddress(t *testing.T) {
	t.Parallel()
	for name, happen := range midRun {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newStack(t)
			s.d.Clock = func() time.Time { return time.Date(2026, 11, 9, 2, 0, 0, 0, hcmZone) } // Monday 02:00, inside 01:00-05:00
			w := newHeldWorker()
			svc, err := newSensorActive(context.Background(), *s.d, w, nil)
			if err != nil {
				t.Fatal(err)
			}
			s.saveScope(t)
			const ip, mac = "192.168.10.20", "3c:22:fb:00:00:20"
			srv := s.seen(t, ip, mac, "server")
			done := make(chan error, 1)
			go func() { done <- svc.ScanDevice(context.Background(), srv, "test") }()
			<-w.started
			happen(s, t, ip, mac)
			close(w.proceed)
			if err := <-done; !errors.Is(err, sensoractive.ErrStopped) {
				t.Fatalf("the held scan ended with %v; want ErrStopped", err)
			}
			if sent := w.sentTo(); len(sent) != 0 {
				t.Fatalf("nmap probed %v after the device left the address", sent)
			}
		})
	}
}
