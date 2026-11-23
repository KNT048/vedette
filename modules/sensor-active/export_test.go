package sensoractive

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

// The driver looks for devices waiting for their turn every second in tests, not every minute.
func init() { sweepTurn = time.Second }

// SetBeforeSNMPBatch makes fn run as every SNMP batch starts, before it registers (a test acting in that window; #855).
func SetBeforeSNMPBatch(s *Service, fn func()) { s.beforeSNMPBatch = fn }

// SNMPJobAt builds the wire job for device asset's saved SNMP settings with its target at ip (snmpJob refuses any address
// but the device's stored read address; a test points it elsewhere).
func SNMPJobAt(ctx context.Context, s *Service, asset string, ip netip.Addr) (sensorlink.SNMPJob, error) {
	r, err := s.snmpRow(ctx, s.db.Reader(), asset)
	if err != nil || r == nil {
		return sensorlink.SNMPJob{}, fmt.Errorf("no settings for %s: %w", asset, err)
	}
	row := *r
	row.ReadFrom = ip // as a target built wrongly would carry it
	return s.snmpJob(ctx, 1, []snmpTarget{{asset: asset, ip: ip, row: row}})
}

// ErrSNMPNotReadAddress is the refusal of a job whose target is not its device's read address.
var ErrSNMPNotReadAddress = errSNMPNotReadAddress

// HoldRunLock takes the lock every nmap run takes before it registers (runMu) and returns its release: a run that starts meanwhile
// waits there, so a test can act between its start and its first look at the lane.
func HoldRunLock(s *Service) (release func()) {
	s.runMu.Lock()
	return s.runMu.Unlock
}

// SetBeforeBoxResume makes fn run right before the box resumes a run it read as waiting (a test acting between that read and the
// resume).
func SetBeforeBoxResume(s *Service, fn func(id string)) { s.beforeBoxResume = fn }

// SetBeforeBackground makes fn run as a scan worker heartbeat's pass is about to be registered with Close.
func SetBeforeBackground(s *Service, fn func()) { s.beforeBackground = fn }

// WaitBackground waits for the heartbeat passes that were started (Close waits for them the same way).
func WaitBackground(s *Service) { s.bg.Wait() }
