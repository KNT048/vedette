package sensoractive

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/knt048/vedette/core/localnet"
	"github.com/knt048/vedette/core/sensorlink"
)

// SNMP reads as the third kind of job (D-512, sensor-protocol.md 6.4, protocol 5). The Service is the only caller: it has checked the
// scope, the consent, the device's approval and the credential's own scope and written the probe row before it calls RunSNMP. The
// worker in the scan container sends the GETs; what comes back is checked here against the job and parsed by the Service, fail
// closed (the worker talked to devices an attacker may control, and may itself be compromised: SYS-6).

// ErrSNMPUnavailable says nothing was sent: the worker cannot take an snmp job now (no heartbeat, or a worker of protocol 4).
var ErrSNMPUnavailable = errors.New("sensoractive: snmp_unavailable")

// SNMPReader is how the Service sends SNMP reads; *Dispatcher implements it, tests put a fake in Config.SNMP.
type SNMPReader interface {
	// SNMPHealth is "" when an snmp job can be sent now, else what the person is told.
	SNMPHealth() string
	// RunSNMP sends the job and returns one answer per target the worker got to, each checked against the job.
	RunSNMP(ctx context.Context, job sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error)
}

var _ SNMPReader = (*Dispatcher)(nil)

// SNMPHealth implements SNMPReader.
func (d *Dispatcher) SNMPHealth() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.expireLocked(now)
	switch {
	case !d.haveBeat:
		return "the scan worker has not reported since core started; SNMP reads run once it does"
	case !d.fresh(now):
		return "the scan worker has not reported for 90 seconds; SNMP reads cannot run until it does"
	case !d.snmp:
		return "the scan worker is older than this version of Vedette and cannot read SNMP; SNMP reads run once " + d.imageFix()
	case d.snmpSlot.overrun != "":
		return "the scan worker ran an SNMP job past its time limit; core has told it to stop, and SNMP reads wait until it has"
	}
	return ""
}

// RunSNMP implements SNMPReader.
func (d *Dispatcher) RunSNMP(ctx context.Context, job sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
	if err := checkSNMPJob(&job); err != nil {
		return nil, fmt.Errorf("sensoractive: %w", err)
	}
	if msg := d.SNMPHealth(); msg != "" {
		return nil, fmt.Errorf("%w: %s", ErrSNMPUnavailable, msg)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec := job
	spec.Credentials, spec.Targets = slices.Clone(job.Credentials), slices.Clone(job.Targets)
	j := &djob{spec: sensorlink.Job{ID: randomHex(), Kind: sensorlink.KindSNMP, SNMP: &spec}}
	if err := d.await(ctx, d.snmpSlot, j); err != nil {
		if errors.Is(err, ErrWorkerUnavailable) {
			return nil, fmt.Errorf("%w: %w", ErrSNMPUnavailable, err)
		}
		return nil, err
	}
	if j.err != nil {
		return nil, j.err
	}
	res := j.res
	switch {
	case res.Status == "refused":
		d.log.ErrorContext(ctx, "sensor_active_worker_refused_job", "reason", res.Reason) // core and worker disagree on the grammar
		return nil, fmt.Errorf("%w (%s)", ErrWorkerRefused, res.Reason)
	case res.XML() != nil || res.XMLB64 != "" || res.JSONL() != nil || res.JSONLB64 != "" || len(res.HostErrors) > 0:
		return nil, fmt.Errorf("%w: nmap or nuclei output on an snmp job", ErrResultRejected)
	case res.Status != "done":
		return nil, fmt.Errorf("sensoractive: the worker reported %s (%s)", res.Status, res.Reason)
	}
	for _, a := range res.SNMP {
		i := slices.IndexFunc(job.Targets, func(t sensorlink.SNMPTarget) bool { return t.IP == a.Target })
		if i < 0 || !slices.Contains(job.Targets[i].Credentials, a.Credential) {
			return nil, fmt.Errorf("%w: an snmp answer for a target or a credential the job did not name", ErrResultRejected)
		}
	}
	return res.SNMP, nil
}

// checkSNMPJob is the grammar of the wire (sensorlink.CheckSNMPJob) and every target a local address (core/localnet, as nmap's).
func checkSNMPJob(j *sensorlink.SNMPJob) error {
	if err := sensorlink.CheckSNMPJob(j); err != nil {
		return err
	}
	for _, t := range j.Targets {
		if a, err := netip.ParseAddr(t.IP); err != nil || !localnet.Addr(a) {
			return fmt.Errorf("snmp target %q is not a local address", t.IP)
		}
	}
	return nil
}
