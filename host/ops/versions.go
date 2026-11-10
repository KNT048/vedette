package ops

import (
	"errors"

	"github.com/knt048/vedette/host/api"
)

// What container.start with a version and container.rollback keep on disk (spec 6.8, 6.10, D-104,
// D-138): containers/versions-<service>.json holds the release a service runs (current) and the one it
// ran before (previous), each with the signed manifest it was verified with, so that rollback can
// verify it again against the stored index. One file, one atomic write: a crash can never leave the
// two records out of step. The record of the running version also remembers the pre_update backup
// made when the service moved into it (core only): the rollback of a core release whose manifest says
// rollback.safe=false restores exactly that backup.
//
// Until the bootstrap of slice 3-8b writes the first current record, a service installed without
// one has an unknown running version: the first container.start with a version records it (nothing
// can be rolled back to yet) and the downgrade and min_upgrade_from checks have nothing to compare.

// versionRecord is a pulledRecord that ran (or runs) as the service's image.
type versionRecord struct {
	pulledRecord
	BackupID string `json:"backup_id,omitempty"` // the pre_update backup made when the service moved into this version
}

// versionState is containers/versions-<service>.json.
type versionState struct {
	Service  string         `json:"service"`
	Current  *versionRecord `json:"current,omitempty"`
	Previous *versionRecord `json:"previous,omitempty"`
}

func versionsName(service string) string { return "versions-" + service + ".json" }

func (r versionRecord) valid(service string) bool {
	return r.pulledRecord.valid(service) && (r.BackupID == "" || hexIDRE.MatchString(r.BackupID))
}

func (s versionState) valid(service string) bool {
	return s.Service == service && (s.Current == nil || s.Current.valid(service)) && (s.Previous == nil || s.Previous.valid(service))
}

// loadVersions reads the state of a service. A missing file is an empty state; a damaged one is an
// empty state too, with a warning (a damaged record is no record: the version reads as unknown and
// nothing can be rolled back, never a guess).
func (o *Ops) loadVersions(service string) versionState {
	empty := versionState{Service: service}
	if !knownService(service) {
		return empty
	}
	var s versionState
	exists, err := readStrict(o.stateFile("containers", versionsName(service)), &s)
	if !exists {
		return empty
	}
	if err != nil || !s.valid(service) {
		o.log.Warn("the record of the running and previous versions is not valid; ignoring it", "service", service)
		return empty
	}
	return s
}

func (o *Ops) saveVersions(s versionState) error {
	if !s.valid(s.Service) || !knownService(s.Service) {
		return errors.New("ops: refusing to record invalid versions")
	}
	return writeJSONAtomic(o.stateFile("containers", versionsName(s.Service)), s)
}

// completeTransition records what a change that worked did to the versions. It is idempotent (the
// host may run it twice: once in the run and once at Start after a crash between the "verified" phase
// and the end of the run) and does nothing for a change that did not take effect (Applied false).
func (o *Ops) completeTransition(t transition) {
	if !t.Applied || t.Version == "" {
		return
	}
	s := o.loadVersions(t.Service)
	switch t.Op {
	case opStart:
		if s.Current != nil && s.Current.Digest == t.Digest {
			return
		}
		rec, ok := o.loadPulled(t.Service)
		if !ok || rec.Digest != t.Digest || rec.Version != t.Version {
			o.log.Warn("the pulled record changed under a version change; the versions are not updated", "service", t.Service)
			return
		}
		next := versionState{Service: t.Service, Current: &versionRecord{pulledRecord: rec, BackupID: t.BackupID}}
		if s.Current != nil && s.Current.Digest == t.FromDigest {
			next.Previous = s.Current // the release that ran until now
		}
		if err := o.saveVersions(next); err != nil {
			o.log.Error("could not record the new version", "service", t.Service, "error", err.Error())
		}
		o.note(api.CmdContainerStart, "versions_recorded", map[string]any{"service": t.Service, "version": t.Version, "digest": t.Digest})
	case opRollback:
		if s.Current != nil && s.Current.Digest == t.Digest {
			return
		}
		if s.Previous == nil || s.Previous.Digest != t.Digest || s.Current == nil || s.Current.Digest != t.FromDigest {
			o.log.Warn("the versions changed under a rollback; they are not updated", "service", t.Service)
			return
		}
		// Swap: the version just left becomes previous, so a second rollback goes back where it started.
		if err := o.saveVersions(versionState{Service: t.Service, Current: s.Previous, Previous: s.Current}); err != nil {
			o.log.Error("could not record the rollback", "service", t.Service, "error", err.Error())
		}
		o.note(api.CmdContainerRollback, "versions_recorded", map[string]any{"service": t.Service, "version": t.Version, "digest": t.Digest})
	}
}

// adoptCurrent records pulled as the running version when the unit already pins its digest and the
// versions know nothing (or something else) about it: the first container.start with a version of a
// service that the bootstrap or an installer set up. Nothing is rolled back to, so previous is dropped.
func (o *Ops) adoptCurrent(rec pulledRecord) {
	s := o.loadVersions(rec.Service)
	if s.Current != nil && s.Current.Digest == rec.Digest {
		return
	}
	if err := o.saveVersions(versionState{Service: rec.Service, Current: &versionRecord{pulledRecord: rec}}); err != nil {
		o.log.Error("could not record the running version", "service", rec.Service, "error", err.Error())
	}
}
