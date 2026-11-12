package ops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/knt048/vedette/host/api"
)

// The root write path of the Quadlet units (D-105 (2), spec 18). Root writes into /etc/containers/systemd,
// a tree the installer builds, so everything that leads to it must be root's and closed:
//
//   - the directory and every parent up to "/" is a real directory (no link), owned by root (or the
//     host's owner, which is root in production), and not writable by group or others. There is no
//     exception for a sticky bit (sshd StrictModes has none);
//   - the directory is opened with os.OpenRoot after that check and looked at again through the
//     descriptor, so a swap between the check and the open is caught;
//   - a file is written as a temp file made with O_CREATE|O_EXCL|O_NOFOLLOW, then fsynced, then renamed
//     inside the root, then the directory is fsynced: a link planted at the unit name is never
//     followed (the name is also looked at first and a link there is refused);
//   - the old bytes go to containers/units/<service>.prev before the unit changes, when they differ.

var errUnitUnsafe = errors.New("ops: the Quadlet directory or unit is not safe to write as root")

// unitDirChain checks the directory of the units and each parent up to "/" (Deps.ChainTop in tests). It
// returns the directory's path and what Lstat said about it. It never creates anything: the installer builds the tree.
func (o *Ops) unitDirChain() (string, os.FileInfo, error) {
	var dirInfo os.FileInfo
	base, err := filepath.EvalSymlinks(o.d.Root) // the root prefix is the host's own (a test seam, "/" in production)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", errUnitUnsafe, err)
	}
	top := ""
	if o.d.ChainTop != "" {
		if top, err = filepath.EvalSymlinks(o.d.ChainTop); err != nil {
			return "", nil, fmt.Errorf("%w: %w", errUnitUnsafe, err)
		}
	}
	dir := filepath.Join(base, unitsRel)
	trusted := func(uid uint32) bool { return int(uid) == 0 || int(uid) == o.cfg.OwnerUID }
	for d := dir; ; d = filepath.Dir(d) {
		st, err := os.Lstat(d)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %w", errUnitUnsafe, err)
		}
		if d == dir {
			dirInfo = st
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		switch {
		case st.Mode()&os.ModeSymlink != 0 || !st.IsDir():
			return "", nil, fmt.Errorf("%w: %s is not a real directory", errUnitUnsafe, d)
		case !ok || !trusted(sys.Uid):
			return "", nil, fmt.Errorf("%w: %s is not owned by root", errUnitUnsafe, d)
		case st.Mode().Perm()&0o022 != 0:
			return "", nil, fmt.Errorf("%w: %s can be written by group or others", errUnitUnsafe, d)
		}
		if d == filepath.Dir(d) || (top != "" && d == top) {
			break
		}
	}
	return dir, dirInfo, nil
}

// openUnitDir checks the chain and opens the directory as a root. The descriptor is the same
// directory the check saw.
func (o *Ops) openUnitDir() (*os.Root, error) {
	dir, lst, err := o.unitDirChain()
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnitUnsafe, err)
	}
	st, err := r.Stat(".")
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("%w: %w", errUnitUnsafe, err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !os.SameFile(lst, st) || !ok || (int(sys.Uid) != 0 && int(sys.Uid) != o.cfg.OwnerUID) || st.Mode().Perm()&0o022 != 0 {
		_ = r.Close()
		return nil, fmt.Errorf("%w: the directory changed while it was opened", errUnitUnsafe)
	}
	return r, nil
}

// readUnit reads a service's unit file (no link, regular file, at most maxUnitSize bytes).
func (o *Ops) readUnit(service string) ([]byte, fileState) {
	return o.readNoFollowIn(unitsRel, unitFileName(service), maxUnitSize)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// prevDirRel is where the bytes a unit had before its last change are kept, under the state directory.
func (o *Ops) prevName(service string) string { return service + ".prev" }

// writePrev keeps old as containers/units/<service>.prev (0600, atomic).
func (o *Ops) writePrev(service string, old []byte) error {
	return writeFileAtomic(o.stateFile("containers", "units", o.prevName(service)), old, 0o600)
}

// readPrev reads the saved previous bytes; fileAbsent when there are none.
func (o *Ops) readPrev(service string) ([]byte, fileState) {
	r, err := os.OpenRoot(o.stateFile("containers", "units"))
	if err != nil {
		return nil, fileAbsent
	}
	defer func() { _ = r.Close() }()
	return readNoFollow(r, o.prevName(service), maxUnitSize)
}

// writeUnit puts text in place as the unit of service. When keepPrev is set and the file holds other
// bytes, those go to .prev first, and a failure there stops the write (fail closed). A link, a
// directory or anything else but a regular file at the unit name is refused.
func (o *Ops) writeUnit(service string, text []byte, keepPrev bool) error {
	r, err := o.openUnitDir()
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	name := unitFileName(service)
	old, state := readNoFollow(r, name, maxUnitSize)
	if state == fileBroken {
		return fmt.Errorf("%w: %s is a link, not a regular file, or too large", errUnitUnsafe, name)
	}
	if state == fileOK && bytes.Equal(old, text) {
		return nil
	}
	if keepPrev && state == fileOK {
		if err := o.writePrev(service, old); err != nil {
			return fmt.Errorf("ops: keep the previous unit: %w", err)
		}
	}
	return writeAtomicIn(r, name, text, 0o644)
}

// writeUnitForStart is writeUnit for the paths that start a service (bootstrap, container.start with or without a version): the
// .volume units the service mounts (see ensureVolumeUnits) are put in place first (idempotent). Rollback and the recovery of an
// interrupted change use plain writeUnit: they put back what was there, and a volume unit is not part of what they undo (L5).
func (o *Ops) writeUnitForStart(service string, text []byte) error {
	if service == api.ServiceCore || service == api.ServiceSensor || service == api.ServiceScan || service == api.ServiceHoneypot {
		r, err := o.openUnitDir()
		if err != nil {
			return err
		}
		err = o.ensureVolumeUnits(r, service)
		_ = r.Close()
		if err != nil {
			return err
		}
	}
	return o.writeUnit(service, text, true) // the old bytes go to .prev, like every unit change that is not a revert
}

// errVolumeOwner: a credential .volume unit the host wrote names another core_uid or sensor_gid than host.conf gives now (D-316 (9)).
// Quadlet sets User= and Group= only when it creates the volume, so rewriting the unit would change nothing on the volume and leave
// core unable to write the bundles; the host never changes the owner of what a container wrote (core can point a root chown of its
// tree at another file with a link it planted), so the change of ids is refused and the RUNBOOK says how to make it by hand.
var errVolumeOwner = errors.New("ops: a credential volume was made for other ids than host.conf gives now")

// volumeOwnerText is the message of the refusal (unit_unsafe) for errVolumeOwner.
const volumeOwnerText = "host.conf gives another core_uid or sensor_gid than the sensor credential volumes were made for; Podman does not change the owner of an existing volume and the host does not either. Put the ids back in host.conf, or change the owner by hand as RUNBOOK section 3 says."

// volumeOwnerChanged returns the name of a credential .volume unit the host wrote for other ids than host.conf gives now ("" when
// there is none; a missing, odd or hand-edited file is not this refusal: the write path deals with it).
func (o *Ops) volumeOwnerChanged() string {
	r, err := o.openUnitDir()
	if err != nil {
		return "" // the caller refuses an unsafe directory on its own
	}
	defer func() { _ = r.Close() }()
	return volumeOwnerChangedIn(r, o.cfg.CoreUID, o.cfg.SensorGID)
}

func volumeOwnerChangedIn(r *os.Root, coreUID, sensorGID int) string {
	for _, role := range credsRoles {
		text, st := readNoFollow(r, volumeFileName(role), maxUnitSize)
		if st != fileOK {
			continue
		}
		if u, g, ok := volumeIDs(role, text); ok && (u != coreUID || g != sensorGID) {
			return volumeFileName(role)
		}
	}
	return ""
}

// ensureVolumeUnits puts the .volume units a service mounts in place in the opened Quadlet directory: the two credential volumes
// for core, sensor and scan (constant text, host.conf ids; see renderVolume) and the honeypot log volume for core and honeypot. A unit that already holds the right bytes is not touched; a link or odd
// file at its name is refused. The text never depends on a service or an image, so it needs no .prev and no journal: writing it again is always right.
func (o *Ops) ensureVolumeUnits(r *os.Root, service string) error {
	type vol struct {
		name string
		text []byte
	}
	var vols []vol
	if service != api.ServiceHoneypot { // the honeypot mounts no credential volume
		for _, role := range credsRoles {
			text, err := renderVolume(role, o.cfg.CoreUID, o.cfg.SensorGID)
			if err != nil {
				return err // errBadFill: host.conf does not give usable ids (host_conf_incomplete), not an unsafe directory
			}
			vols = append(vols, vol{volumeFileName(role), text})
		}
		if name := volumeOwnerChangedIn(r, o.cfg.CoreUID, o.cfg.SensorGID); name != "" { // before any write: all or nothing
			return fmt.Errorf("%w: %s: %w", errUnitUnsafe, name, errVolumeOwner)
		}
	}
	if service == api.ServiceCore || service == api.ServiceHoneypot { // the two that mount the honeypot log volume (D-318)
		vols = append(vols, vol{hpLogVolumeFileName, hpLogVolumeText})
	}
	for _, v := range vols {
		name, text := v.name, v.text
		old, state := readNoFollow(r, name, maxUnitSize)
		switch {
		case state == fileBroken:
			return fmt.Errorf("%w: %s is a link, not a regular file, or too large", errUnitUnsafe, name)
		case state == fileOK && bytes.Equal(old, text):
			continue
		}
		if err := writeAtomicIn(r, name, text, 0o644); err != nil {
			return err
		}
	}
	return nil
}
