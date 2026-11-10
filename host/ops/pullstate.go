package ops

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

// What container.pull keeps on disk (spec 6.7, D-104, D-108 L2, D-130), all under the state directory,
// written atomically (temp file, fsync, rename) and read strictly (no unknown field, no trailing data,
// regular files only, 8 MiB at most):
//
//	releases/index.json                the newest index the host accepted: the raw bytes and the signature,
//	                                   and the revocations carried with it (they are not in the signed bytes)
//	containers/pulled-<service>.json   the version pulled last: {version, digest, key_id, manifest}
//
// The stored index is the only source of revocation (D-104 (2)). It is re-verified every time it is
// loaded: VerifyIndex runs again on the raw bytes with the carried list as the stored index, so a
// file that no longer verifies is not believed, and the host refuses to pull (release_state_invalid)
// instead of guessing a "first ever" state that would reopen the replay and freeze attacks.

const (
	indexStateFile = "index.json"
	// maxCarried is the cap of internal/release on the revocations a stored index holds.
	maxCarried = 4096
)

// indexState is releases/index.json.
type indexState struct {
	Index   string               `json:"index"`   // base64 of index.json
	Sig     string               `json:"sig"`     // base64 of index.json.minisig
	Carried []release.Revocation `json:"carried"` // idx.Revoked of the value VerifyIndex returned
}

// readStrict decodes one JSON value from a regular file of the host's own state. A missing file
// reports exists false and no error.
func readStrict(path string, v any) (exists bool, err error) {
	f, _, err := openRegularNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return true, err
	}
	if len(b) > maxStateFile {
		return true, errors.New("ops: state file too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return true, fmt.Errorf("ops: state file does not parse: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return true, errors.New("ops: state file has trailing data")
	}
	return true, nil
}

// sweepTmp removes the temp files (".tmp-*") that a write cut short left in a state directory; the
// directory is the host's own and private, and only plain files and links are removed, never followed.
func (o *Ops) sweepTmp(dirs ...string) {
	for _, d := range dirs {
		ents, err := os.ReadDir(o.stateFile(d))
		if err != nil {
			continue
		}
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".tmp-") && !e.IsDir() {
				_ = os.Remove(o.stateFile(d, e.Name()))
			}
		}
	}
}

// loadIndex returns the stored index, verified again; nil when none was ever stored.
func (o *Ops) loadIndex(trust release.Trust) (*release.Index, error) {
	var st indexState
	exists, err := readStrict(o.stateFile("releases", indexStateFile), &st)
	if !exists {
		return nil, nil //nolint:nilnil // no stored index is a state, not an error
	}
	if err != nil {
		return nil, err
	}
	if len(st.Carried) > maxCarried {
		return nil, fmt.Errorf("ops: the stored index carries more than %d revocations", maxCarried)
	}
	raw, err1 := decodeDoc(st.Index, release.MaxDocBytes)
	sig, err2 := decodeDoc(st.Sig, release.MaxSigBytes)
	if err := errors.Join(err1, err2); err != nil {
		return nil, errors.New("ops: the stored index is not usable")
	}
	// Retired keys of the build may have signed it (a key rotation keeps the floor and revocations).
	idx, err := release.VerifyStoredIndex(raw, sig, trust, st.Carried)
	if err != nil {
		return nil, fmt.Errorf("ops: the stored index does not verify: %w", err)
	}
	return idx, nil
}

// saveIndex stores idx, the value VerifyIndex returned for raw and sig.
func (o *Ops) saveIndex(raw, sig []byte, idx *release.Index) error {
	st := indexState{
		Index: base64.StdEncoding.EncodeToString(raw), Sig: base64.StdEncoding.EncodeToString(sig),
		Carried: idx.Revoked,
	}
	if st.Carried == nil {
		st.Carried = []release.Revocation{}
	}
	return writeJSONAtomic(o.stateFile("releases", indexStateFile), st)
}

// pulledRecord is containers/pulled-<service>.json: what the last successful container.pull of the
// service verified. Manifest and ManifestSig are the signed bytes (base64) so that a later command
// (container.start with a version, rollback) can verify them again against the stored index.
type pulledRecord struct {
	Service     string    `json:"service"`
	Version     string    `json:"version"`
	Digest      string    `json:"digest"`
	KeyID       string    `json:"key_id"` // minisign key that signed the manifest
	Size        int64     `json:"size"`
	PulledAt    time.Time `json:"pulled_at"`
	Manifest    string    `json:"manifest"`
	ManifestSig string    `json:"manifest_sig"`
}

var keyIDRE = regexp.MustCompile(`^[0-9A-F]{16}$`)

func pulledName(service string) string { return "pulled-" + service + ".json" }

func (r pulledRecord) valid(service string) bool {
	return r.Service == service && len(r.Version) <= 64 && tagVersionRE.MatchString(r.Version) && digestRE.MatchString(r.Digest) &&
		keyIDRE.MatchString(r.KeyID) && r.Size >= 0 && !r.PulledAt.IsZero() && r.Manifest != "" && r.ManifestSig != ""
}

// loadPulled reads the record of a service. ok is false when there is none or it is not valid (a
// damaged record is no record: the version then reads as not pulled, never as a guess).
func (o *Ops) loadPulled(service string) (pulledRecord, bool) {
	if !knownService(service) {
		return pulledRecord{}, false
	}
	var r pulledRecord
	exists, err := readStrict(o.stateFile("containers", pulledName(service)), &r)
	if !exists {
		return pulledRecord{}, false
	}
	if err != nil || !r.valid(service) {
		o.log.Warn("the record of the pulled version is not valid; ignoring it", "service", service)
		return pulledRecord{}, false
	}
	return r, true
}

func (o *Ops) savePulled(r pulledRecord) error {
	if !r.valid(r.Service) {
		return errors.New("ops: refusing to record an invalid pulled version")
	}
	return writeJSONAtomic(o.stateFile("containers", pulledName(r.Service)), r)
}

// latestPulled is the state/containers view of the record.
func (o *Ops) latestPulled(service string) *api.ContainerVersion {
	r, ok := o.loadPulled(service)
	if !ok {
		return nil
	}
	v := r.Version
	return &api.ContainerVersion{Version: &v, Digest: r.Digest}
}
