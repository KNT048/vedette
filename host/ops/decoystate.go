package ops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/knt048/vedette/host/api"
)

// hp/decoys.json (spec 18): what the host last put in the honeypot namespace. It is the host's own
// state, but it is read like hostile input (D-87 style): a size cap, strict decoding (unknown fields
// and trailing data refused), and every value checked, because a corrupt file would otherwise reach
// an ip command line.

const maxDecoysFile = 64 << 10

type decoyEntry struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Table int    `json:"table"` // the per-IP routing table, 100 to 131, kept for the life of the decoy
	Iface string `json:"iface"` // the card the macvlan sits on when it was made
}

type decoyFile struct {
	Decoys []decoyEntry `json:"decoys"`
}

func (e decoyEntry) addr() netip.Addr { a, _ := netip.ParseAddr(e.IP); return a }

var errDecoysInvalid = errors.New("ops: hp/decoys.json is not valid")

// parseDecoys decodes and validates the file's bytes.
func parseDecoys(b []byte) ([]decoyEntry, error) {
	if len(b) > maxDecoysFile {
		return nil, errDecoysInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f decoyFile
	if err := dec.Decode(&f); err != nil {
		return nil, errDecoysInvalid
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errDecoysInvalid
	}
	if len(f.Decoys) > api.MaxDecoys {
		return nil, errDecoysInvalid
	}
	ips, macs, tables := map[string]bool{}, map[string]bool{}, map[int]bool{}
	for _, e := range f.Decoys {
		a, err := netip.ParseAddr(e.IP)
		hw, merr := net.ParseMAC(e.MAC)
		switch {
		case err != nil || !a.Is4() || a.String() != e.IP || !unicast4(a),
			merr != nil || len(hw) != 6 || hw.String() != e.MAC || hw[0]&0x01 != 0,
			!tableOK(e.Table), !validIfaceName(e.Iface),
			ips[e.IP], macs[e.MAC], tables[e.Table]:
			return nil, errDecoysInvalid
		}
		ips[e.IP], macs[e.MAC], tables[e.Table] = true, true, true
	}
	return f.Decoys, nil
}

func (o *Ops) decoysPath() string { return o.stateFile("hp", "decoys.json") }

// readDecoys loads the state. A missing file is no decoys. A file that is a symlink, not a regular
// file, too large or invalid is errDecoysInvalid (never followed, never trusted).
func (o *Ops) readDecoys() ([]decoyEntry, error) {
	f, err := os.OpenFile(o.decoysPath(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errDecoysInvalid
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxDecoysFile {
		return nil, errDecoysInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, maxDecoysFile+1))
	if err != nil {
		return nil, errDecoysInvalid
	}
	return parseDecoys(b)
}

// loadDecoys is readDecoys for the writers: an invalid file is set aside as decoys.json.invalid (the
// evidence stays, nothing is destroyed) and the state starts empty; the links of the namespace that
// no entry owns are then removed by the next reconcile. The second result says it happened.
func (o *Ops) loadDecoys() (list []decoyEntry, quarantined bool, err error) {
	list, err = o.readDecoys()
	if err == nil {
		return list, false, nil
	}
	if !errors.Is(err, errDecoysInvalid) {
		return nil, false, err
	}
	if rerr := os.Rename(o.decoysPath(), o.decoysPath()+".invalid"); rerr != nil {
		return nil, false, fmt.Errorf("ops: set aside hp/decoys.json: %w", rerr)
	}
	return nil, true, nil
}

// saveDecoys writes the state atomically (0600) in the order of the table numbers.
func (o *Ops) saveDecoys(list []decoyEntry) error {
	if err := privDir(filepath.Dir(o.decoysPath()), o.cfg.OwnerUID); err != nil {
		return err
	}
	l := slices.Clone(list)
	slices.SortFunc(l, func(a, b decoyEntry) int { return a.Table - b.Table })
	if l == nil {
		l = []decoyEntry{}
	}
	return writeJSONAtomic(o.decoysPath(), decoyFile{Decoys: l})
}

// freeTable is the lowest routing table, 100 to 131, no decoy uses. Tables are stored with the
// decoy, so one decoy keeps its table until it is removed and two never share one; 32 decoys at
// most and 32 tables, so a free table exists whenever the limit allows another decoy.
func freeTable(list []decoyEntry) (int, bool) {
	for t := hpTableFirst; t < hpTableFirst+api.MaxDecoys; t++ {
		if !slices.ContainsFunc(list, func(e decoyEntry) bool { return e.Table == t }) {
			return t, true
		}
	}
	return 0, false
}
