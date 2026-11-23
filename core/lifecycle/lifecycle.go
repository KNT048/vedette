// Package lifecycle keeps what other modules hold about a device consistent with the inventory, in the inventory's own write
// transaction. When the inventory merges two device rows (one machine seen twice), splits an address off a device as a device of its
// own, or deletes a device, it calls every registered
// participant with that transaction before the device row goes: each one moves or removes its own rows there, so either every
// module's rows change with the device or none does (a participant's error rolls the whole write back). Events on the bus still
// announce the change after the commit; they are for notifications, never for integrity.
//
// Rules for a participant:
//   - Write only through tx and only the participant's own tables. Never call db.Write (the one writer connection is held: it
//     would wait for itself) and never publish an event (the write may still roll back). Reads through a reader connection see the
//     state before this write.
//   - A merge loses nothing: a row of From that collides with a row of Into is folded into it (times widened, the people's
//     decisions and history kept), never dropped.
//   - Work that must wait for the commit (caches in memory) goes in the Committed functions.
//
// Participants run in the order they were registered, whether or not their module is switched on: the rows exist either way, and
// a switched-off module must find them consistent when it is switched on again.
package lifecycle

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// Merge is two device rows found to be one machine: From joins Into and is deleted after the participants ran.
type Merge struct {
	From, Into         string
	FromName, IntoName string // the devices' names when they were merged, for notes and audit rows
	Actor              string // the person who merged them; "" for the inventory's own join rules
	// Software maps the id of every software row the merge removed because the other device had the same row to the id of the row
	// that stays (either direction). A software row that only moved from From to Into keeps its id and is not listed.
	Software map[string]string
}

// SoftwareID is the id that stays for software row id after the merge.
func (m Merge) SoftwareID(id string) string {
	if to, ok := m.Software[id]; ok {
		return to
	}
	return id
}

// Split is an address of device From that a person says is another device: Into is the device made for it, with what was read only
// there (the software a merge brought from it, the readings a scan took at that address).
type Split struct {
	From, Into string
	Actor      string // the person who split it
	// Software maps the id of every software line of From whose readings went to Into to Into's line that holds them now, for the
	// lines a module may keep rows by: another line of Into, or the same id when the line went whole (it is Into's now, Gone true).
	Software map[string]SplitLine
}

// SplitLine is where one software line of a split's From went.
type SplitLine struct {
	// Into is the line of the split's Into that took the readings: the line's own id when it went whole.
	Into string
	// Gone says From no longer has the software: no reading is left on its line (now removed). When false, From still reads the
	// software too (another source, or a reading both devices shared): both devices have it.
	Gone bool
}

// Delete is a device removed from the inventory: by a person, or a row the inventory found was never a device.
type Delete struct {
	Device string
	Name   string // the device's name when it was deleted
	Actor  string // "" for the system
}

// FindingFold is a finding folded into another one of the same device and CVE (a merge, or software lines that go): From is deleted
// after the participants ran, Into stays. Modules that keep rows by finding id move them to Into here.
type FindingFold struct {
	From, Into string
}

// LinesDelete is software lines the inventory deletes for good (removed lines past their retention): Lines are their ids, deleted
// after the participants ran. A module that points at a line with a foreign key settles its rows on them here.
type LinesDelete struct {
	Lines []string
}

// Participant is one module's part. Every function may be nil.
type Participant struct {
	Name          string
	DeviceMerged  func(ctx context.Context, tx *sql.Tx, m Merge) error
	DeviceSplit   func(ctx context.Context, tx *sql.Tx, s Split) error
	DeviceDeleted func(ctx context.Context, tx *sql.Tx, d Delete) error
	FindingFolded func(ctx context.Context, tx *sql.Tx, f FindingFold) error
	LinesDeleted  func(ctx context.Context, tx *sql.Tx, l LinesDelete) error
	// MergeCommitted and DeleteCommitted run after the write committed (in-memory state only; they cannot fail it).
	MergeCommitted  func(ctx context.Context, m Merge)
	DeleteCommitted func(ctx context.Context, d Delete)
}

// Hooks is the set of participants. The zero value has none; a nil *Hooks calls nothing.
type Hooks struct {
	mu    sync.RWMutex
	parts []Participant
}

// Register adds p after the participants already registered. A participant without a name, or a second one with the same
// name, is a programming error: it panics.
func (h *Hooks) Register(p Participant) {
	if p.Name == "" {
		panic("lifecycle: a participant needs a name")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, q := range h.parts {
		if q.Name == p.Name {
			panic("lifecycle: participant " + p.Name + " registered twice")
		}
	}
	h.parts = append(h.parts, p)
}

// Names lists the participants in the order they run.
func (h *Hooks) Names() []string {
	var out []string
	for _, p := range h.list() {
		out = append(out, p.Name)
	}
	return out
}

func (h *Hooks) list() []Participant {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]Participant(nil), h.parts...)
}

// DeviceMerged calls every participant's DeviceMerged in tx; the first error stops and is returned (the caller rolls back).
func (h *Hooks) DeviceMerged(ctx context.Context, tx *sql.Tx, m Merge) error {
	for _, p := range h.list() {
		if p.DeviceMerged == nil {
			continue
		}
		if err := p.DeviceMerged(ctx, tx, m); err != nil {
			return fmt.Errorf("lifecycle: %s: merge of a device: %w", p.Name, err)
		}
	}
	return nil
}

// DeviceSplit calls every participant's DeviceSplit in tx, after the inventory moved the address and its readings and before the write
// commits; the first error stops and is returned (the caller rolls back).
func (h *Hooks) DeviceSplit(ctx context.Context, tx *sql.Tx, s Split) error {
	for _, p := range h.list() {
		if p.DeviceSplit == nil {
			continue
		}
		if err := p.DeviceSplit(ctx, tx, s); err != nil {
			return fmt.Errorf("lifecycle: %s: split of a device: %w", p.Name, err)
		}
	}
	return nil
}

// DeviceDeleted calls every participant's DeviceDeleted in tx; the first error stops and is returned (the caller rolls back).
func (h *Hooks) DeviceDeleted(ctx context.Context, tx *sql.Tx, d Delete) error {
	for _, p := range h.list() {
		if p.DeviceDeleted == nil {
			continue
		}
		if err := p.DeviceDeleted(ctx, tx, d); err != nil {
			return fmt.Errorf("lifecycle: %s: delete of a device: %w", p.Name, err)
		}
	}
	return nil
}

// LinesDeleted calls every participant's LinesDeleted in tx; the first error stops and is returned (the caller rolls back).
func (h *Hooks) LinesDeleted(ctx context.Context, tx *sql.Tx, l LinesDelete) error {
	if len(l.Lines) == 0 {
		return nil
	}
	for _, p := range h.list() {
		if p.LinesDeleted == nil {
			continue
		}
		if err := p.LinesDeleted(ctx, tx, l); err != nil {
			return fmt.Errorf("lifecycle: %s: delete of software lines: %w", p.Name, err)
		}
	}
	return nil
}

// FindingFolded calls every participant's FindingFolded in tx; the first error stops and is returned (the caller rolls back).
func (h *Hooks) FindingFolded(ctx context.Context, tx *sql.Tx, f FindingFold) error {
	for _, p := range h.list() {
		if p.FindingFolded == nil {
			continue
		}
		if err := p.FindingFolded(ctx, tx, f); err != nil {
			return fmt.Errorf("lifecycle: %s: fold of a finding: %w", p.Name, err)
		}
	}
	return nil
}

// MergeCommitted calls every participant's MergeCommitted, after the merge's write committed.
func (h *Hooks) MergeCommitted(ctx context.Context, m Merge) {
	for _, p := range h.list() {
		if p.MergeCommitted != nil {
			p.MergeCommitted(ctx, m)
		}
	}
}

// DeleteCommitted calls every participant's DeleteCommitted, after the delete's write committed.
func (h *Hooks) DeleteCommitted(ctx context.Context, d Delete) {
	for _, p := range h.list() {
		if p.DeleteCommitted != nil {
			p.DeleteCommitted(ctx, d)
		}
	}
}
