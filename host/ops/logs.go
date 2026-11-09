package ops

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// Limits of logs.export (spec 6.13, section 10).
const (
	maxExportRange   = 31 * 24 * time.Hour
	maxExportBytes   = 256 << 20 // of journal text, before compression
	exportKeep       = 24 * time.Hour
	maxJournalLine   = 1 << 20
	exportSweepEvery = time.Hour
)

var unitArgRE = regexp.MustCompile(`^[a-z][a-z-]{0,40}$`)

// cmdLogsExport is logs.export (spec 6.13).
func (o *Ops) cmdLogsExport() server.Command {
	return server.Define(server.Spec[api.LogsExportArgs]{
		Name: api.CmdLogsExport, Write: true, Timeout: 10 * time.Minute,
		Validate: func(a *api.LogsExportArgs) error {
			if len(a.Units) == 0 || len(a.Units) > len(journalUnits) {
				return server.Invalid("units", "must list 1 to 6 units")
			}
			for _, u := range a.Units {
				if !unitArgRE.MatchString(u) {
					return server.Invalid("units", "a unit name is not valid")
				}
			}
			since, until, err := parseRange(*a)
			if err != nil {
				return err
			}
			a.Since, a.Until = since.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano)
			return nil
		},
		Check: func(_ context.Context, a api.LogsExportArgs) error {
			for _, u := range a.Units {
				if !slices.Contains(journalUnits, u) {
					return refuse412(api.CodeUnitUnknown, "That unit is not one of the Vedette units.")
				}
			}
			since, until, _ := parseRange(a)
			if until.Sub(since) > maxExportRange {
				return refuse412(api.CodeRangeTooLarge, "The time range is longer than 31 days.")
			}
			return nil
		},
		Run: func(ctx context.Context, rc *server.RunContext, a api.LogsExportArgs) (any, error) {
			since, until, _ := parseRange(a)
			res, err := o.exportLogs(ctx, rc, dedupe(a.Units), since, until)
			if err != nil {
				return nil, err
			}
			return res, nil
		},
	})
}

func dedupe(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

func parseRange(a api.LogsExportArgs) (since, until time.Time, err *server.ArgsError) {
	s, e1 := time.Parse(time.RFC3339, a.Since)
	u, e2 := time.Parse(time.RFC3339, a.Until)
	switch {
	case e1 != nil:
		return s, u, server.Invalid("since", "must be an RFC 3339 time")
	case e2 != nil:
		return s, u, server.Invalid("until", "must be an RFC 3339 time")
	case s.Year() < 2000 || u.Year() > 2100:
		return s, u, server.Invalid("since", "must be between the years 2000 and 2100")
	case !u.After(s):
		return s, u, server.Invalid("until", "must be after since")
	}
	return s.UTC(), u.UTC(), nil
}

// journalTime is the format journalctl reads without guessing a time zone.
func journalTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") + " UTC" }

type exportRecord struct {
	ID        string    `json:"export_id"`
	CreatedAt time.Time `json:"created_at"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
}

type exportIndex struct {
	Exports []exportRecord `json:"exports"`
}

func (o *Ops) exportDir() string { return o.stateFile("exports") }

func (o *Ops) exportPath(id string) string { return filepath.Join(o.exportDir(), id+".jsonl.gz") }

func (o *Ops) loadExportsLocked() exportIndex {
	var ix exportIndex
	if err := readJSONFile(filepath.Join(o.exportDir(), "index.json"), &ix); err != nil && !errors.Is(err, os.ErrNotExist) {
		o.log.Warn("export index is unreadable; starting empty")
		return exportIndex{}
	}
	return ix
}

func (o *Ops) saveExportsLocked(ix exportIndex) error {
	if ix.Exports == nil {
		ix.Exports = []exportRecord{}
	}
	return writeJSONAtomic(filepath.Join(o.exportDir(), "index.json"), ix)
}

// exportLogs reads each unit's journal with the fixed journalctl argv, filters secrets out of every
// line, and writes one gzip file of JSON lines. A run that would pass the size limit stops and
// refuses (output_too_large): the file is never cut silently.
func (o *Ops) exportLogs(ctx context.Context, rc *server.RunContext, units []string, since, until time.Time) (api.LogsExportResult, error) {
	o.sweepExports()
	id, err := randomHex(16)
	if err != nil {
		return api.LogsExportResult{}, err
	}
	tmp, err := os.CreateTemp(o.stateFile("tmp"), "ex-")
	if err != nil {
		return api.LogsExportResult{}, fail("export_failed", "The export could not be started.")
	}
	tmpPath := tmp.Name()
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	_ = tmp.Chmod(0o600)
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(tmp, h)}
	zw := gzip.NewWriter(cw)
	var total int64
	lines := 0
	untilCeil := until.Truncate(time.Second)
	if untilCeil.Before(until) {
		untilCeil = untilCeil.Add(time.Second)
	}
	for i, u := range units {
		rc.Log("Reading the journal of " + u)
		res, code, err := o.exec(ctx, binJournal, "-u", u, "--since", journalTime(since), "--until", journalTime(untilCeil), "-o", "json", "--no-pager")
		if err != nil {
			return api.LogsExportResult{}, err
		}
		if res.Truncated {
			return api.LogsExportResult{}, refuse412(api.CodeOutputTooLarge, "The logs are larger than 256 MiB for this range; choose a shorter range or fewer units.")
		}
		if code != 0 {
			return api.LogsExportResult{}, fail("journal_failed", fmt.Sprintf("journalctl failed for %s (exit %d).", u, code))
		}
		n, w, err := filterJournal(bytes.NewReader(res.Stdout), zw, o.d.ExportLimit-total)
		total += w
		lines += n
		if errors.Is(err, errTooLarge) {
			return api.LogsExportResult{}, refuse412(api.CodeOutputTooLarge, "The logs are larger than 256 MiB for this range; choose a shorter range or fewer units.")
		}
		if err != nil {
			return api.LogsExportResult{}, fail("export_failed", "The export could not be written.")
		}
		rc.Progress((i + 1) * 90 / len(units))
	}
	if err := zw.Close(); err != nil {
		return api.LogsExportResult{}, fail("export_failed", "The export could not be written.")
	}
	if err := tmp.Sync(); err != nil {
		return api.LogsExportResult{}, fail("export_failed", "The export could not be written.")
	}
	if err := tmp.Close(); err != nil {
		return api.LogsExportResult{}, fail("export_failed", "The export could not be written.")
	}
	rec := exportRecord{ID: id, CreatedAt: o.d.Now().UTC().Truncate(time.Second), Size: cw.n, SHA256: hex.EncodeToString(h.Sum(nil))}
	o.exMu.Lock()
	defer o.exMu.Unlock()
	if err := os.Rename(tmpPath, o.exportPath(id)); err != nil {
		return api.LogsExportResult{}, fail("export_failed", "The export could not be stored.")
	}
	done = true
	ix := o.loadExportsLocked()
	ix.Exports = append(ix.Exports, rec)
	if err := o.saveExportsLocked(ix); err != nil {
		_ = os.Remove(o.exportPath(id))
		return api.LogsExportResult{}, fail("export_failed", "The export could not be stored.")
	}
	rc.Progress(100)
	return api.LogsExportResult{ExportID: id, Size: rec.Size, SHA256: rec.SHA256, Lines: lines}, nil
}

var errTooLarge = errors.New("ops: export is too large")

// filterJournal copies journal JSON lines from r to w, one per line, with secrets redacted. A line
// that is not a JSON object, or longer than 1 MiB, is replaced by a note line saying so (the
// export says what it dropped; it never drops silently). budget is how many bytes of output may
// still be written; going over returns errTooLarge. It returns the number of lines and bytes written.
func filterJournal(r io.Reader, w io.Writer, budget int64) (lines int, written int64, err error) {
	rd := bufio.NewReaderSize(r, 64<<10)
	for {
		line, tooLong, rerr := readJournalLine(rd)
		if len(line) == 0 && !tooLong && rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return lines, written, nil
			}
			return lines, written, rerr
		}
		var out []byte
		switch {
		case tooLong:
			out = []byte(`{"vedette_note":"a journal line longer than 1 MiB was dropped"}`)
		case len(bytes.TrimSpace(line)) == 0:
			out = nil
		default:
			red := RedactJournalLine(line)
			if !json.Valid(red) || !bytes.HasPrefix(bytes.TrimSpace(red), []byte("{")) {
				out = []byte(`{"vedette_note":"a journal line that is not a JSON object was dropped"}`)
			} else {
				out = bytes.TrimSpace(red)
			}
		}
		if out != nil {
			if written+int64(len(out))+1 > budget {
				return lines, written, errTooLarge
			}
			if _, werr := w.Write(append(out, '\n')); werr != nil {
				return lines, written, werr
			}
			written += int64(len(out)) + 1
			lines++
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return lines, written, nil
			}
			return lines, written, rerr
		}
	}
}

// readJournalLine reads one line without its newline; a line over maxJournalLine is skipped to its
// end and reported as tooLong.
func readJournalLine(rd *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		part, perr := rd.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(part) > maxJournalLine {
				tooLong, line = true, nil
			} else {
				line = append(line, part...)
			}
		}
		switch {
		case perr == nil:
			return bytes.TrimRight(line, "\r\n"), tooLong, nil
		case errors.Is(perr, bufio.ErrBufferFull):
			continue
		default:
			return bytes.TrimRight(line, "\r\n"), tooLong, perr
		}
	}
}

// sweepExports deletes exports older than 24 hours and files that are not in the index.
func (o *Ops) sweepExports() {
	o.exMu.Lock()
	defer o.exMu.Unlock()
	ix := o.loadExportsLocked()
	now := o.d.Now()
	kept := ix.Exports[:0]
	known := map[string]bool{}
	for _, r := range ix.Exports {
		if now.Sub(r.CreatedAt) >= exportKeep {
			_ = os.Remove(o.exportPath(r.ID))
			continue
		}
		kept = append(kept, r)
		known[r.ID+".jsonl.gz"] = true
	}
	if len(kept) != len(ix.Exports) {
		ix.Exports = kept
		if err := o.saveExportsLocked(ix); err != nil {
			o.log.Warn("could not save the export index")
		}
	}
	if ents, err := os.ReadDir(o.exportDir()); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".jsonl.gz") && !known[e.Name()] {
				_ = os.Remove(filepath.Join(o.exportDir(), e.Name()))
			}
		}
	}
}

// armSweep schedules the next sweep; each sweep arms the one after.
func (o *Ops) armSweep() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sweepOff != nil {
		o.sweepOff()
	}
	o.sweepOff = o.d.AfterFunc(exportSweepEvery, func() {
		o.sweepExports()
		o.armSweep()
	})
}

// exportContent is GET /v1/exports/{id}/content.
func (o *Ops) exportContent(id string) (server.File, error) {
	o.sweepExports()
	o.exMu.Lock()
	ix := o.loadExportsLocked()
	o.exMu.Unlock()
	for _, r := range ix.Exports {
		if r.ID != id {
			continue
		}
		f, st, err := openRegularNoFollow(o.exportPath(id))
		if err != nil || st.Size() != r.Size {
			if f != nil {
				_ = f.Close()
			}
			return server.File{}, server.NewReadError(404, api.CodeExportUnknown, "There is no such export.")
		}
		return server.File{Body: f, Size: r.Size, Name: "vedette-logs-" + r.CreatedAt.Format("20060102T150405Z") + ".jsonl.gz", Type: "application/gzip"}, nil
	}
	return server.File{}, server.NewReadError(404, api.CodeExportUnknown, "There is no such export.")
}
