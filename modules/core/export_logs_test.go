package core

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/logexport"
)

// LogSourcesForTest is the registry behind GET /core/logs/export: external tests register fake sources on it.
func (h *APIHandlers) LogSourcesForTest() *logexport.Registry { return h.logs }

// SetLogsCapForTest lowers the size cap of the export.
func (h *APIHandlers) SetLogsCapForTest(n int64) { h.logsCap = n }

// SetLogsGapForTest sets the minimum time between two export starts (negative = no limit).
func (h *APIHandlers) SetLogsGapForTest(d time.Duration) { h.logsGap = d }

// SetLogsDirForTest sets the spool directory of the export.
func (h *APIHandlers) SetLogsDirForTest(dir string) { h.logsDir = dir }

// A read error after the 200 and part of the file are out must break the download: a clean end would look like a whole file.
func TestDownloadAbortsTheConnectionOnAReadErrorAfterTheFirstByte(t *testing.T) {
	t.Parallel()
	reg := logexport.New()
	reg.Register("honeypot", func(_ context.Context, _, _ time.Time, w io.Writer) error {
		for range 3000 {
			if _, err := io.WriteString(w, `{"a":"`+strings.Repeat("x", 100)+"\"}\n"); err != nil {
				return err
			}
		}
		return nil
	})
	exp, err := reg.Build(t.Context(), logexport.Request{Categories: []string{"honeypot"}, Format: logexport.JSON, MaxBytes: 1 << 24, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	freed := false
	d := &download{exp: exp, release: func() { freed = true }}
	buf := make([]byte, 4096)
	if _, err := d.Read(buf); err != nil {
		t.Fatal(err)
	}
	_ = exp.Close() // the spool vanishes under the reader: the next chunk cannot be read
	defer func() {
		if p := recover(); p != http.ErrAbortHandler { //nolint:errorlint // net/http documents comparing the value itself
			t.Fatalf("recovered %v, want http.ErrAbortHandler", p)
		}
		_ = d.Close()
		if !freed {
			t.Fatal("Close did not give the export slot back")
		}
	}()
	for {
		if _, err := d.Read(buf); err != nil {
			t.Fatalf("a read error before the end must abort, got %v", err)
		}
	}
}

// A read error before any byte went out is an ordinary error (the handler can still answer 500).
func TestDownloadReadErrorBeforeTheFirstByteIsAnError(t *testing.T) {
	t.Parallel()
	reg := logexport.New()
	exp, err := reg.Build(t.Context(), logexport.Request{Categories: []string{"honeypot"}, Format: logexport.JSON, MaxBytes: 1 << 20, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	d := &download{exp: exp, release: func() {}}
	if _, err := io.ReadAll(d); err != nil {
		t.Fatalf("an export with no source reads clean: %v", err)
	}
	_ = d.Close()
}

// SetExportCapForTest lowers the size cap of /core/data/export.
func (h *APIHandlers) SetExportCapForTest(n int64) { h.exportCap = n }

// CheckDataFilesForTest runs the check NewAPIHandlers makes on HandlersConfig.DataFiles.
func CheckDataFilesForTest(names []string) error { return checkDataFiles(names) }

// The tables of the test module of handlers_data_test.go are classified like those of a real module: columns that look like a secret
// are skipped, the rest is exported. Done once at init, before any test runs, so the parallel tests only read the policy.
func init() {
	for tbl, p := range map[string]tablePolicy{
		"tm_parent": {export: "id name"},
		"tm_child":  {export: "id parent_id note last4 secret_last4", skip: "api_secret token_hash blobby"},
		"tm_seed":   {export: "id v"},
		"tm_log":    {export: "seq line"},
	} {
		exportPolicy[tbl] = p
		exportClasses[tbl] = classesOf(p)
	}
}

// AuditExportPageForTest is how many rows GET /core/audit/export reads per query.
const AuditExportPageForTest = auditExportPage
