package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/knt048/vedette/core/store"
)

// e2ePackRoutes is the control route that gives a made-up CVE of the e2e box a confirmed mitigation pack:
//
//	POST /packs/seed {"cve": "CVE-2099-123456"} -> 204
//
// The release key is offline and test keys are refused outside test binaries, so the box cannot load a signed pack (D-345..D-349);
// the load path is covered by mitigation_packs_test.go. This takes the pack of content/mitigation/testdata (the one the web mock and the
// QA spec use), puts the given CVE in its place and writes it into mit_pack through a second connection to the box's database, as a
// developer seed. It writes no audit row and goes through no Loader. It lives in a _test.go file: the production binary has none of it.
func e2ePackRoutes(mux *http.ServeMux, dbPath string) {
	cveRE := regexp.MustCompile(`^CVE-2099-[0-9]{4,7}$`) // a year no real list has reached: never a real CVE's pack
	mux.HandleFunc("POST /packs/seed", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CVE string `json:"cve"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || !cveRE.MatchString(in.CVE) {
			http.Error(w, "cve must be a CVE-2099-nnnn id", http.StatusBadRequest)
			return
		}
		_, here, _, _ := runtime.Caller(0)
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "content", "mitigation", "testdata", "CVE-2022-27593.json"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body := map[string]json.RawMessage{}
		for _, k := range []string{"sources", "patch", "workaround", "firewall", "checklist", "recheck"} {
			body[k] = doc[k]
		}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var by, with string
		var at time.Time
		if json.Unmarshal(doc["confirmed_by"], &by) != nil || json.Unmarshal(doc["drafted_with"], &with) != nil || json.Unmarshal(doc["confirmed_at"], &at) != nil {
			http.Error(w, "the test pack is malformed", http.StatusInternalServerError)
			return
		}
		db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath, RawQuery: url.Values{"_pragma": {"busy_timeout(5000)"}}.Encode()}).String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = db.Close() }()
		_, err = db.ExecContext(r.Context(), `INSERT OR REPLACE INTO mit_pack (cve, body, compromise, confirmed_by, confirmed_at, drafted_with, pack_version) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			in.CVE, string(bodyJSON), string(doc["compromise"]), by, store.FormatTS(at), with, "e2e-seed")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
