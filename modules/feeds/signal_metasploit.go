package feeds

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Metasploit's module metadata: db/modules_metadata_base.json of the metasploit-framework repository (BSD-3-Clause), one JSON
// object whose values describe one module each. Only three fields are read: the module's full name (its link on Rapid7's module
// database), its last change (mod_time) and its references (the CVE ids). The module's code is never fetched.

// metasploitMaxModules bounds the modules of one file (7,274 in November 2026).
const metasploitMaxModules = 100_000

// metasploitNameRE is a module's full name as the link uses it: a type, then path segments of plain characters.
var metasploitNameRE = regexp.MustCompile(`^[a-z]{3,12}(/[A-Za-z0-9_.-]{1,80}){1,10}$`)

// metasploitTimeLayout is mod_time as the file writes it ("2025-05-21 08:32:40 +0000").
const metasploitTimeLayout = "2006-01-02 15:04:05 -0700"

// metasploitModuleURL is where a person reads a module: Rapid7's module database, not the code.
const metasploitModuleURL = "https://www.rapid7.com/db/modules/"

type metasploitModule struct {
	FullName   string   `json:"fullname"`
	ModTime    string   `json:"mod_time"`
	References []string `json:"references"`
}

// parseMetasploitModules reads Metasploit's module metadata file. A module that names a CVE gives that CVE a signal dated by the
// module's last change (the file keeps no date of the module's arrival; for a new module the two are the same day, and for an old
// one the date is late, never early); a CVE named by several modules keeps the earliest. A module without a CVE reference is not
// counted; one with a CVE but a bad name or date is rejected. The file must be one JSON object (fail-closed).
func parseMetasploitModules(r io.Reader) (publicIndex, error) {
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return publicIndex{}, readFail(err, "The Metasploit module file is not a JSON object.")
	}
	tl := newTally()
	type agg struct {
		date    time.Time
		name    string
		modules int
	}
	byCVE := map[string]*agg{}
	row := 0
	for dec.More() {
		if _, err := dec.Token(); err != nil { // the module's key
			return publicIndex{}, readFail(err, "The Metasploit module file could not be read: %v.", err)
		}
		if row++; row > metasploitMaxModules {
			return publicIndex{}, fail(ErrBadSample, "The Metasploit module file lists more than %s modules.", grouped(metasploitMaxModules))
		}
		var m metasploitModule
		if err := dec.Decode(&m); err != nil {
			var te *json.UnmarshalTypeError
			if !errors.As(err, &te) {
				return publicIndex{}, readFail(err, "The Metasploit module file could not be read: %v.", err)
			}
			tl.reject(row, "module: a field has the wrong type")
			continue
		}
		cves, ok := cvesOf(slices.Values(m.References))
		if !ok {
			tl.reject(row, "references: more than %s CVEs", strconv.Itoa(maxCVEsPerEntry))
			continue
		}
		if len(cves) == 0 {
			continue
		}
		mod, err := time.Parse(metasploitTimeLayout, m.ModTime)
		if err != nil {
			tl.reject(row, "mod_time: %s is not a date", m.ModTime)
			continue
		}
		if !metasploitNameRE.MatchString(m.FullName) || strings.Contains(m.FullName, "..") {
			tl.reject(row, "fullname: %s is not a module name", m.FullName)
			continue
		}
		tl.Accepted++
		for _, c := range cves {
			a := byCVE[c]
			if a == nil {
				if len(byCVE) == maxSignalsPerIndex {
					return publicIndex{}, fail(ErrBadSample, "The Metasploit module file names more than %s CVEs.", grouped(maxSignalsPerIndex))
				}
				a = &agg{date: mod, name: m.FullName}
				byCVE[c] = a
			} else if mod.Before(a.date) || (mod.Equal(a.date) && m.FullName < a.name) {
				a.date, a.name = mod, m.FullName
			}
			a.modules++
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return publicIndex{}, readFail(err, "The Metasploit module file is cut short.")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return publicIndex{}, readFail(err, "The Metasploit module file has data after its end.")
	}
	out := publicIndex{Signals: make([]publicSignal, 0, len(byCVE)), Stats: tl.stats()}
	for c, a := range byCVE {
		out.Signals = append(out.Signals, publicSignal{CVE: c, Date: a.date.UTC(), URL: metasploitModuleURL + a.name + "/",
			Detail: fmt.Sprintf(`{"modules":%d}`, a.modules)})
	}
	sort.Slice(out.Signals, func(i, j int) bool { return out.Signals[i].CVE < out.Signals[j].CVE })
	return out, nil
}

// cvesOf is the distinct CVE ids among an entry's references, upper case, in their order ("CVE-2021-44228"; other ids such as
// "OSVDB-1" or "URL-https://…" are not CVEs). ok is false when the entry names more than maxCVEsPerEntry: the entry is rejected, and
// reading stops there.
func cvesOf(refs iter.Seq[string]) (out []string, ok bool) {
	seen := map[string]bool{}
	for r := range refs {
		c := strings.ToUpper(strings.TrimSpace(r))
		if len(c) > 20 || !cveRE.MatchString(c) || seen[c] {
			continue
		}
		if len(out) == maxCVEsPerEntry {
			return nil, false
		}
		seen[c] = true
		out = append(out, c)
	}
	return out, true
}
