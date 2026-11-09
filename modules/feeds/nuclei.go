package feeds

import (
	"bufio"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// NucleiCVEs is the set of CVEs that have a nuclei template (has_template).
type NucleiCVEs struct {
	CVEs []string // sorted, unique
	Stats
}

type nucleiEntry struct {
	ID string `json:"ID"` // encoding/json also matches "id"
}

const maxNucleiLine = 1 << 20

// ParseNucleiCVEs reads the nuclei-templates cves.json index: one JSON object
// per line (or one JSON array) with an "ID" like CVE-2024-1234. Lines that are
// not a CVE are rejected and counted. Duplicates collapse.
func ParseNucleiCVEs(data []byte) (NucleiCVEs, error) {
	if len(data) > MaxBodyBytes {
		return NucleiCVEs{}, fail(ErrTooLarge, "The index is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	text := cleanText(data)
	tl := newTally()
	set := map[string]bool{}
	row := 0
	add := func(e nucleiEntry) {
		row++
		id := strings.ToUpper(jsTrim(e.ID))
		if !cveRE.MatchString(id) {
			tl.reject(row, `ID: "`+jsSlice(id, 30)+`" is not a CVE ID`)
			return
		}
		if !set[id] {
			set[id] = true
			tl.Accepted++
		}
	}
	truncated := func() bool { return row >= MaxRows }
	if strings.HasPrefix(jsTrim(text), "[") {
		dec := json.NewDecoder(strings.NewReader(text))
		if _, err := dec.Token(); err != nil {
			return NucleiCVEs{}, fail(ErrBadSample, "The index is not valid JSON.")
		}
		for dec.More() {
			if truncated() {
				tl.Truncated = true
				break
			}
			var e nucleiEntry
			if err := dec.Decode(&e); err != nil {
				var te *json.UnmarshalTypeError
				if !errors.As(err, &te) {
					return NucleiCVEs{}, fail(ErrBadSample, "The index is not valid JSON.")
				}
				row++
				tl.reject(row, "entry is not an object with an ID")
				continue
			}
			add(e)
		}
		if !tl.Truncated {
			if _, err := dec.Token(); err != nil { // closing bracket
				return NucleiCVEs{}, fail(ErrBadSample, "The index is not valid JSON.")
			}
		}
	} else {
		sc := bufio.NewScanner(strings.NewReader(text))
		sc.Buffer(make([]byte, 0, 4096), maxNucleiLine)
		for sc.Scan() {
			line := jsTrim(sc.Text())
			if line == "" {
				continue
			}
			if truncated() {
				tl.Truncated = true
				break
			}
			var e nucleiEntry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				row++
				tl.reject(row, "line is not a JSON object with an ID")
				continue
			}
			add(e)
		}
		if err := sc.Err(); err != nil {
			return NucleiCVEs{}, fail(ErrBadSample, "The index has a line that is far too long.")
		}
	}
	out := NucleiCVEs{CVEs: make([]string, 0, len(set)), Stats: tl.stats()}
	for id := range set {
		out.CVEs = append(out.CVEs, id)
	}
	sort.Strings(out.CVEs)
	return out, nil
}
