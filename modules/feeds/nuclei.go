package feeds

import (
	"sort"
	"strings"
)

// NucleiCVEs is the set of CVEs that have a nuclei template (has_template).
type NucleiCVEs struct {
	CVEs []string // sorted, unique
	Stats
}

const maxNucleiLine = 1 << 20

// ParseNucleiCVEs reads the nuclei-templates cves.json index, JSON Lines: one
// object per line with "ID" (like CVE-2024-1234), "Info" and "file_path". The
// key is matched exactly. A line that is not such an object is rejected and
// counted; a line over 1 MiB fails the parse. Duplicates collapse.
func ParseNucleiCVEs(data []byte) (NucleiCVEs, error) {
	if len(data) > MaxBodyBytes {
		return NucleiCVEs{}, fail(ErrTooLarge, "The index is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	tl := newTally()
	set := map[string]bool{}
	row := 0
	for rest := cleanText(data); rest != ""; {
		var line string
		line, rest = nextLine(rest)
		if len(line) > maxNucleiLine {
			return NucleiCVEs{}, fail(ErrBadSample, "The index has a line that is far too long.")
		}
		if line = jsTrim(line); line == "" {
			continue
		}
		if row >= MaxRows {
			tl.Truncated = true
			break
		}
		row++
		n, err := decodeJSON(line)
		if err != nil || n.k != jObj {
			tl.reject(row, "line is not a JSON object")
			continue
		}
		idNode, found := n.get("ID")
		if !found || idNode.k != jStr {
			tl.reject(row, "line has no ID text")
			continue
		}
		id := strings.ToUpper(jsTrim(idNode.s))
		if !cveRE.MatchString(id) {
			tl.reject(row, "ID: %s is not a CVE ID", id)
			continue
		}
		if !set[id] {
			set[id] = true
			tl.Accepted++
		}
	}
	out := NucleiCVEs{CVEs: make([]string, 0, len(set)), Stats: tl.stats()}
	for id := range set {
		out.CVEs = append(out.CVEs, id)
	}
	sort.Strings(out.CVEs)
	return out, nil
}
