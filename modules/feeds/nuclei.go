package feeds

import (
	"regexp"
	"sort"
	"strings"
)

// NucleiCVEs is the set of CVEs that have a nuclei template: a public-exploit signal of each (feeds_signal).
type NucleiCVEs struct {
	CVEs      []string   // sorted, unique
	Templates []Template // the same CVEs, each with the address of its template ("" when the index gives no usable path)
	Stats
}

// nucleiRepo is where a template of the index is read by a person (the signal's link).
const nucleiRepo = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"

// nucleiPathRE is a template path of the index as the box keeps it: a relative path of plain characters to a YAML file.
var nucleiPathRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._/-]{0,250}\.ya?ml$`)

func nucleiURL(path string) string {
	if !nucleiPathRE.MatchString(path) || strings.Contains(path, "..") || strings.Contains(path, "//") {
		return ""
	}
	return nucleiRepo + path
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
	set := map[string]string{}
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
		if _, seen := set[id]; !seen {
			url := ""
			if p, found := n.get("file_path"); found && p.k == jStr {
				url = nucleiURL(jsTrim(p.s))
			}
			set[id] = url
			tl.Accepted++
		}
	}
	out := NucleiCVEs{CVEs: make([]string, 0, len(set)), Stats: tl.stats()}
	for id := range set {
		out.CVEs = append(out.CVEs, id)
	}
	sort.Strings(out.CVEs)
	out.Templates = make([]Template, len(out.CVEs))
	for i, id := range out.CVEs {
		out.Templates[i] = Template{CVE: id, URL: set[id]}
	}
	return out, nil
}
