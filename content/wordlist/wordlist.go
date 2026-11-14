// Package wordlist is the short list of common names a domain scan tries under a verified domain (D-567 (1), exposure INV-27): the
// names attackers try first (vpn, mail, remote, owa…) that a certificate log does not show. It ships with the release (labels.txt,
// kept by hand) and is tried only after a wildcard check, at most 20 lookups a second, through the box's own resolver.
package wordlist

import (
	_ "embed" // labels.txt
	"regexp"
	"strings"
	"sync"
)

// MaxLabels bounds the list (D-567 (1)): enough for the names attackers try first, small enough to be ordinary DNS load.
const MaxLabels = 150

//go:embed labels.txt
var data string

// labelRE is one DNS label of a host name.
var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var labels = sync.OnceValue(func() []string {
	var out []string
	for line := range strings.SplitSeq(data, "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "#") && labelRE.MatchString(l) && len(out) < MaxLabels {
			out = append(out, l)
		}
	}
	return out
})

// Labels returns the common names, in file order (at most MaxLabels). The caller must not change it.
func Labels() []string { return labels() }
