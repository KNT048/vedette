package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/knt048/vedette/core/versionscheme"
)

// checkKeyRE is the shape of a stored check key: 64 lower-case hex digits.
var checkKeyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// checkable says a question is one a check of the CVE's advisories can decide: about one CVE, on a line with a version, where the
// versions the CVE lists are what is unknown (no_range_data, older_line, a not_comparable one that no build attribute decides), and NVD
// has answered for the CVE (while it has not, its data may still come and decide it for free).
func checkable(q Question) bool {
	if q.CVE == "" || q.SoftwareID == "" || q.Detail.Version == "" || q.Detail.NVDPending {
		return false
	}
	switch q.Kind {
	case QuestionNoRangeData, QuestionOlderLine:
		return true
	case QuestionNotComparable:
		return q.Detail.Attribute == ""
	}
	return false
}

// keyQuestions sets the check identity of each checkable question of device a (Question.CheckKey, Detail.Check): the CVE, the line's
// product, its release line, the exact version and the CVE record's stamp (Vuln.Stamp). A new version or a changed record gives a new
// key, so a check made before no longer applies.
func keyQuestions(qs []Question, lines map[string]line, byCVE map[string]Vuln) {
	for i := range qs {
		q := &qs[i]
		l, ok := lines[q.SoftwareID]
		if !ok || !checkable(*q) {
			continue
		}
		product := productKey(l.sw)
		if product == "" {
			continue
		}
		build := statedBuild(l.sw) // ESXi 8.0 Update 1 and Update 3 are both version 8.0: the build tells them apart
		id := CheckID{Product: product, Line: releaseLine(product, q.Detail.Version, build), Version: q.Detail.Version, Build: build,
			Evidence: hashHex("v1\x1f" + CheckID{Version: q.Detail.Version, Build: build}.Release() + "\x1f" + byCVE[q.CVE].Stamp)}
		q.Detail.Check, q.CheckKey = &id, checkKey(q.CVE, id)
	}
}

// checkKey is the identity of one check: sha256 hex of the CVE and its CheckID.
func checkKey(cve string, id CheckID) string {
	return hashHex("pc1\x1f" + cve + "\x1f" + id.Product + "\x1f" + id.Line + "\x1f" + id.Evidence)
}

// releaseLine is the release line of version as the product's scheme names it ("15.1" of Junos "15.1R7.9"), else the version itself.
func releaseLine(product, version, build string) string {
	if sc := productScheme(product); sc != nil {
		if v, ok := sc.Installed(version, build); ok {
			return versionscheme.LineStart(v).Label
		}
	}
	return version
}

// Release is the version with the build the device states, as a person and the AI read it ("8.0 (build 24022510)").
func (id CheckID) Release() string {
	if id.Build == "" {
		return id.Version
	}
	return id.Version + " (build " + id.Build + ")"
}

func hashHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
