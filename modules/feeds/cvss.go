package feeds

import (
	"math"
	"regexp"
	"strings"
)

// CVSS is the CVSS base score every page shows for a CVE (PickCVSS): one scorer's score of one CVSS version, always with its vector
// (FIRST: a score is shown with its vector). The band follows from Score and Version (Severity), so it is not kept.
type CVSS struct {
	Score   float64 // 0.0 … 10.0, one decimal
	Version string  // "4.0", "3.1", "3.0" or "2.0"
	Source  string  // MetricNVD, MetricCNA or MetricADP
	Vector  string  // the vector string of that score ("CVSS:3.1/AV:N/…", v2 "AV:N/AC:L/…")
}

// Metric is one stored CVSS base score of a CVE (feeds_cve_metric): one per scorer and version.
type Metric struct {
	Source  string // MetricNVD, MetricCNA, MetricADP
	Version string
	Score   float64
	Vector  string
}

// The scorers of a CVSS score (feeds_cve_metric.source), in the order PickCVSS prefers them within one CVSS version.
const (
	MetricNVD = "nvd" // NVD's own score ("Primary" in NVD's record)
	MetricCNA = "cna" // the CVE Numbering Authority's
	MetricADP = "adp" // CISA's Authorized Data Publisher (Vulnrichment)
)

// cvssVersions are the CVSS versions PickCVSS knows, newest first.
var cvssVersions = []string{"4.0", "3.1", "3.0", "2.0"}

// metricSources is the order of the scorers within one version.
var metricSources = []string{MetricNVD, MetricCNA, MetricADP}

// PickCVSS is the one rule that chooses the CVSS score of a CVE, for every reader (findings, the plan, the CVE page, reports): the
// newest CVSS version present (4.0, 3.1, 3.0, then 2.0), and within it NVD's own score before the CNA's before CISA's ADP. ok is
// false when the CVE has no score.
func PickCVSS(ms []Metric) (CVSS, bool) {
	for _, v := range cvssVersions {
		for _, src := range metricSources {
			for _, m := range ms {
				if m.Version == v && m.Source == src {
					return m.cvss(), true
				}
			}
		}
	}
	return CVSS{}, false
}

func (m Metric) cvss() CVSS {
	return CVSS{Score: m.Score, Version: m.Version, Source: m.Source, Vector: m.Vector}
}

// Severity is the band of a CVSS base score as FIRST and NVD write it: CVSS 3.x and 4.0 NONE (0), LOW (0.1–3.9), MEDIUM (4.0–6.9),
// HIGH (7.0–8.9), CRITICAL (9.0–10.0); CVSS 2.0 LOW (0–3.9), MEDIUM (4.0–6.9), HIGH (7.0–10.0), with no CRITICAL.
func Severity(score float64, version string) string {
	if version == "2.0" {
		switch {
		case score >= 7:
			return "HIGH"
		case score >= 4:
			return "MEDIUM"
		}
		return "LOW"
	}
	switch {
	case score == 0:
		return "NONE"
	case score < 4:
		return "LOW"
	case score < 7:
		return "MEDIUM"
	case score < 9:
		return "HIGH"
	}
	return "CRITICAL"
}

// cisaADP is the source identifier NVD writes for scores of CISA's Authorized Data Publisher (CISA-ADP, Vulnrichment).
const cisaADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"

type cvssEntry struct {
	Source       string `json:"source"`
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"` // CVSS 2.0 only: NVD writes v2's severity beside cvssData, not in it
	CVSSData     struct {
		BaseScore    *float64 `json:"baseScore"`
		BaseSeverity string   `json:"baseSeverity"`
		VectorString string   `json:"vectorString"`
	} `json:"cvssData"`
}

// cvssMetrics is the `metrics` of an NVD CVE API 2.0 record.
type cvssMetrics struct {
	V40 []cvssEntry `json:"cvssMetricV40"`
	V31 []cvssEntry `json:"cvssMetricV31"`
	V30 []cvssEntry `json:"cvssMetricV30"`
	V2  []cvssEntry `json:"cvssMetricV2"`
}

// cvssVectorRE is a CVSS 3.x or 4.0 vector string as NVD writes it ("CVSS:3.1/AV:N/AC:L/…"), cvss2VectorRE a CVSS 2.0 base vector
// ("AV:N/AC:L/Au:N/C:P/I:P/A:P", no prefix); anything else is not kept.
var (
	cvssVectorRE  = regexp.MustCompile(`^CVSS:(3\.0|3\.1|4\.0)(/[A-Za-z]{1,3}:[A-Za-z]{1,5}){1,40}$`)
	cvss2VectorRE = regexp.MustCompile(`^AV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]$`)
)

var cvssSeverities = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "NONE": true}

// vectorOf is e's vector string when it is a vector of version, else "".
func vectorOf(e cvssEntry, version string) string {
	v := strings.TrimSpace(e.CVSSData.VectorString)
	switch {
	case len(v) > 200:
		return ""
	case version == "2.0" && cvss2VectorRE.MatchString(v), version != "2.0" && cvssVectorRE.MatchString(v) && strings.HasPrefix(v, "CVSS:"+version+"/"):
		return v
	}
	return ""
}

// metricsFrom reads the scores of an NVD record: NVD's own ("Primary") as nvd, CISA's ADP as adp, any other "Secondary" scorer as cna.
// An entry counts only with a known severity, a score in 0..10 and a valid vector of its version; the first such entry of each scorer
// and version is kept. The score is rounded to one decimal, as CVSS defines it, so text and band agree.
func metricsFrom(m cvssMetrics) []Metric {
	var out []Metric
	seen := map[[2]string]bool{}
	for _, l := range []struct {
		version string
		list    []cvssEntry
	}{{"4.0", m.V40}, {"3.1", m.V31}, {"3.0", m.V30}, {"2.0", m.V2}} {
		for _, e := range l.list {
			sev := e.CVSSData.BaseSeverity
			if l.version == "2.0" {
				sev = e.BaseSeverity
			}
			sc, vec := e.CVSSData.BaseScore, vectorOf(e, l.version)
			if !cvssSeverities[strings.ToUpper(strings.TrimSpace(sev))] || sc == nil || *sc < 0 || *sc > 10 || vec == "" {
				continue
			}
			var src string
			switch {
			case e.Type == "Primary":
				src = MetricNVD
			case e.Type == "Secondary" && strings.EqualFold(strings.TrimSpace(e.Source), cisaADP):
				src = MetricADP
			case e.Type == "Secondary":
				src = MetricCNA
			default:
				continue
			}
			if k := [2]string{src, l.version}; !seen[k] {
				seen[k] = true
				out = append(out, Metric{Source: src, Version: l.version, Score: math.Round(*sc*10) / 10, Vector: vec})
			}
		}
	}
	return out
}
