package feeds

import (
	"strings"
)

// VectorReading is a CVSS base vector read into words: the attack conditions and the impact, one value per metric, the same words for
// CVSS 2.0, 3.x and 4.0 so a reader never decodes a vector itself. Summary says it in one sentence.
type VectorReading struct {
	AttackVector       string // network | adjacent | local | physical
	AttackComplexity   string // low | medium (2.0 only) | high
	AttackRequirements string // 4.0 only: none | present; "" otherwise
	// PrivilegesRequired is none | low | high; for CVSS 2.0 its Authentication read the same way (none, single, multiple).
	PrivilegesRequired string
	UserInteraction    string // none | required (3.x) | passive | active (4.0); "" for 2.0, which has no such metric
	Scope              string // 3.x only: unchanged | changed; "" otherwise
	// Confidentiality, Integrity and Availability are the impact on the vulnerable system: none | low | high (2.0's partial is low,
	// complete is high).
	Confidentiality, Integrity, Availability string
	Subsequent                               *Impact // 4.0 only: the impact on the systems beyond it; nil otherwise
	Summary                                  string
}

// Impact is an impact on confidentiality, integrity and availability: none | low | high each.
type Impact struct{ Confidentiality, Integrity, Availability string }

// vectorWords are the values of each metric, by CVSS family ("2" or "3" for 3.0 and 3.1, "4"), in the words of VectorReading.
var vectorWords = map[string]map[string]map[string]string{
	"2": {
		"AV": {"N": "network", "A": "adjacent", "L": "local"},
		"AC": {"L": "low", "M": "medium", "H": "high"},
		"Au": {"N": "none", "S": "low", "M": "high"},
		"C":  {"N": "none", "P": "low", "C": "high"},
		"I":  {"N": "none", "P": "low", "C": "high"},
		"A":  {"N": "none", "P": "low", "C": "high"},
	},
	"3": {
		"AV": {"N": "network", "A": "adjacent", "L": "local", "P": "physical"},
		"AC": {"L": "low", "H": "high"},
		"PR": {"N": "none", "L": "low", "H": "high"},
		"UI": {"N": "none", "R": "required"},
		"S":  {"U": "unchanged", "C": "changed"},
		"C":  {"N": "none", "L": "low", "H": "high"},
		"I":  {"N": "none", "L": "low", "H": "high"},
		"A":  {"N": "none", "L": "low", "H": "high"},
	},
	"4": {
		"AV": {"N": "network", "A": "adjacent", "L": "local", "P": "physical"},
		"AC": {"L": "low", "H": "high"},
		"AT": {"N": "none", "P": "present"},
		"PR": {"N": "none", "L": "low", "H": "high"},
		"UI": {"N": "none", "P": "passive", "A": "active"},
		"VC": {"N": "none", "L": "low", "H": "high"},
		"VI": {"N": "none", "L": "low", "H": "high"},
		"VA": {"N": "none", "L": "low", "H": "high"},
		"SC": {"N": "none", "L": "low", "H": "high"},
		"SI": {"N": "none", "L": "low", "H": "high"},
		"SA": {"N": "none", "L": "low", "H": "high"},
	},
}

// ReadVector reads a CVSS base vector as the catalogue stores it ("CVSS:3.1/AV:N/…", "CVSS:4.0/…", 2.0 "AV:N/AC:L/Au:N/C:P/I:P/A:P").
// It returns nil for a vector it cannot read whole: an unknown version, a base metric missing or given twice, or a value the version
// does not define. Metrics beyond the base ones (a 4.0 threat or environmental metric, 3.x temporal ones) are passed over.
func ReadVector(vector string) *VectorReading {
	family, rest := "2", vector
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0/"), strings.HasPrefix(vector, "CVSS:3.1/"):
		family, rest = "3", vector[len("CVSS:3.x/"):]
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		family, rest = "4", vector[len("CVSS:4.0/"):]
	case strings.HasPrefix(vector, "CVSS:"):
		return nil
	}
	words := vectorWords[family]
	got := map[string]string{}
	for _, part := range strings.Split(rest, "/") {
		k, v, ok := strings.Cut(part, ":")
		vals, base := words[k]
		switch {
		case !ok:
			return nil
		case !base:
			continue
		case got[k] != "":
			return nil
		}
		w, known := vals[v]
		if !known {
			return nil
		}
		got[k] = w
	}
	if len(got) != len(words) {
		return nil
	}
	r := &VectorReading{AttackVector: got["AV"], AttackComplexity: got["AC"], AttackRequirements: got["AT"], PrivilegesRequired: got["PR"],
		UserInteraction: got["UI"], Scope: got["S"], Confidentiality: got["C"], Integrity: got["I"], Availability: got["A"]}
	switch family {
	case "2":
		r.PrivilegesRequired = got["Au"]
	case "4":
		r.Confidentiality, r.Integrity, r.Availability = got["VC"], got["VI"], got["VA"]
		r.Subsequent = &Impact{Confidentiality: got["SC"], Integrity: got["SI"], Availability: got["SA"]}
	}
	r.Summary = r.summary()
	return r
}

// summary says the reading in one sentence: "Attacker needs local access, low complexity, high privileges needed, no user action;
// high impact on confidentiality, integrity and availability; can reach beyond the vulnerable component."
func (r *VectorReading) summary() string {
	where := map[string]string{"network": "Remote attack over the network", "adjacent": "Attacker needs access to the same local network segment",
		"local": "Attacker needs local access", "physical": "Attacker needs physical access"}[r.AttackVector]
	parts := []string{where, r.AttackComplexity + " complexity"}
	if r.AttackRequirements == "present" {
		parts = append(parts, "only under conditions the attacker does not control")
	}
	parts = append(parts, map[string]string{"none": "no privileges needed", "low": "low privileges needed", "high": "high privileges needed"}[r.PrivilegesRequired])
	switch r.UserInteraction {
	case "none":
		parts = append(parts, "no user action")
	case "required":
		parts = append(parts, "a user must take an action")
	case "passive":
		parts = append(parts, "a user must be involved")
	case "active":
		parts = append(parts, "a user must take a specific action")
	}
	s := strings.Join(parts, ", ") + "; " + impactWords(Impact{r.Confidentiality, r.Integrity, r.Availability})
	switch {
	case r.Scope == "changed":
		s += "; can reach beyond the vulnerable component"
	case r.Subsequent != nil && *r.Subsequent != (Impact{"none", "none", "none"}):
		s += "; can also affect other systems (" + impactWords(*r.Subsequent) + ")"
	}
	return s + "."
}

// impactWords says an impact: "high impact on confidentiality, integrity and availability" when the three agree, else each one
// ("impact: confidentiality high, integrity none, availability low"); "no impact on confidentiality, integrity or availability".
func impactWords(i Impact) string {
	switch {
	case i.Confidentiality == i.Integrity && i.Integrity == i.Availability && i.Confidentiality == "none":
		return "no impact on confidentiality, integrity or availability"
	case i.Confidentiality == i.Integrity && i.Integrity == i.Availability:
		return i.Confidentiality + " impact on confidentiality, integrity and availability"
	}
	return "impact: confidentiality " + i.Confidentiality + ", integrity " + i.Integrity + ", availability " + i.Availability
}
