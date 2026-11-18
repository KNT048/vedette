package findings

// One software on one device is often reported by several sources at once: the scan reads a banner ("OpenSSH 10.2"), a person enters
// the package release, the agent reads the package database ("OpenSSH 10.2p1", apk 10.2_p1-r1). Which row describes the software is
// inventory's decision (its effective-row resolver: the agent's row, else a person's, else the device's SNMP answer, else the scan
// banner; a less precise version of the same release is the same software), passed in Software.Shadowed. Every surface of this
// module reads the software through effectiveSoftware, so the matcher, Needs your input, the plan, To fix, the report and the
// assistant's device updates all describe it by the same row; findings never ranks sources itself.

// effectiveSoftware is the device's software rows that describe their software (inventory's effective rows): Software.Shadowed rows
// are left out. The rows are returned as given when none is shadowed.
func effectiveSoftware(a Asset) []Software {
	n := 0
	for _, s := range a.Software {
		if s.Shadowed {
			n++
		}
	}
	if n == 0 {
		return a.Software
	}
	out := make([]Software, 0, len(a.Software)-n)
	for _, s := range a.Software {
		if !s.Shadowed {
			out = append(out, s)
		}
	}
	return out
}
