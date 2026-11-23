package exposure

// runnerScans and listName are what the surface scanner does with the names of a domain's scan: it probes a name the scan's plan gives
// it (cmd/vedette hands NamePlan.Scans to it) and lists the others without a probe.
func runnerScans(st ScanTarget, name string) bool { return st.Names.Scans(name) }

func listName(c *Content, h HostRow) {
	c.Listed = append(c.Listed, HostRow{Name: h.Name, Source: h.Source, CNAME: h.CNAME})
}
