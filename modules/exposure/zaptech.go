package exposure

import (
	"net/netip"
	"strings"
)

// The technologies ZAP's active scan may leave out of a page (INV-24, ScanTarget.NoTech): only what this run positively identified
// the page as not running on, never a guess. A product is identified on the page's own address and port by an engine of this run:
// a nuclei template that matched (its matchers read the product's own pages), or nmap naming the product from a probe's answer
// (never from the port number alone). The product's databases are those its own documentation states it can run on; a technology
// it never supported is left out, one it once supported stays (an old install may still use it). An unknown stack leaves out
// nothing: every rule runs.

// webStack is a product and the technologies (ZAP's names, host api.ZapTechs) it never runs on.
type webStack struct {
	product   string   // nmap's product name for it, compared without case
	templates []string // nuclei template ids that identify it
	absent    []string // ZAP technologies it never runs on, sorted
}

// webStacks: GitLab stores its data in PostgreSQL; it supported MySQL until 12.1 (2019), so MySQL is not left out, and it never ran
// on Oracle, Microsoft SQL Server or HyperSQL (https://docs.gitlab.com/install/requirements/#postgresql).
var webStacks = []webStack{
	{product: "GitLab", templates: []string{"gitlab-detect"}, absent: []string{"HypersonicSQL", "Microsoft SQL Server", "Oracle"}},
}

// webTechAbsent are the technologies page's address and port is positively known not to run on, from what this run identified there
// (c.Templates, c.Services); nil when nothing identified a product of webStacks. Two products identified on one port leave out only
// what neither runs on.
func webTechAbsent(c Content, page WebPage) []string {
	here := func(ip string, port int) bool {
		a, err := netip.ParseAddr(ip)
		return err == nil && port == page.Port && a.Unmap() == page.IP.Unmap()
	}
	var out []string
	found := false
	for _, s := range webStacks {
		if !stackSeen(c, s, here) {
			continue
		}
		if !found {
			out, found = append([]string(nil), s.absent...), true
			continue
		}
		var both []string
		for _, t := range out {
			for _, u := range s.absent {
				if t == u {
					both = append(both, t)
				}
			}
		}
		out = both
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func stackSeen(c Content, s webStack, here func(string, int) bool) bool {
	for _, r := range c.Templates {
		if r.Outcome == OutcomeMatched && here(r.IP, r.Port) && containsStr(s.templates, r.Template) {
			return true
		}
	}
	for _, r := range c.Services {
		if r.Method == "probed" && here(r.IP, r.Port) && strings.EqualFold(strings.TrimSpace(r.Product), s.product) {
			return true
		}
	}
	return false
}

// WebTechs are every technology an identification of webStacks can leave out: the host takes only names of its own list
// (api.ZapTechs), which the scanner adapter's test holds these to.
func WebTechs() []string {
	var out []string
	for _, s := range webStacks {
		for _, t := range s.absent {
			if !containsStr(out, t) {
				out = append(out, t)
			}
		}
	}
	return out
}
