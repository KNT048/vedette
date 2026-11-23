package findings

import (
	"strconv"

	"github.com/knt048/vedette/core/winrel"
)

// winHost is a device whose agent reports a Windows release row at build.rev, with the OS name given ("" = the release's name).
func winHost(build int, server bool, rev int, os string) Asset {
	r, ok := winrel.ByBuild(build, server)
	if !ok {
		panic("no release")
	}
	v := "10.0." + strconv.Itoa(build) + "." + strconv.Itoa(rev)
	if os == "" {
		os = "Microsoft " + r.Display
	}
	return Asset{ID: "a-win", Name: "Windows host", OS: os + " " + v, AgentOS: os, Software: []Software{{
		ID: "s-win", Display: r.Display, Vendor: "Microsoft", Product: "Windows", Version: v, Source: "agent",
		CPE: "cpe:2.3:o:microsoft:" + r.Product + ":" + v + ":*:*:*:*:*:*:*", KevKeys: []string{"microsoft|windows"}}}}
}
