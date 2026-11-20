package main

import (
	"context"
	"time"

	"github.com/knt048/vedette/core/jobs"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// reachEvery is how often the reach-audit job looks for a refresh of the feed data findings matches with (the exploited list is
// pulled hourly, NVD's affected versions with it).
const reachEvery = 10 * time.Minute

// reachJob is findings' KEV reachability audit (#910 phase 1: the class check re-runs like a test): when the
// feeds' match stamp changed (a pull of the exploited list, NVD's or CVE.org's affected versions; and once at start), it classes
// every entry against the software Vedette can produce (reachRows) and stores the run (fnd_reach_run) with the CVEs that became
// unreachable. Off while findings is off; nothing while feeds is off.
func reachJob(d deps) jobs.Job {
	last := ""
	return jobs.Job{Module: "findings", Name: "reach-audit", Every: reachEvery, Run: func(ctx context.Context) error {
		st, ok := feedsKEV{&d}.store()
		if !ok || d.Findings == nil || d.Inventory == nil {
			return nil
		}
		stamp, err := st.MatchStamp(ctx)
		if err != nil || stamp == last {
			return err
		}
		cat, err := d.Inventory.Catalog(ctx)
		if err != nil {
			return err
		}
		if _, err := d.Findings.ReachAudit(ctx, stamp, reachRows(cat)); err != nil {
			return err
		}
		last = stamp
		return nil
	}}
}

// reachRows is the software Vedette's inventory produces by itself, as findings reads it: every row agent-intake's mapper gives a
// KEV key (content/catalog/products pairs, the Windows release rows) and every curated catalog entry a person can pick, with the keys inventory
// gives it (keysFor over the live KEV pairs). findings adds the network OS rows (network-os.json). Not counted: an auto catalog
// entry (any KEV pair picked by hand reaches its own key) and nmap's own CPEs.
func reachRows(cat *inventory.Catalog) []findings.Software {
	var out []findings.Software
	for _, s := range agentintake.KnownSoftware() {
		out = append(out, findings.Software{ID: "reach:agent", Display: s.Display, Vendor: s.Vendor, Product: s.Product, Version: s.Version,
			KevKeys: s.KevKeys, CPE: s.CPE, Source: "agent"})
	}
	for _, s := range cat.Curated() {
		out = append(out, findings.Software{ID: "reach:manual", Display: s.Display, Vendor: s.Vendor, Product: s.Product, KevKeys: s.KevKeys, Source: "manual"})
	}
	return out
}
