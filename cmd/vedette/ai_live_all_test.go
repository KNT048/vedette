package main

import (
	"context"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/reports"
	"github.com/knt048/vedette/modules/response"
)

// liveBox is a small network as the AI jobs read it: one CVE on the exploited list, the devices it matches, findings and a day of logs.
type liveBox struct{}

func (liveBox) CVE(_ context.Context, id string) (ai.CVEFacts, bool, error) {
	if id != "CVE-2024-3400" {
		return ai.CVEFacts{}, false, nil
	}
	return ai.CVEFacts{CVE: id, Vendor: "Palo Alto Networks", Product: "PAN-OS", Name: "Palo Alto Networks PAN-OS Command Injection Vulnerability",
		Description:    "Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability that allows an unauthenticated attacker to execute code with root privileges on the firewall.",
		RequiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.", DateAdded: "2024-04-12",
		Links: []string{"https://security.paloaltonetworks.com/CVE-2024-3400", "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"}}, true, nil
}

func (liveBox) AffectedAssets(context.Context, string) ([]ai.AssetFact, error) {
	return []ai.AssetFact{{Name: "FW-HQ", IP: "192.168.1.1", Kind: "firewall", Basis: "version", Status: "confirmed"}}, nil
}

func (liveBox) Assets(context.Context) ([]ai.AssetRow, error) {
	return []ai.AssetRow{
		{ID: "dev-live1", Name: "FW-HQ", IP: "192.168.1.1", Kind: "firewall", Vendor: "Palo Alto Networks", Model: "PA-440", OS: "PAN-OS 11.1.0", Approved: true,
			Ports: []string{"443/tcp https", "22/tcp ssh"}, FirstSeen: "2026-11-01T08:00:00.000Z", LastSeen: "2026-11-13T05:00:00.000Z", Origin: "discovered", SeenBy: "scan"},
		{ID: "dev-live2", Name: "PC-ACCOUNTS-03", IP: "192.168.1.23", Kind: "workstation", Vendor: "Dell", Model: "OptiPlex 7010", OS: "Windows 11 Pro 10.0.22631.4460",
			Ports: []string{"3389/tcp ms-wbt-server"}, FirstSeen: "2026-11-02T09:00:00.000Z", LastSeen: "2026-11-13T05:00:00.000Z", Origin: "manual", SeenBy: "osquery"},
	}, nil
}

var liveFinding = ai.FindingRow{ID: "fnd-live1", AssetID: "dev-live1", Asset: "FW-HQ", AssetIP: "192.168.1.1", CVE: "CVE-2024-3400", Status: "confirmed", Severity: "critical",
	Basis: "version", Confidence: 0.9, FirstSeen: "2026-11-03T10:00:00.000Z", LastSeen: "2026-11-13T05:00:00.000Z"}

func (liveBox) Findings(context.Context) ([]ai.FindingRow, error) {
	return []ai.FindingRow{liveFinding}, nil
}
func (liveBox) Finding(context.Context, string) (ai.FindingRow, bool, error) {
	return liveFinding, true, nil
}
func (liveBox) IOC(context.Context, string, string) (ai.IOCFact, bool, error) {
	return ai.IOCFact{}, false, nil
}

func liveDigest(context.Context) (ai.LogDigestData, bool, error) {
	name := "PC-ACCOUNTS-03"
	return ai.LogDigestData{Lines24h: 48210, BaselineDays: 7,
		New:            []ai.LogDigestNew{{Signature: "sshd: Failed password for invalid user <*> from <ip>", SourceName: "FW-HQ", Count: 312, FirstSeen: "2026-11-13T01:12:00.000Z"}},
		Spikes:         []ai.LogDigestSpike{{Signature: "DNS query for <domain>", SourceName: "DNS-01", Count: 9100, BaselinePerDay: 1200}},
		BadConnections: []ai.LogDigestBadConn{{TS: "2026-11-13T02:40:00.000Z", AssetName: &name, SrcIP: "192.168.1.23", Dest: "203.0.113.50", DestKind: "ip", SeenVia: "firewall", Feeds: []string{"Feodo Tracker"}, Confidence: 0.9}},
	}, true, nil
}

func liveAround(context.Context, netip.Addr, time.Time, time.Time) (ai.LogAroundData, bool, error) {
	return ai.LogAroundData{Lines: 40, Kinds: []ai.LogAroundKind{{Signature: "allow tcp <ip>:<port> -> <ip>:443", SourceName: "FW-HQ", Count: 40}}}, true, nil
}

// TestLiveEveryAIJob runs every AI job that has a caller once against a real model (kien's machine only: VEDETTE_LIVE_AI=1, never CI;
// translate-advisory has no caller yet). The key is read from ANTHROPIC_API_KEY, held in memory for the calls, and never printed or
// stored. Each job must come back parsed, and no answer may be cut at the output limit (beta 0.1.0-beta.1: Claude Haiku 5.5 cut every
// explanation at 1,000 tokens). Run:
//
//	VEDETTE_LIVE_AI=1 ANTHROPIC_API_KEY=$(security find-generic-password -s vedette-anthropic-test -w) go test -run '^TestLiveEveryAIJob$' -count=1 -v ./cmd/vedette/
func TestLiveEveryAIJob(t *testing.T) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if os.Getenv("VEDETTE_LIVE_AI") != "1" || key == "" {
		t.Skip("set VEDETTE_LIVE_AI=1 and ANTHROPIC_API_KEY to run the live AI test")
	}
	model := os.Getenv("VEDETTE_LIVE_MODEL")
	if model == "" {
		model = "claude-haiku-5-5"
	}
	ctx := t.Context()
	db := storetest.New(t)
	for name, m := range map[string]fs.FS{"core": core.Migrations, "ai": ai.Migrations} {
		if err := store.Migrate(ctx, db, name, m); err != nil {
			t.Fatal(err)
		}
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ai.New(ctx, ai.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Log: slog.New(slog.DiscardHandler),
		Facts: liveBox{}, Data: liveBox{}, LogDigest: liveDigest, LogAround: liveAround})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.AddProfile(ctx, "test", ai.ProfileInput{Name: "Live", Kind: "anthropic", APIStyle: provider.StyleAnthropic, BaseURL: "https://api.anthropic.com",
		Model: model, APIKey: key, Location: ai.LocationCloud, DailyCap: 500000})
	if err != nil {
		t.Fatal(err)
	}
	asg := svc.Assignments()
	for _, j := range ai.Jobs() {
		asg.Jobs[string(j)] = ai.SlotView{Primary: &p.ID}
	}
	if _, err := svc.SetAssignments(ctx, "test", asg); err != nil {
		t.Fatal(err)
	}
	setTier := func(tier ai.Tier) {
		if _, err := svc.SetConfig(ctx, "test", ai.Settings{Tier: tier, DailyCap: 500000, RedactPII: true}); err != nil {
			t.Fatal(err)
		}
	}
	setTier(ai.TierMed)
	finding := []ai.DataBlock{{Kind: ai.DataFeed, Source: "exploited list entry CVE-2024-3400", Text: "CVE: CVE-2024-3400\nVendor: Palo Alto Networks\nProduct: PAN-OS\nRequired action (CISA): Apply mitigations per vendor instructions.\n"},
		{Kind: "inventory", Source: "the device of the finding", Text: "Device: FW-HQ, IP 192.168.1.1, kind firewall, Palo Alto Networks PA-440 PAN-OS 11.1.0\n"}}
	jobs := []struct {
		job ai.Job
		run func() error
	}{
		{ai.JobExplainFinding, func() error { _, err := svc.ExplainCVE(ctx, "test", "CVE-2024-3400"); return err }},
		{ai.JobExplainFinding, func() error {
			_, err := svc.Brief(ctx, ai.BriefRequest{Job: ai.JobExplainFinding, Actor: "test", Target: "CVE-2024-3400", Question: "Explain this finding.", Data: finding})
			return err
		}},
		{ai.JobMitigationConfig, func() error {
			_, err := svc.Brief(ctx, ai.BriefRequest{Job: ai.JobMitigationConfig, Actor: "test", Target: "CVE-2024-3400", Question: "Draft a recommendation for this finding.", Data: finding})
			return err
		}},
		{ai.JobCVENews, func() error { _, err := svc.NewsCVE(ctx, "test", "CVE-2024-3400"); return err }},
		{ai.JobLogDigest, func() error { _, err := svc.LogDigest(ctx, "test"); return err }},
		{ai.JobLogInvestigate, func() error {
			setTier(ai.TierMax)
			_, err := svc.LogDigest(ctx, "test")
			setTier(ai.TierMed)
			return err
		}},
		{ai.JobAskMyData, func() error {
			_, err := svc.Ask(ctx, "test", "Which devices need attention first, and why?")
			return err
		}},
		{ai.JobWeeklyReport, func() error {
			_, err := reportsAI{svc}.Summarize(ctx, "test", string(ai.JobWeeklyReport), "Write a short commentary on one week of a small company's network security report. Use only the figures in the data block. Write at most 3 short paragraphs. Reply with one JSON object only.",
				[]reports.Block{{Source: "weekly report figures", Text: "Devices: 14 (2 new). Open findings: 3 (1 critical: CVE-2024-3400 on FW-HQ). Fixed this week: 2. Honeypot touches: 5 from 192.168.1.23."}})
			return err
		}},
		{ai.JobPDPLAssessment, func() error {
			_, err := reportsAI{svc}.Summarize(ctx, "test", string(ai.JobPDPLAssessment), "Write a short commentary on a personal-data-protection self-assessment of a small company's network. Use only the facts in the data block. Write at most 3 short paragraphs. Give no legal advice. Reply with one JSON object only.",
				[]reports.Block{{Source: "self-assessment figures", Text: "Encrypted admin access: 9 of 14 devices. Devices with an exploited vulnerability: 1. Log retention: 90 days. Backups checked: no."}})
			return err
		}},
		{ai.JobResponsePlan, func() error {
			_, err := responsePlanner{svc: svc}.Plan(ctx, response.PlanAsk{Target: response.PlanTarget{FindingID: "fnd-live1", CVE: "CVE-2024-3400", AssetID: "dev-live1", AssetName: "FW-HQ", AssetIP: "192.168.1.1", AssetKind: "firewall"}})
			return err
		}},
	}
	for _, j := range jobs {
		if err := j.run(); err != nil {
			t.Errorf("%s: %v", j.job, err)
		}
	}
	// every call is in the activity log: answered, parsed (a refused answer is result error), and not cut at the output limit
	rows, err := db.Reader().QueryContext(ctx, `SELECT job, result, COALESCE(stop, ''), tokens_in, tokens_out, summary FROM ai_activity ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	for rows.Next() {
		var job, result, stop, summary string
		var in, out int
		if err := rows.Scan(&job, &result, &stop, &in, &out, &summary); err != nil {
			t.Fatal(err)
		}
		t.Logf("%-18s %-14s stop=%-10s in=%-6d out=%-6d %s", job, result, stop, in, out, summary)
		if job == "connection-test" {
			continue
		}
		seen[job] = true
		if result != string(ai.ResultOK) || stop == string(provider.StopMaxTokens) {
			t.Errorf("%s: result %s, stop %s: %s", job, result, stop, summary)
		}
	}
	for _, j := range jobs {
		if !seen[string(j.job)] {
			t.Errorf("%s made no call", j.job)
		}
	}
}
