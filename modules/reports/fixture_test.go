package reports

import "time"

// The network of the golden report, made at t0 (Wednesday 11 Nov 2026 10:00 UTC) over the last 7 days, (4 Nov 10:00, 11 Nov 10:00]:
//
//   - WinRAR on ws-accounting-07 was updated 6.24 → 7.23 on 9 Nov without anyone telling Vedette: both of its CVEs are handled by
//     Vedette with the versions (patch credit); a person later added a note to one, and the credit stays.
//   - Log4j on web-01 was mitigated by a person on 6 Nov, with a note.
//   - An HP firmware match was corrected (not relevant, data corrected) on 7 Nov: no credit, and left out unless asked for.
//   - Apache on web-01 is under attack here (an intrusion alert), open since October.
//   - 7-Zip on laptop-sales-12 (not added yet) and a Windows update on ws-accounting-07 are new in the period.
//   - Outlook on ws-accounting-07 was accepted until 8 Nov; the acceptance ran out on 9 Nov and it is open again.
//   - An old finding patched in October is outside the period.
type fixtureData struct {
	devices []Device
	views   []FindingView
	reasons map[string][]Reason
	targets []ExposureTarget
	counts  []DetectionCount
	top     []Detection
	feeds   []FeedHealth
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func sp(s string) *string { return &s }

func sev(band string, score float64) *CveSeverity {
	return &CveSeverity{Band: band, Score: score, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
}

func fix(kind, product, version string) Fix {
	f := Fix{Key: product + "|" + kind + "|" + version, Kind: kind, Product: product}
	if version != "" {
		f.Version = sp(version)
	}
	return f
}

var (
	devWS  = DeviceRef{ID: "a-ws", Name: "ws-accounting-07", Added: true}
	devWeb = DeviceRef{ID: "a-web", Name: "web-01", Added: true}
	devLap = DeviceRef{ID: "a-lap", Name: "laptop-sales-12", Added: false}

	byDevice = Verification{Verified: "device", Basis: "device_version", At: sp("2026-10-20T09:00:00.000Z")}
	byScan   = Verification{Verified: "scan", Basis: "scan", At: sp("2026-10-01T09:00:00.000Z")}
	byBanner = Verification{Verified: "no", Basis: "banner_version"}
)

func created(s string) FindingEvent { return FindingEvent{At: at(s), Kind: "created"} }

func handledEv(s, res, via, by string, note, from, to, until *string) FindingEvent {
	return FindingEvent{At: at(s), Kind: "handled", Handled: &Handled{Resolution: res, Via: via, By: by, At: ts(at(s)), Note: note, FromVersion: from, ToVersion: to, AcceptedUntil: until}}
}

func fixture() fixtureData {
	winrarCredit := handledEv("2026-11-09T08:00:00Z", "patched", "version_moved", "system", nil, sp("6.24"), sp("7.23"), nil)
	winrarNote := handledEv("2026-11-10T09:00:00Z", "patched", "person", "it@acme.example", sp("Checked on the machine."), nil, nil, nil)
	mitigated := handledEv("2026-11-06T12:00:00Z", "mitigated", "person", "it@acme.example", sp("JNDI lookups turned off until the vendor update."), nil, nil, nil)
	corrected := handledEv("2026-11-07T07:00:00Z", "not_relevant", "data_corrected", "system", nil, nil, nil, nil)
	accepted := handledEv("2026-10-01T10:00:00Z", "accepted", "person", "it@acme.example", sp("Replaced at the end of the month."), nil, nil, sp("2026-11-08"))
	oldPatch := handledEv("2026-10-01T10:00:00Z", "patched", "person", "it@acme.example", nil, nil, nil, nil)
	credited := *winrarCredit.Handled
	credited.Note = winrarNote.Handled.Note
	return fixtureData{
		devices: []Device{
			{ID: "a-ws", Name: "ws-accounting-07", IP: "10.0.0.7", Kind: "pc", Approved: true, Agent: true},
			{ID: "a-web", Name: "web-01", IP: "10.0.0.10", Kind: "server", Approved: true},
			{ID: "a-lap", Name: "laptop-sales-12", IP: "10.0.0.42", Kind: "laptop", Approved: false, Agent: true},
			{ID: "a-box", Name: "vedette", IP: "10.0.0.2", Kind: "server", Approved: true, Box: true, Agent: true},
		},
		views: []FindingView{
			{ID: "f-winrar-1", CVE: "CVE-2023-38831", Device: devWS, Product: "WinRAR", Version: "6.24", Status: "patched", Urgency: 2, Severity: sev("high", 7.8),
				Verification: byDevice, Fix: fix("update", "WinRAR", "6.23"), Handled: winrarCredit.Handled, FirstSeen: at("2026-10-20T09:00:00Z"),
				Events: []FindingEvent{created("2026-10-20T09:00:00Z"), {At: at("2026-10-21T09:00:00Z"), Kind: "urgency_changed"}, winrarCredit}},
			{ID: "f-winrar-2", CVE: "CVE-2023-40477", Device: devWS, Product: "WinRAR", Version: "6.24", Status: "patched", Urgency: 5, Severity: sev("high", 7.8),
				Verification: byDevice, Fix: fix("update", "WinRAR", "6.23"), Handled: &credited, FirstSeen: at("2026-10-20T09:00:00Z"),
				Events: []FindingEvent{created("2026-10-20T09:00:00Z"), winrarCredit, winrarNote}},
			{ID: "f-log4j", CVE: "CVE-2021-44228", Device: devWeb, Product: "Apache Log4j", Version: "2.14.1", Status: "mitigated", Urgency: 2, Severity: sev("critical", 10),
				Verification: byScan, Fix: fix("update", "Apache Log4j", "2.17.1"), Handled: mitigated.Handled, FirstSeen: at("2026-11-01T12:00:00Z"),
				Events: []FindingEvent{created("2026-11-01T12:00:00Z"), mitigated}},
			{ID: "f-hp", CVE: "CVE-2022-3942", Device: devWeb, Product: "HP LaserJet firmware", Version: "5.6.0.2", Status: "not_relevant", Urgency: 5, Severity: sev("medium", 6.1),
				Verification: byBanner, Fix: fix("unknown", "HP LaserJet firmware", ""), Handled: corrected.Handled, FirstSeen: at("2026-11-05T07:00:00Z"),
				Events: []FindingEvent{created("2026-11-05T07:00:00Z"), corrected}},
			{ID: "f-apache", CVE: "CVE-2021-41773", Device: devWeb, Product: "Apache HTTP Server", Version: "2.4.49", Status: "under_attack", Urgency: 1, Severity: sev("high", 7.5),
				Verification: byScan, Fix: fix("update", "Apache HTTP Server", "2.4.51"), FirstSeen: at("2026-10-01T09:00:00Z"),
				Events: []FindingEvent{created("2026-10-01T09:00:00Z")}},
			{ID: "f-7zip", CVE: "CVE-2025-0411", Device: devLap, Product: "7-Zip", Version: "24.07", Status: "exploited", Urgency: 2, Severity: sev("high", 7),
				Verification: byDevice, Fix: fix("update", "7-Zip", "24.09"), FirstSeen: at("2026-11-09T15:00:00Z"),
				Events: []FindingEvent{created("2026-11-09T15:00:00Z")}},
			{ID: "f-win", CVE: "CVE-2024-38063", Device: devWS, Product: "Windows 11 23H2", Version: "22631.3880", Status: "update_recommended", Urgency: 5, Severity: sev("critical", 9.8),
				Verification: byDevice, Fix: Fix{Key: "microsoft|windows_11|os_update|", Kind: "os_update", Product: "Windows 11 23H2", Ref: sp("KB5041585")}, FirstSeen: at("2026-11-10T06:00:00Z"),
				Events: []FindingEvent{created("2026-11-10T06:00:00Z")}},
			{ID: "f-outlook", CVE: "CVE-2023-23397", Device: devWS, Product: "Microsoft Outlook", Version: "16.0.1", Status: "exploited", Urgency: 2, Severity: sev("critical", 9.8),
				Verification: byDevice, Fix: fix("update", "Microsoft Outlook", "16.0.2"), FirstSeen: at("2026-09-01T09:00:00Z"),
				Events: []FindingEvent{created("2026-09-01T09:00:00Z"), accepted, {At: at("2026-11-09T00:00:00Z"), Kind: "acceptance_expired"}}},
			{ID: "f-old", CVE: "CVE-2020-0601", Device: devWeb, Product: "Windows Server 2019", Version: "17763.1", Status: "patched", Urgency: 5, Severity: nil,
				Verification: byDevice, Fix: fix("os_update", "Windows Server 2019", ""), Handled: oldPatch.Handled, FirstSeen: at("2026-09-15T09:00:00Z"),
				Events: []FindingEvent{created("2026-09-15T09:00:00Z"), oldPatch}},
		},
		reasons: map[string][]Reason{
			"f-apache": {{Layer: 1, Source: "ids", Name: "Intrusion alert", Date: "2026-11-10", Detail: sp("192.0.2.77")},
				{Layer: 2, Source: "cisa-kev", Name: "CISA KEV", Date: "2021-11-03", URL: sp("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"), Due: sp("2021-11-17")}},
			"f-7zip": {{Layer: 2, Source: "cisa-kev", Name: "CISA KEV", Date: "2025-02-06", Due: sp("2025-02-27")}},
		},
		targets: []ExposureTarget{
			{TargetID: "t-1", Kind: "domain", Value: "example.com", Proof: "proven", LastScanAt: sp("2026-11-10T02:30:00.000Z"),
				Services: []ExposureService{
					{IP: "198.51.100.10", Port: 443, Proto: "tcp", Name: sp("https"), Product: sp("nginx"), Version: sp("1.24.0"), CertExpiresAt: sp("2026-11-23T00:00:00.000Z")},
					{IP: "198.51.100.10", Port: 10443, Proto: "tcp", Name: sp("https"), Product: sp("GitLab"), Change: sp("new")},
					{IP: "198.51.100.10", Port: 21, Proto: "tcp", Name: sp("ftp"), Product: sp("vsftpd"), Version: sp("3.0.5"), Change: sp("closed")},
				},
				Issues: []ExposureIssues{{Engine: "zap", Severity: "medium", Open: 3, New: 1}}},
		},
		counts: []DetectionCount{
			{Kind: "intrusion", N: 2, LastAt: at("2026-11-10T08:00:00Z")},
			{Kind: "trap", N: 1, LastAt: at("2026-11-09T22:00:00Z")},
			{Kind: "custom_kind", N: 4, LastAt: at("2026-11-09T22:00:00Z")}, // a kind a producer added later: not named
		},
		top: []Detection{
			{Kind: "intrusion", Title: "Exploit attempt for CVE-2021-41773 against web-01", Severity: "critical", DeviceID: "a-web", DeviceName: "web-01", At: at("2026-11-10T08:00:00Z")},
			{Kind: "trap", Title: "A device touched the SSH trap", Severity: "high", DeviceID: "a-lap", DeviceName: "laptop-sales-12", At: at("2026-11-09T22:00:00Z")},
		},
		feeds: []FeedHealth{
			{ID: "cisa-kev", Name: "CISA KEV", LastOK: at("2026-11-11T09:00:00Z")},
			{ID: "nvd", Name: "NVD", LastOK: at("2026-11-07T09:00:00Z"), Stale: true},
		},
	}
}
