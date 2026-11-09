package feeds

import "embed"

// The built-in samples of POST /feeds/parse-test (INV-7: no network, no database). They are the same files the
// golden tests parse and the SPA's samples.ts, so a preview on the box and in the GUI agree.
//
//go:embed testdata/samples/*
var sampleFiles embed.FS

var sampleLabels = map[Kind]map[Format]string{
	KindVulnerabilities: {FormatJSON: "Vendor advisory API (JSON)", FormatCSV: "Advisory export (CSV)", FormatRSS: "Advisory feed (RSS 2.0)"},
	KindIOC: {FormatJSON: "Threat intel API (JSON)", FormatCSV: "Botnet C2 blocklist (CSV)", FormatRSS: "Phishing reports (Atom)",
		FormatSTIX: "TAXII 2.1 collection (STIX 2.1 objects)", FormatLines: "Plain list of addresses"},
}

// SampleFor returns the built-in sample of a kind and format, with its label.
func SampleFor(k Kind, f Format) (text, label string, ok bool) {
	label, ok = sampleLabels[k][f]
	if !ok {
		return "", "", false
	}
	b, err := sampleFiles.ReadFile("testdata/samples/" + string(k) + "." + string(f))
	if err != nil {
		return "", "", false
	}
	return string(b), label, true
}
