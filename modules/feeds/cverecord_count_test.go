package feeds

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// Count tests of the CVE records (matching when NVD is slow), on frozen public data:
//   - testdata/cverecord/sample.json.gz: the CISA KEV entries listed in the 90 days before 2026-11-16 with whether NVD gave them
//     affected versions by then (the snapshot of cmd/vedette/testdata/kev-nvd-2026-11-16.json.gz), and the CVE records (identity and
//     affected lists only) of those CVEs and of every CVE published in the 365 days before 2026-11-20 whose record ranges name a product
//     of the inventory below, from the CVE Program's archive of 2026-11-20;
//   - testdata/cverecord/inventory.json: the software of an anonymised test network (public product strings as reported).
//
// go test ./modules/feeds -run TestCount_Record -update-records rebuilds the sample from VEDETTE_CVE_ARCHIVE (a daily archive).

var updateRecords = flag.Bool("update-records", false, "rebuild testdata/cverecord/sample.json.gz from $VEDETTE_CVE_ARCHIVE")

const (
	recordSamplePath = "testdata/cverecord/sample.json.gz"
	recordInvPath    = "testdata/cverecord/inventory.json"
	kevSnapshotPath  = "../../cmd/vedette/testdata/kev-nvd-2026-11-16.json.gz"
)

type recordSample struct {
	About   string                     `json:"_about"`
	KEV     []sampleKEV                `json:"kev"`
	Records map[string]json.RawMessage `json:"records"`
}

type sampleKEV struct {
	CVE       string `json:"cve"`
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	DateAdded string `json:"date_added"`
	NVDRanges bool   `json:"nvd_ranges"` // NVD gave affected versions by the snapshot
}

type invRow struct {
	Device, Vendor, Product, Display, Version, CPE string
}

func loadInventory(t *testing.T) []invRow {
	t.Helper()
	var f struct {
		Software []invRow `json:"software"`
	}
	if err := json.Unmarshal([]byte(testFile(t, "cverecord/inventory.json")), &f); err != nil {
		t.Fatal(err)
	}
	return f.Software
}

// invKeys are the product keys a matcher asks the catalogue with for one software row: the NVD CPE names of its product
// (core/productid), the record key of its names and of the product's other names, and the CPE the row states.
func invKeys(r invRow) (keys []ProductKey, version string) {
	version = r.Version
	add := func(k ProductKey) {
		if k.Vendor != "" && k.Product != "" && !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	add(RecordProductKey(r.Vendor, r.Product))
	if p, ok := productid.ResolveStored(r.Vendor, r.Product, r.Display, r.CPE); ok {
		for _, c := range p.CPEs {
			if !c.Prefix {
				add(ProductKey{c.Vendor, c.Product})
			}
		}
		add(RecordProductKey(p.Vendor, p.Product))
		for _, a := range append(append([]string{}, p.Also...), p.KEV...) {
			v, pr, _ := strings.Cut(a, "|")
			add(RecordProductKey(v, pr))
		}
		if p.Version != "" {
			version = p.Version
		} else if p.VersionNotOwn {
			version = ""
		}
	}
	if _, v, pr := cpeParts(r.CPE); v != "" {
		add(ProductKey{v, pr})
	}
	return keys, version
}

// inRange says a version is inside a range by its leading numbers (cmpLead); a comparison it cannot make is "no" here (a count of
// matches Vedette is sure of).
func inRange(v string, r Range) bool {
	if v == "" {
		return false
	}
	cmp := func(b string) (int, bool) {
		c, ok := cmpLead(v, b)
		if !ok || c == 0 && v != b {
			return 0, false
		}
		return c, true
	}
	for _, b := range []struct {
		bound string
		ok    func(int) bool
	}{
		{r.StartIncl, func(c int) bool { return c >= 0 }}, {r.StartExcl, func(c int) bool { return c > 0 }},
		{r.EndIncl, func(c int) bool { return c <= 0 }}, {r.EndExcl, func(c int) bool { return c < 0 }},
	} {
		if b.bound == "" {
			continue
		}
		c, ok := cmp(b.bound)
		if !ok || !b.ok(c) {
			return false
		}
	}
	return true
}

func loadRecordSample(t *testing.T) (recordSample, map[string]CVERecord) {
	t.Helper()
	b, err := os.ReadFile(recordSamplePath)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var s recordSample
	if err := json.NewDecoder(zr).Decode(&s); err != nil {
		t.Fatal(err)
	}
	recs := map[string]CVERecord{}
	for cve, raw := range s.Records {
		r, err := ParseCVERecord(raw, cve)
		if err != nil {
			t.Fatalf("%s: %v", cve, err)
		}
		recs[cve] = r
	}
	return s, recs
}

// The exploited CVEs listed in the last 90 days. NVD's history is in no public bulk file, so "without NVD ranges on the day they
// were listed" is bounded by the snapshot four days later; the record gives the vendor's versions for most of them on the day the
// CVE is published.
func TestCount_RecordRangesOfRecentlyListedCVEs(t *testing.T) {
	t.Parallel()
	if *updateRecords {
		t.Skip("rebuilding the sample")
	}
	s, recs := loadRecordSample(t)
	listed, noNVD, withRanges, viewed, noNVDWithRanges := len(s.KEV), 0, 0, 0, 0
	for _, k := range s.KEV {
		r := recs[k.CVE]
		key := RecordProductKey(k.Vendor, k.Product)
		has := slices.ContainsFunc(r.Ranges, func(x Range) bool {
			return x.Origin == OriginCNA && x.Vendor == key.Vendor && x.Product == key.Product && x.Generic()
		})
		if has {
			withRanges++
			if !recordSkipVendors[key.Vendor] && productid.Norm(k.Product) != "multipleproducts" {
				viewed++ // what findings matches today (kevRecordView)
			}
		}
		if !k.NVDRanges {
			noNVD++
			if has {
				noNVDWithRanges++
			}
		}
	}
	t.Logf("listed CVEs: %d listed in 90 days; %d without NVD ranges four days later (%d of them with record ranges); %d with record ranges "+
		"for the listed product, %d of them in the exploited-list view findings matches", listed, noNVD, noNVDWithRanges, withRanges, viewed)
	if listed != 115 || noNVD != 1 || withRanges != listedWithRanges || viewed != listedViewed || noNVDWithRanges != listedNoNVDWithRanges {
		t.Errorf("listed CVEs moved: listed %d, no NVD %d (%d with record ranges), with record ranges %d, viewed %d", listed, noNVD, noNVDWithRanges, withRanges, viewed)
	}
}

// The counts with this reader. With the reader it replaced (the CISA entry's product only, the whole CVE refused on one
// unreadable entry, modules and processor platforms refused): 22 listed CVEs with record ranges; no device
// matched by record ranges (they were read only for exploited CVEs without NVD ranges).
const (
	listedWithRanges      = 23
	listedViewed          = 23
	listedNoNVDWithRanges = 0
	matchedDevices        = 7
	matchedPairs          = 708
	matchedKEVPairs       = 0
)

// Devices of the test inventory that match a CVE through the record's ranges, which NVD alone does not give them (NVD's ranges win
// when NVD has any: for the exploited CVEs the snapshot says which; for the other CVEs of the window the sample holds no NVD state, so
// they count as NVD-less, the upper bound the CVE records add).
func TestCount_DevicesMatchedByRecordRangesOnly(t *testing.T) {
	t.Parallel()
	if *updateRecords {
		t.Skip("rebuilding the sample")
	}
	s, recs := loadRecordSample(t)
	nvd := map[string]bool{}
	for _, k := range s.KEV {
		nvd[k.CVE] = k.NVDRanges
	}
	inv := loadInventory(t)
	pairs := map[string]bool{}
	devices := map[string]bool{}
	byProduct := map[string]int{}
	kevPairs := 0
	for _, row := range inv {
		keys, version := invKeys(row)
		for cve, r := range recs {
			if nvd[cve] {
				continue // NVD's ranges win
			}
			for _, x := range r.Ranges {
				if x.Generic() && slices.Contains(keys, ProductKey{x.Vendor, x.Product}) && inRange(version, x) {
					if p := row.Device + " " + cve; !pairs[p] {
						pairs[p] = true
						byProduct[productid.Key(x.Vendor, x.Product)]++
						if _, isKEV := nvd[cve]; isKEV {
							kevPairs++
						}
					}
					devices[row.Device] = true
					break
				}
			}
		}
	}
	t.Logf("devices: %d of %d devices match %d (device, CVE) pairs through record ranges only (%d on exploited CVEs)",
		len(devices), len(deviceSet(inv)), len(pairs), kevPairs)
	top := slices.SortedFunc(maps.Keys(byProduct), func(a, b string) int { return byProduct[b] - byProduct[a] })
	for _, k := range top[:min(len(top), 12)] {
		t.Logf("  %s: %d pairs", k, byProduct[k])
	}
	if len(devices) != matchedDevices || len(pairs) != matchedPairs || kevPairs != matchedKEVPairs {
		t.Errorf("devices moved: %d devices, %d pairs, %d exploited", len(devices), len(pairs), kevPairs)
	}
}

func deviceSet(inv []invRow) map[string]bool {
	m := map[string]bool{}
	for _, r := range inv {
		m[r.Device] = true
	}
	return m
}

// TestCount_RecordSampleBuild rebuilds the sample (-update-records with VEDETTE_CVE_ARCHIVE).
func TestCount_RecordSampleBuild(t *testing.T) {
	if !*updateRecords {
		t.Skip("-update-records rebuilds the sample")
	}
	path := os.Getenv("VEDETTE_CVE_ARCHIVE")
	if path == "" {
		t.Fatal("set VEDETTE_CVE_ARCHIVE to a daily archive of the CVE Program")
	}
	snap, err := os.ReadFile(kevSnapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(snap))
	if err != nil {
		t.Fatal(err)
	}
	var kev []struct {
		CVE       string            `json:"cve"`
		Vendor    string            `json:"vendor"`
		Product   string            `json:"product"`
		DateAdded string            `json:"date_added"`
		Affected  []json.RawMessage `json:"affected"`
	}
	if err := json.NewDecoder(zr).Decode(&kev); err != nil {
		t.Fatal(err)
	}
	s := recordSample{About: "Public data: CISA KEV entries (CC0) with NVD's state of 2026-11-16, and CVE records (identity and affected lists " +
		"only) from the CVE Program's archive of 2026-11-20 (CVE records © The MITRE Corporation, CVE Program Terms of Use).",
		Records: map[string]json.RawMessage{}}
	want := map[string]bool{}
	for _, k := range kev {
		if k.DateAdded >= "2026-08-18" {
			s.KEV = append(s.KEV, sampleKEV{CVE: k.CVE, Vendor: k.Vendor, Product: k.Product, DateAdded: k.DateAdded, NVDRanges: len(k.Affected) > 0})
			want[k.CVE] = true
		}
	}
	var keys []ProductKey
	for _, row := range loadInventory(t) {
		ks, _ := invKeys(row)
		for _, k := range ks {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	cutoff := time.Date(2025, 11, 20, 0, 0, 0, 0, time.UTC)
	f, err := os.Open(path) //nolint:gosec // the archive named by the person rebuilding the sample
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	err = walkDailyArchive(f, info.Size(), func(e archiveEntry, body func() ([]byte, error)) error {
		b, err := body()
		if err != nil {
			return nil
		}
		r, err := ParseCVERecord(b, e.CVE)
		if err != nil {
			return nil
		}
		hit := want[e.CVE]
		if !hit && !r.Published.Before(cutoff) {
			hit = slices.ContainsFunc(r.Ranges, func(x Range) bool { return slices.Contains(keys, ProductKey{x.Vendor, x.Product}) })
		}
		if hit {
			s.Records[e.CVE] = trimRecord(t, b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&out, gzip.BestCompression)
	enc := json.NewEncoder(zw)
	if err := enc.Encode(s); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordSamplePath, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d KEV entries, %d records, %d bytes", len(s.KEV), len(s.Records), out.Len())
}

// trimRecord keeps what the range conversion reads: the record's identity and the affected lists.
func trimRecord(t *testing.T, b []byte) json.RawMessage {
	t.Helper()
	var r struct {
		DataType    string `json:"dataType"`
		DataVersion string `json:"dataVersion"`
		Meta        struct {
			ID        string `json:"cveId"`
			State     string `json:"state"`
			Assigner  string `json:"assignerShortName"`
			Published string `json:"datePublished"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA struct {
				Affected json.RawMessage `json:"affected,omitempty"`
			} `json:"cna"`
			ADP []struct {
				Affected json.RawMessage `json:"affected,omitempty"`
			} `json:"adp,omitempty"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
