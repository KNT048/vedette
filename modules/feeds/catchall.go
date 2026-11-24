package feeds

import "slices"

// CutCatchAll reads a CVE record's open-ended row the way its vendor means it when the same product also has bounded rows above the
// row's start. Some vendors list each release train they evaluated with its fixed release and add one row "affected from X, every
// later version" for the trains they no longer evaluate (F5's NGINX records: 1.31.0 before 1.31.7, 1.30.0 before 1.30.6, and 1.25.0
// with no end, next to the note that end-of-support versions are not evaluated). Read literally, that row says the fixed releases the
// same record names are affected, so no release would ever fix the flaw and a device stays affected after the update. The row is cut
// where the lowest bounded row above its start begins: 1.25.0 before 1.30.0. Versions below the first evaluated train stay affected
// with no fix named; the evaluated trains keep their own rows and fixes.
//
// Only the rows of a CVE record (origin cna or adp) are read so; NVD writes its own ranges. Rows of one product are those of one
// origin, part, vendor, product and CPE. A row is open-ended when it has a start and no end; a bounded row has a start and an end that
// differ (an exact version is not a train). Starts that cannot be compared leave the row as it is. The rows are not changed in place:
// a cut row is a copy.
func CutCatchAll(rows []Range) []Range {
	var out []Range
	for i, r := range rows {
		if !openEnded(r) {
			continue
		}
		start := cmpStart(r)
		cut := ""
		for _, b := range rows {
			if !sameRecordProduct(r, b) || !boundedTrain(b) {
				continue
			}
			bs := cmpStart(b)
			if c, ok := cmpLead(bs, start); !ok || c <= 0 {
				continue
			}
			if cut == "" {
				cut = bs
			} else if c, ok := cmpLead(bs, cut); ok && c < 0 {
				cut = bs
			}
		}
		if cut == "" {
			continue
		}
		if out == nil {
			out = slices.Clone(rows)
		}
		out[i].EndExcl = cut
	}
	if out == nil {
		return rows
	}
	return out
}

func recordOrigin(r Range) bool { return r.Origin == OriginCNA || r.Origin == OriginADP }

// openEnded: a record row with a start and no end ("affected from 1.25.0, every later version").
func openEnded(r Range) bool {
	return recordOrigin(r) && r.Generic() && cmpStart(r) != "" && r.EndIncl == "" && r.EndExcl == ""
}

// boundedTrain: a record row with a start and an end that is not its start (a train with its last affected or first fixed release).
func boundedTrain(r Range) bool {
	if !recordOrigin(r) || !r.Generic() || cmpStart(r) == "" {
		return false
	}
	return r.EndExcl != "" || r.EndIncl != "" && r.EndIncl != r.StartIncl
}

func cmpStart(r Range) string {
	if r.StartIncl != "" {
		return r.StartIncl
	}
	return r.StartExcl
}

func sameRecordProduct(a, b Range) bool {
	return a.CVE == b.CVE && a.Origin == b.Origin && a.Part == b.Part && a.Vendor == b.Vendor && a.Product == b.Product && a.CPE == b.CPE
}
