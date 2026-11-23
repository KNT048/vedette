// Package httpenc holds the Accept-Encoding parsing shared by the places that compress responses.
package httpenc

import (
	"strconv"
	"strings"
)

// AcceptsGzip reports whether an Accept-Encoding value allows gzip (RFC 9110 section 12.4.2): the coding name and the parameter
// name q are case-insensitive, q may follow other parameters, and q=0 refuses it. A bare "*" is not taken as gzip.
func AcceptsGzip(v string) bool {
	for part := range strings.SplitSeq(v, ",") {
		fields := strings.Split(part, ";")
		if !strings.EqualFold(strings.TrimSpace(fields[0]), "gzip") {
			continue
		}
		for _, p := range fields[1:] {
			name, val, ok := strings.Cut(strings.TrimSpace(p), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil && f <= 0 {
				return false
			}
		}
		return true
	}
	return false
}
