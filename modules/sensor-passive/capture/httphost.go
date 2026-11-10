package capture

import (
	"bytes"
	"net/netip"
	"strings"
)

const maxHTTPHead = 8192 // bytes of a request examined while looking for Host

var httpMethods = [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT ")}

// parseHTTPHost returns the Host header of an HTTP/1.x request that starts at b[0]. Only the header names
// are compared; no other header value (Cookie, Authorization, ...) is copied and the body is never read
// (INV-3, FORBID-2). errIgnore: not the start of a request, or no Host header in the part seen.
func parseHTTPHost(b []byte) (string, error) {
	isReq := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			isReq = true
			break
		}
	}
	if !isReq {
		return "", errIgnore
	}
	if len(b) > maxHTTPHead {
		b = b[:maxHTTPHead]
	}
	line, rest, ok := bytes.Cut(b, []byte("\r\n"))
	if !ok {
		return "", errIgnore // the request line is split over segments
	}
	if !bytes.Contains(line, []byte(" HTTP/1.")) {
		return "", malformed("http: request line")
	}
	for len(rest) > 0 {
		line, rest, ok = bytes.Cut(rest, []byte("\r\n"))
		if len(line) == 0 { // end of the headers
			return "", errIgnore
		}
		if len(line) > 5 && strings.EqualFold(string(line[:5]), "host:") {
			return cleanHost(string(line[5:]))
		}
		if !ok {
			break
		}
	}
	return "", errIgnore
}

// cleanHost turns a Host header value into a host name or an IPv4 address without a port.
func cleanHost(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if strings.ContainsAny(v, "@/\\?#") { // userinfo (user:password@host) or a path: not a Host header
		return "", malformed("http: Host with userinfo or path")
	}
	if strings.HasPrefix(v, "[") { // IPv6 literal: not read (IPv4 only)
		return "", errIgnore
	}
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSuffix(v, ".")
	if ip, err := netip.ParseAddr(v); err == nil {
		if ip.Is4() {
			return v, nil
		}
		return "", errIgnore
	}
	if !hostnameOK(v) {
		return "", malformed("http: Host is not a host name")
	}
	return v, nil
}
