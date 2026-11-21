package surface

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// The certificate-transparency search (PRIVACY flow 9): crt.sh, run by Sectigo, a public search over the CT logs that needs no
// key. Only the verified domain name is sent.
const (
	ctBase     = "https://crt.sh/"
	maxCTBody  = 16 << 20 // bytes of one answer
	maxCTEntry = 1 << 20  // bytes of the names of one certificate (a real one holds a few kilobytes)
	maxNames   = 300      // distinct names of one domain, the domain itself included
)

// ErrCT means the certificate-transparency search gave no usable answer (down, slow, not JSON). The scan stops: a snapshot
// without the subdomains would say they are gone.
var ErrCT = errors.New("surface: the certificate-transparency search did not answer")

// ErrTooManyNames means the domain has more names in the CT logs than one scan reads (maxNames, or an answer over maxCTBody).
// The scan stops rather than keep a part: which part is kept would change from day to day, and the comparison of two days
// would show names, ports and pages as new or gone that never changed.
var ErrTooManyNames = errors.New("surface: the domain has more names than one scan reads")

// nameRE is a plain host name (the exposure module's rule for a domain): labels of letters, digits and inner dashes, a
// letter-only last label.
var nameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ctURL is the search of every name under domain ("%.domain") in certificates that have not expired, as JSON.
func ctURL(domain string) string {
	return ctBase + "?q=" + url.QueryEscape("%."+domain) + "&output=json&exclude=expired"
}

// searchCT asks crt.sh for the names under domain, once more when the first answer fails (the service is often busy), and
// returns them: the domain first, then the others sorted. Names are untrusted: parseCTScope keeps only valid names under the domain.
// scans picks the names the scan probes (nil: every name): only those count against maxNames; the others are returned apart
// (skipped, sorted, at most maxNames of them).
func (s *Scanner) searchCT(ctx context.Context, domain string, scans func(string) bool) (names, skipped []string, err error) {
	var last error
	for range 2 {
		names, skipped, err := s.askCT(ctx, domain, scans)
		if err == nil || errors.Is(err, ErrTooManyNames) {
			return names, skipped, err
		}
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrCT, ctx.Err())
		}
		last = err
	}
	return nil, nil, fmt.Errorf("%w: %w", ErrCT, last)
}

func (s *Scanner) askCT(ctx context.Context, domain string, scans func(string) bool) ([]string, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, ctTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ctURL(domain), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := s.ct.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK { // a redirect is not followed (the client's CheckRedirect): it lands here
		return nil, nil, fmt.Errorf("crt.sh answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCTBody+1))
	if err != nil {
		return nil, nil, fmt.Errorf("reading crt.sh: %w", err)
	}
	return parseCTScope(body, domain, maxCTBody, scans)
}

// parseCTScope reads crt.sh's JSON (an array of certificates; name_value holds the names of one, one a line), at most limit bytes and
// maxCTEntry bytes a certificate, and returns every distinct valid name under domain: the domain first, the others sorted.
// Wildcards, e-mail addresses, other domains and anything that is not a host name are dropped. A body that is not that JSON,
// or an entry over maxCTEntry, is an error (fail closed); over limit, or over maxNames names, is ErrTooManyNames: nothing is
// cut, so the same logs give the same names every day. Only the names scans accepts (nil: all) count against maxNames and are returned
// first; the others are returned apart, sorted, at most maxNames of them (a listing, not a scan: one past the bound is left out).
func parseCTScope(body []byte, domain string, limit int, scans func(string) bool) ([]string, []string, error) {
	if len(body) > limit {
		return nil, nil, ErrTooManyNames
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	seen := map[string]bool{domain: true}
	other := map[string]bool{}
	add := func(raw json.RawMessage) error {
		if len(raw) == 0 {
			return nil
		}
		if len(raw) > maxCTEntry {
			return errors.New("an entry of the answer is too long")
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("reading the answer: %w", err)
		}
		for n := range strings.SplitSeq(v, "\n") {
			n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
			switch {
			case len(n) > 253 || !nameRE.MatchString(n) || !strings.HasSuffix(n, "."+domain):
			case scans == nil || scans(n):
				seen[n] = true
			case len(other) < maxNames:
				other[n] = true
			}
		}
		if len(seen) > maxNames {
			return ErrTooManyNames
		}
		return nil
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, nil, errors.New("the answer is not a JSON array")
	}
	for dec.More() {
		var e struct {
			NameValue  json.RawMessage `json:"name_value"`
			CommonName json.RawMessage `json:"common_name"`
		}
		if err := dec.Decode(&e); err != nil {
			return nil, nil, fmt.Errorf("reading the answer: %w", err)
		}
		for _, raw := range []json.RawMessage{e.CommonName, e.NameValue} {
			if string(raw) == "null" {
				continue
			}
			if err := add(raw); err != nil {
				return nil, nil, err
			}
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim(']') {
		return nil, nil, errors.New("the answer is not a whole JSON array")
	}
	delete(seen, domain)
	names := slices.Sorted(maps.Keys(seen))
	return append([]string{domain}, names...), slices.Sorted(maps.Keys(other)), nil
}
