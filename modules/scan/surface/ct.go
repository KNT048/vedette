package surface

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// The certificate-transparency search (PRIVACY flow 9): crt.sh, run by Sectigo, a public search over the CT logs that needs no
// key. Only the verified domain name is sent.
const (
	ctBase    = "https://crt.sh/"
	maxCTBody = 32 << 20 // bytes read of one answer; a large domain's names come well before this
	maxNames  = 200      // names kept, the domain itself included
)

// ErrCT means the certificate-transparency search gave no usable answer (down, slow, not JSON). The scan stops: a snapshot
// without the subdomains would say they are gone.
var ErrCT = errors.New("surface: the certificate-transparency search did not answer")

// nameRE is a plain host name (the exposure module's rule for a domain): labels of letters, digits and inner dashes, a
// letter-only last label.
var nameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ctURL is the search of every name under domain ("%.domain"), as JSON.
func ctURL(domain string) string {
	return ctBase + "?q=" + url.QueryEscape("%."+domain) + "&output=json"
}

// searchCT asks crt.sh for the names under domain, once more when the first answer fails (the service is often busy), and
// returns them, the domain first. Names are untrusted: parseCT keeps only valid names under the domain.
func (s *Scanner) searchCT(ctx context.Context, domain string) ([]string, error) {
	var last error
	for range 2 {
		names, err := s.askCT(ctx, domain)
		if err == nil {
			return names, nil
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %w", ErrCT, ctx.Err())
		}
		last = err
	}
	return nil, fmt.Errorf("%w: %w", ErrCT, last)
}

func (s *Scanner) askCT(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, ctTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ctURL(domain), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.ct.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh answered %d", resp.StatusCode)
	}
	return parseCT(resp.Body, domain, maxCTBody)
}

// parseCT reads crt.sh's JSON (an array of certificates; name_value holds the names of one, one a line) as a stream, up to
// limit bytes, and returns the distinct valid names under domain, the domain itself first, at most maxNames. Wildcards,
// e-mail addresses, other domains and anything that is not a host name are dropped. A body that is not that JSON is an error
// (fail closed); a body cut at the limit keeps the names read before the cut.
func parseCT(r io.Reader, domain string, limit int64) ([]string, error) {
	lr := &io.LimitedReader{R: r, N: limit}
	dec := json.NewDecoder(lr)
	names := []string{domain}
	seen := map[string]bool{domain: true}
	add := func(raw string) {
		for n := range strings.SplitSeq(raw, "\n") {
			n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
			if seen[n] || len(names) >= maxNames || len(n) > 253 || !nameRE.MatchString(n) || !strings.HasSuffix(n, "."+domain) {
				continue
			}
			seen[n] = true
			names = append(names, n)
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, errors.New("the answer is not a JSON array")
	}
	for dec.More() && len(names) < maxNames {
		var e struct {
			NameValue  string `json:"name_value"`
			CommonName string `json:"common_name"`
		}
		if err := dec.Decode(&e); err != nil {
			if lr.N == 0 { // cut at the size limit: what was read is whole entries
				return names, nil
			}
			return nil, fmt.Errorf("reading the answer: %w", err)
		}
		add(e.CommonName)
		add(e.NameValue)
	}
	return names, nil
}
