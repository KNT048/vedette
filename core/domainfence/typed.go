package domainfence

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/localnet"
)

// The proof of a public IP a person typed in (exposure INV-35), as the executors check it. A typed IP's token is this box's own
// (Token over the IP literal, which no domain name can be), and the host lists the IP like a domain, so core's word is taken for none
// of it. The proof is one of:
//
//   - the file ProofPath served on the IP itself, http or https, whose whole content is the token (the ACME HTTP-01 model);
//   - forward-confirmed reverse DNS: the IP's PTR answers PTRName, and PTRName is proved by a domain this box proves now (the same
//     rule as a domain job: its record through Owned, the name resolving to the IP) under it or under ProofAt.
//
// A yes stands CacheFor, like a domain's; a long run asks again every Recheck.

const (
	// ProofPath is where the token file of a typed IP is served.
	ProofPath = "/.well-known/vedette-verify.txt"
	// ProofMaxBody bounds what is read of the file: a token is 16 digits.
	ProofMaxBody = 512
	// ProofTimeout bounds one request of the file.
	ProofTimeout = 5 * time.Second
	proofRedirects = 3
)

// The two ways a typed IP is proved (TypedProof.Method).
const (
	MethodFile = "file"
	MethodPTR  = "ptr"
)

// TypedProof is what a typed-IP job carries beside the IP (Job.Domain and Job.Name are the IP literal, Job.Token the box-bound token of
// that literal). For Method MethodPTR the Cover fields are the domain job that proves PTRName.
type TypedProof struct {
	Method       string
	PTRName      string // MethodPTR: the name the IP's PTR gives, which a domain of this box proves
	CoverDomain  string // the domain whose record proves PTRName
	CoverToken   string // that domain's box-bound token
	CoverProofAt string // the parent name where that record sits, "" when it is on CoverDomain
}

// ValidIPLiteral says whether s is a canonical public IPv4 address as the fence lists it (the host's list holds typed IPs beside domains).
func ValidIPLiteral(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4() && a.String() == s && localnet.Public(a)
}

func (j Job) validTyped() error {
	t := j.Typed
	switch {
	case !j.IP.Is4() || !localnet.Public(j.IP):
		return errors.New("the address is not a public IPv4 address")
	case j.Domain != j.IP.String() || j.Name != j.Domain:
		return errors.New("a typed IP's domain and name are the address itself")
	case !tokenRE.MatchString(j.Token):
		return errors.New("the token is not 16 hex digits")
	case j.ProofAt != "":
		return errors.New("a typed IP has no proof name")
	case t.Method == MethodFile:
		return nil
	case t.Method != MethodPTR:
		return errors.New("the proof method is neither the token file nor reverse DNS")
	case !tokenRE.MatchString(t.CoverToken):
		return errors.New("the covering domain's token is not 16 hex digits")
	}
	if err := (Job{Domain: t.CoverDomain, Name: t.PTRName, IP: j.IP, Token: t.CoverToken, ProofAt: t.CoverProofAt}).Valid(); err != nil {
		return fmt.Errorf("the reverse DNS name's proof: %w", err)
	}
	return nil
}

// coverJob is the domain job that proves the PTR name.
func (j Job) coverJob() Job {
	t := j.Typed
	return Job{Domain: t.CoverDomain, Name: t.PTRName, IP: j.IP, Token: t.CoverToken, ProofAt: t.CoverProofAt}
}

// PTRResolver looks up the names of an address; *net.Resolver satisfies it. A resolver without it proves nothing by reverse DNS.
type PTRResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// FileFetcher gets the proof file of an IP: the body (at most ProofMaxBody+1 bytes) of a 200, else an error.
type FileFetcher interface {
	Fetch(ctx context.Context, rawURL string, ip netip.Addr) ([]byte, error)
}

// SetFetcher replaces the fetcher of the token file (tests; the default is HTTPFetcher).
func (f *Fence) SetFetcher(x FileFetcher) { f.fetcher = x }

// checkTyped is the check of a typed IP after the grammar, the token and the list: the proof, now.
func (f *Fence) checkTyped(ctx context.Context, j Job) Outcome {
	if j.Typed.Method == MethodFile {
		return f.checkFile(ctx, j)
	}
	cj := j.coverJob()
	if !hmac.Equal([]byte(cj.Token), []byte(f.Token(cj.Domain))) {
		return Outcome{Reason: TokenForeign, Detail: "the covering token is not this box's token for " + cj.Domain}
	}
	if f.listed == nil || !f.listed(cj.Domain) {
		return Outcome{Reason: TokenForeign, Detail: "vedette-host has not issued a token for " + cj.Domain}
	}
	r, ok := f.r.(PTRResolver)
	if !ok {
		return Outcome{Reason: Unchecked, Detail: "the resolver cannot look up reverse DNS"}
	}
	lctx, cancel := context.WithTimeout(ctx, LookupTimeout)
	names, err := r.LookupAddr(lctx, j.IP.String())
	cancel()
	switch {
	case err != nil && !notFound(err):
		return Outcome{Reason: Unchecked, Detail: "the reverse DNS lookup of " + j.IP.String() + " failed"}
	case !slices.ContainsFunc(names, func(n string) bool { return strings.ToLower(strings.TrimSuffix(n, ".")) == j.Typed.PTRName }):
		return Outcome{Reason: NotOwned, Detail: j.IP.String() + " has no reverse DNS name " + j.Typed.PTRName + " now"}
	}
	o, _ := f.check(ctx, cj) // the record of the covering domain, and the name resolving back to the address
	return o
}

func (f *Fence) checkFile(ctx context.Context, j Job) Outcome {
	fetch := f.fetcher
	if fetch == nil {
		fetch = HTTPFetcher{}
	}
	var okAt [2]bool
	var errs [2]error
	var wg sync.WaitGroup
	for i, scheme := range []string{"http", "https"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, ProofTimeout+time.Second)
			defer cancel()
			body, err := fetch.Fetch(c, scheme+"://"+j.IP.String()+ProofPath, j.IP)
			okAt[i], errs[i] = err == nil && TokenInFile(body, j.Token), err
		}()
	}
	wg.Wait()
	if okAt[0] || okAt[1] {
		return Outcome{}
	}
	if ctx.Err() != nil {
		return Outcome{Reason: Unchecked, Detail: "the check was cut short"}
	}
	return Outcome{Reason: NotOwned, Detail: "the token file is not served on " + j.IP.String() + " now"}
}

// TokenInFile says whether the body of a proof file is the token (alone, or as vedette-verify=<token>).
func TokenInFile(body []byte, token string) bool {
	if len(body) > ProofMaxBody || token == "" {
		return false
	}
	v := strings.TrimSpace(string(body))
	return v == token || v == "vedette-verify="+token
}

// HTTPFetcher is the real FileFetcher: it dials the IP whatever the URL says, uses no proxy, takes no certificate as proof and follows a
// redirect only to the same IP.
type HTTPFetcher struct{}

// Fetch implements FileFetcher.
func (HTTPFetcher) Fetch(ctx context.Context, rawURL string, ip netip.Addr) ([]byte, error) {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("address %q: %w", addr, err)
			}
			d := net.Dialer{Timeout: ProofTimeout}
			return d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port)) // the IP, never what a name or a redirect says
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // the token in the file is the proof, not the certificate of a bare IP
		TLSHandshakeTimeout:   ProofTimeout,
		ResponseHeaderTimeout: ProofTimeout,
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{
		Transport: tr,
		Timeout:   ProofTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > proofRedirects {
				return errors.New("too many redirects")
			}
			if req.URL.Hostname() != ip.String() {
				return errors.New("redirected to another host")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ProofMaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading the answer: %w", err)
	}
	return body, nil
}
