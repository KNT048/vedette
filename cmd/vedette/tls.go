package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/host/api"
)

// Self-signed certificate lifetime (WP-04b part 2): 825 days, the longest Apple platforms accept for a
// certificate (support.apple.com/en-us/103769, HT210176), the same as mkcert. The box makes a new one at
// start-up, and once a day while running, when its own pair expires within selfSignedRenewBefore (a new
// certificate for the same key, served without a restart); browsers still warn about a self-signed certificate, and the owner who wants a clean padlock
// passes -tls-cert and -tls-key (a certificate the owner supplies is never replaced).
const (
	selfSignedLifetime    = 825 * 24 * time.Hour
	selfSignedRenewBefore = 30 * 24 * time.Hour
	// selfSignedCheckEvery is how often a running box looks at its own certificate.
	selfSignedCheckEvery = 24 * time.Hour
	// selfSignedOrg marks the certificates this file makes: only those are renewed.
	selfSignedOrg = "Vedette (self-signed)"
)

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// parseHosts splits the -hosts flag (comma separated names and IP addresses, ports allowed and dropped) into
// canonical entries. A name that cannot be a host name is refused: it would end up in a certificate. A name
// may start with "*." to cover one label, like a wildcard certificate (*.corp.example is box.corp.example,
// not a.b.corp.example nor corp.example) and needs at least two labels after "*." (*.com is refused;
// *.co.uk is accepted, there is no public-suffix list here).
func parseHosts(flag string) ([]string, error) {
	var out []string
	for _, h := range strings.Split(flag, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if host, port, err := net.SplitHostPort(h); err == nil {
			if _, perr := strconv.ParseUint(port, 10, 16); perr != nil {
				return nil, fmt.Errorf("-hosts: %q is not a host name or an IP address", h)
			}
			h = host
		}
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
		if a, err := netip.ParseAddr(h); err == nil {
			out = append(out, a.Unmap().WithZone("").String())
			continue
		}
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if !hostRE.MatchString(strings.TrimPrefix(h, "*.")) {
			return nil, fmt.Errorf("-hosts: %q is not a host name or an IP address", h)
		}
		if strings.HasPrefix(h, "*.") && !server.ValidWildcard(h) {
			return nil, fmt.Errorf("-hosts: %q is too broad or IP-shaped: a wildcard needs at least two labels after \"*.\" (*.corp.example) and never stands for an IP address", h)
		}
		out = append(out, h)
	}
	return out, nil
}

// localNames is what a self-signed certificate covers besides -hosts: the loopback names, the machine's host
// name and the addresses of its interfaces (so that opening the box by its LAN address works on first start).
func localNames() []string {
	out := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil && hostRE.MatchString(h) {
		out = append(out, strings.ToLower(h))
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok && !ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified() {
					out = append(out, ip.Unmap().String())
				}
			}
		}
	}
	return out
}

// ensureCert creates the self-signed certificate and its key on first start, like ensureKey: P-256, 825
// days, both files mode 0600, the names of hosts (plus localNames) as subject alternative names. When the key
// file exists the pair is kept as it is (the owner may have put their own there), except that a pair this
// function made (subject organization selfSignedOrg) that expires within 30 days gets a new certificate for
// the same key, so a box that restarts now and then never runs out; delete both files to have new ones made.
// A key without its certificate is an error; a certificate without its key is a leftover of an interrupted
// first start and is replaced.
func ensureCert(certPath, keyPath string, hosts []string) error {
	return ensureCertAt(certPath, keyPath, hosts, time.Now)
}

// ensureCertAt is ensureCert with the clock injected.
func ensureCertAt(certPath, keyPath string, hosts []string, now func() time.Time) error {
	if _, err := os.Lstat(keyPath); err == nil {
		if _, err := os.Lstat(certPath); err != nil {
			return fmt.Errorf("tls: %s exists but %s does not: restore the certificate or delete the key to make a new pair", keyPath, certPath)
		}
		_, err := renewSelfSigned(certPath, keyPath, hosts, now)
		return err
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("tls key file: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tls: generate key: %w", err)
	}
	ca, err := ensureBoxCA(certPath, now())
	if err != nil {
		return err
	}
	certPEM, err := selfSignedPEM(ca, key, hosts, now())
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("tls: encode key: %w", err)
	}
	if err := writeAtomic(certPath, certPEM); err != nil {
		return err
	}
	return writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// renewSelfSigned replaces the certificate of a pair this program made when it expires within
// selfSignedRenewBefore of now(), signing with the key already there (one atomic file write: a crash cannot
// leave a certificate that does not match the key). It reports whether it replaced it. A pair it cannot
// read, or one that is not its own, is left for loadTLS to judge.
func renewSelfSigned(certPath, keyPath string, hosts []string, now func() time.Time) (bool, error) {
	return reissueSelfSigned(certPath, keyPath, hosts, now, func(l *x509.Certificate) bool { return l.NotAfter.Sub(now()) <= selfSignedRenewBefore })
}

// reissueSelfSigned is renewSelfSigned with the reason as a parameter: a pair this program made is given a new
// certificate (same key, one atomic write) when need says so about the current one.
func reissueSelfSigned(certPath, keyPath string, hosts []string, now func() time.Time, need func(*x509.Certificate) bool) (bool, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return false, nil //nolint:nilerr // loadTLS reports a pair that cannot be loaded, with the file names
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !slices.Contains(leaf.Subject.Organization, selfSignedOrg) {
		return false, nil //nolint:nilerr // see above
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return false, nil
	}
	ca, err := ensureBoxCA(certPath, now())
	if err != nil {
		return false, err
	}
	if notSignedBy(leaf, ca) { // upgrade of a box with an old self-signed leaf (D-262): same key, same names, under the CA
		hosts = append(append(append([]string(nil), hosts...), leaf.DNSNames...), addrStrings(certIPs(leaf))...)
	} else if !need(leaf) {
		return false, nil
	}
	certPEM, err := selfSignedPEM(ca, signer, hosts, now())
	if err != nil {
		return false, err
	}
	return true, writeAtomic(certPath, certPEM)
}

// selfSignedRenewer serves the box's own self-signed pair through tls.Config.GetCertificate and swaps in
// the renewed certificate while the process runs (a box that is never restarted would otherwise let it
// expire after 825 days). It only ever touches the pair the box made, never an owner's -tls-cert.
type selfSignedRenewer struct {
	certPath, keyPath string
	hosts             []string
	now               func() time.Time
	// mgmt is the management addresses of the box from vedette-host (D-139); nil without a host.
	mgmt  func(ctx context.Context) ([]netip.Addr, error)
	local func() []string // localNames; a test gives another
	kick  chan struct{}
	gap   time.Duration // between two address checks started by Kick; 0 = addrSyncGap
	// Used by Check only (one goroutine at a time).
	lastMgmt map[netip.Addr]bool // the management addresses of the last answer; nil before the first
	hostDown bool                // the last ask failed: one warning per outage

	mu   sync.RWMutex
	cert *tls.Certificate
}

// GetCertificate is tls.Config.GetCertificate.
func (r *selfSignedRenewer) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// addrSyncGap is the least time between two runs of the address check that a trigger starts: the box's
// address changes are rare, a burst of triggers (apply, confirm, revert) is one change.
const addrSyncGap = 10 * time.Second

// selfSignedAddrEvery is how often a running box asks vedette-host for its management addresses besides the
// triggers after apply/confirm/revert: a change made another way (DHCP lease, console) is seen within it.
const selfSignedAddrEvery = 10 * time.Minute

// maxMgmtAddrs bounds the management addresses taken from one host answer.
const maxMgmtAddrs = 16

// reservedV4 is 240.0.0.0/4 (reserved, and the limited broadcast address).
var reservedV4 = netip.MustParsePrefix("240.0.0.0/4")

// hostMgmtIPv4s is the IPv4 addresses vedette-host reports on the management card (state/net, role
// "management"; never the SPAN card, never decoys, which hostNetCache also holds), without loopback and
// link-local ones. It is whatever the host reports at that moment (during a network change that waits for
// confirmation that may be the new address only: the certificate follows the host, it does not remember).
// Only private or global unicast addresses count (no multicast, 240/4 or broadcast), each once, at most
// maxMgmtAddrs (the rest are ignored, with one warning on log; nil: none). nil when there is no host.
func hostMgmtIPv4s(r netStateReader, log *slog.Logger) func(ctx context.Context) ([]netip.Addr, error) {
	if r == nil {
		return nil
	}
	warned := false
	return func(ctx context.Context) ([]netip.Addr, error) {
		ctx, cancel := context.WithTimeout(ctx, hostNetTimeout)
		defer cancel()
		st, err := r.StateNet(ctx)
		if err != nil {
			return nil, err
		}
		var out []netip.Addr
		seen := map[netip.Addr]bool{}
		for _, i := range st.Interfaces {
			if i.Role != api.NetRoleManagement {
				continue
			}
			for _, s := range i.Addresses {
				p, err := netip.ParsePrefix(s)
				if err != nil {
					continue
				}
				a := p.Addr().Unmap()
				if !a.Is4() || seen[a] || reservedV4.Contains(a) || a.IsMulticast() || (!a.IsPrivate() && !a.IsGlobalUnicast()) {
					continue
				}
				seen[a] = true
				if len(out) >= maxMgmtAddrs {
					if !warned && log != nil {
						warned = true
						log.WarnContext(ctx, "vedette-host reported more management addresses than the certificate takes; the rest are ignored", "kept", maxMgmtAddrs)
					}
					continue
				}
				out = append(out, a)
			}
		}
		return out, nil
	}
}

// ipSANs is the set of IP addresses among names.
func ipSANs(names []string) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, h := range names {
		if a, err := netip.ParseAddr(h); err == nil {
			out[a.Unmap()] = true
		}
	}
	return out
}

func certIPs(c *x509.Certificate) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, ip := range c.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			out[a.Unmap()] = true
		}
	}
	return out
}

func addrStrings(m map[netip.Addr]bool) []string {
	var out []string
	for a := range m {
		out = append(out, a.String())
	}
	slices.Sort(out)
	return out
}

// Kick asks Run to look at the box's addresses soon (core network applied, confirmed or reverted a change).
// It never blocks; safe on nil.
func (r *selfSignedRenewer) Kick() {
	if r == nil {
		return
	}
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Check re-issues the pair, for the same key, when it expires soon or when its IP addresses are not those the
// box has: -hosts, localNames and the management addresses vedette-host reports (D-139). A host that does not
// answer, or answers nothing, never removes an address: the certificate keeps the ones it has. The new
// certificate is loaded for new handshakes.
//
// The decision to re-issue for addresses compares the management addresses with those of the last answer (at
// start: with the certificate), never the container's own addresses, which localNames adds to the certificate
// but which are not the box's address. The new certificate is built from the new PEM and the key already in
// memory, so a disk that cannot be read back does not keep the old certificate being served; when the pair on
// disk was replaced by something else that loads, that is served instead.
func (r *selfSignedRenewer) Check(ctx context.Context, log *slog.Logger) error {
	r.mu.RLock()
	cur := r.cert
	r.mu.RUnlock()
	if pair, err := tls.LoadX509KeyPair(r.certPath, r.keyPath); err == nil && !bytes.Equal(pair.Certificate[0], cur.Certificate[0]) {
		r.mu.Lock()
		r.cert, cur = &pair, &pair
		r.mu.Unlock()
		if log != nil {
			log.InfoContext(ctx, "the certificate on disk is not the one served; serving it")
		}
	}
	leaf, err := x509.ParseCertificate(cur.Certificate[0])
	if err != nil {
		return fmt.Errorf("tls: parse certificate: %w", err)
	}
	signer, ok := cur.PrivateKey.(crypto.Signer)
	if !ok || !slices.Contains(leaf.Subject.Organization, selfSignedOrg) {
		return nil // not a pair this program made
	}
	var mgmt []netip.Addr
	if r.mgmt != nil {
		a, err := r.mgmt(ctx)
		switch {
		case err != nil:
			if !r.hostDown && log != nil {
				log.WarnContext(ctx, "vedette-host does not answer; the certificate keeps the addresses it has", "error", err)
			}
			r.hostDown = true
		default:
			r.hostDown = false
			mgmt = a
		}
	}
	ca, err := ensureBoxCA(r.certPath, r.now())
	if err != nil {
		return err
	}
	hosts := append([]string(nil), r.hosts...)
	addrChange := false
	var now map[netip.Addr]bool
	if len(mgmt) > 0 {
		now = map[netip.Addr]bool{}
		for _, a := range mgmt {
			hosts = append(hosts, a.String())
			now[a] = true
		}
		if r.lastMgmt == nil { // first answer since start: the certificate is the reference
			addrChange = !maps.Equal(certIPs(leaf), ipSANs(append(hosts, r.localList()...)))
		} else {
			addrChange = !maps.Equal(now, r.lastMgmt)
		}
	} else {
		hosts = append(hosts, addrStrings(certIPs(leaf))...) // no fresh answer: keep the addresses it has
	}
	if !addrChange && leaf.NotAfter.Sub(r.now()) > selfSignedRenewBefore && !notSignedBy(leaf, ca) {
		if now != nil {
			r.lastMgmt = now
		}
		return nil
	}
	certPEM, err := selfSignedPEM(ca, signer, append(hosts, r.localList()...), r.now())
	if err != nil {
		return err
	}
	if err := writeAtomic(r.certPath, certPEM); err != nil {
		return err
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return errors.New("tls: made a certificate that is not PEM")
	}
	r.mu.Lock()
	r.cert = &tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: cur.PrivateKey}
	r.mu.Unlock()
	if now != nil {
		r.lastMgmt = now
	}
	if log != nil {
		log.InfoContext(ctx, "the self-signed certificate was re-issued", "ip_addresses", addrStrings(ipSANs(append(hosts, r.localList()...))))
	}
	return nil
}

// localList is what localNames gives (a test may give another list).
func (r *selfSignedRenewer) localList() []string {
	if r.local != nil {
		return r.local()
	}
	return localNames()
}

// Run calls Check on every tick (the box passes a daily one and one every selfSignedAddrEvery, nil for none),
// once at start and after a Kick (at most once per gap) until ctx is done; a failure is logged and tried again
// at the next trigger.
func (r *selfSignedRenewer) Run(ctx context.Context, log *slog.Logger, tick, addrTick <-chan time.Time) {
	syncLoop(ctx, tick, addrTick, r.kick, r.gap, func(ctx context.Context) error { return r.Check(ctx, log) },
		func(ctx context.Context, err error) {
			log.ErrorContext(ctx, "renewing the self-signed certificate failed", "error", err)
		})
}

// syncLoop runs fn at start, on every tick of either channel, and after a kick, waiting until gap has passed
// since the last run (kicks that arrive meanwhile are one); onErr reports a failure.
func syncLoop(ctx context.Context, tick, addrTick <-chan time.Time, kick <-chan struct{}, gap time.Duration, fn func(context.Context) error, onErr func(context.Context, error)) {
	if gap <= 0 {
		gap = addrSyncGap
	}
	var last time.Time
	run := func() {
		last = time.Now()
		if err := fn(ctx); err != nil {
			onErr(ctx, err)
		}
	}
	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			run()
		case <-addrTick:
			run()
		case <-kick:
			if wait := gap - time.Since(last); wait > 0 {
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
			select {
			case <-kick:
			default:
			}
			run()
		}
	}
}

// ownerCertWarner watches a certificate the owner supplied (-tls-cert): it is never touched, but when it does
// not cover a management address of the box the log says so, once for each set of missing addresses.
type ownerCertWarner struct {
	leaf   *x509.Certificate
	mgmt   func(ctx context.Context) ([]netip.Addr, error)
	kick   chan struct{}
	gap    time.Duration
	warned string
}

func newOwnerCertWarner(cfg *tls.Config, mgmt func(ctx context.Context) ([]netip.Addr, error)) *ownerCertWarner {
	if cfg == nil || len(cfg.Certificates) == 0 || mgmt == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		return nil
	}
	return &ownerCertWarner{leaf: leaf, mgmt: mgmt, kick: make(chan struct{}, 1)}
}

// Kick is selfSignedRenewer.Kick for the owner's certificate; safe on nil.
func (w *ownerCertWarner) Kick() {
	if w == nil {
		return
	}
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// Check logs one warning when the certificate lacks management addresses it did not lack at the last check.
func (w *ownerCertWarner) Check(ctx context.Context, log *slog.Logger) error {
	addrs, err := w.mgmt(ctx)
	if err != nil || len(addrs) == 0 {
		return nil //nolint:nilerr // a host that does not answer says nothing about the certificate
	}
	var missing []string
	for _, a := range addrs {
		if w.leaf.VerifyHostname(a.String()) != nil {
			missing = append(missing, a.String())
		}
	}
	slices.Sort(missing)
	key := strings.Join(missing, ",")
	if key != w.warned && key != "" {
		log.WarnContext(ctx, "the TLS certificate given with -tls-cert does not list the box's management address; browsers will show a name mismatch when it is opened by that address (the box never changes an owner's certificate)", "missing", missing)
	}
	w.warned = key
	return nil
}

// Run checks at start, on every tick and after a Kick (at most once per gap) until ctx is done.
func (w *ownerCertWarner) Run(ctx context.Context, log *slog.Logger, tick, addrTick <-chan time.Time) {
	syncLoop(ctx, tick, addrTick, w.kick, w.gap, func(ctx context.Context) error { return w.Check(ctx, log) },
		func(ctx context.Context, err error) {
			log.ErrorContext(ctx, "checking the owner's certificate failed", "error", err)
		})
}

// The box CA (WP-26 slice 1, D-262): a CA of its own, never the 8443 leaf (Firefox refuses a CA certificate
// as the server's end-entity certificate), signs the self-made leaf, so an agent that pins the CA keeps
// trusting the box through every leaf re-issue (D-139). Created once next to the leaf, never rotated by a
// renewal; only an expired CA, or one that cannot cover a new leaf, is replaced.
const (
	boxCALifetime = 20 * 365 * 24 * time.Hour
	boxCAName     = "vedette-selfsigned-ca"
)

// boxCA is the box CA: its certificate and key.
type boxCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// boxCAPaths are the CA files, in the directory of the leaf's certificate (mode 0600 like the leaf's key).
func boxCAPaths(leafCertPath string) (certPath, keyPath string) {
	d := filepath.Dir(leafCertPath)
	return filepath.Join(d, boxCAName+".crt"), filepath.Join(d, boxCAName+".key")
}

// notSignedBy reports whether leaf does not chain to ca (an old self-signed leaf, or a CA that was replaced).
func notSignedBy(leaf *x509.Certificate, ca *boxCA) bool {
	return leaf.CheckSignatureFrom(ca.cert) != nil
}

// ensureBoxCA loads the box CA next to leafCertPath, or makes it when there is none. A CA that expires
// within selfSignedLifetime (it could not cover a new leaf) is replaced, and the leaf follows at its next
// check. A certificate without its key, or files that do not parse, are an error: they were not left by
// this function (it writes the key first, so a key alone is an interrupted first start and is replaced).
func ensureBoxCA(leafCertPath string, now time.Time) (*boxCA, error) {
	crtPath, keyPath := boxCAPaths(leafCertPath)
	if _, err := os.Lstat(crtPath); err == nil {
		if err := checkKeyFile(keyPath); err != nil {
			return nil, fmt.Errorf("tls: box CA: %w (delete %s and %s to make a new CA; agents must then be enrolled again)", err, crtPath, keyPath)
		}
		pair, err := tls.LoadX509KeyPair(crtPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("tls: box CA: %w (delete %s and %s to make a new CA; agents must then be enrolled again)", err, crtPath, keyPath)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		signer, ok := pair.PrivateKey.(crypto.Signer)
		if err != nil || !ok || !cert.IsCA {
			return nil, fmt.Errorf("tls: %s is not a CA certificate with its key", crtPath)
		}
		if cert.NotAfter.Sub(now) > selfSignedLifetime {
			return &boxCA{cert: cert, key: signer}, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("tls: box CA: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tls: generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("tls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Vedette box CA", Organization: []string{selfSignedOrg}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(boxCALifetime),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("tls: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tls: parse CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("tls: encode CA key: %w", err)
	}
	if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return nil, err
	}
	if err := writeAtomic(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return nil, err
	}
	return &boxCA{cert: cert, key: key}, nil
}

// trustAnchorPEM is what an agent pins to trust this box's 8443 (served by GET /intake/ca.pem in a later
// slice): the box CA's certificate for the box's own pair; for a certificate the owner supplied
// (-tls-cert), the certificates of the file as supplied (the chain, or the leaf alone), never anything else
// that file holds (a key in the same file is not copied).
func trustAnchorPEM(certPath string, ownerSupplied bool) ([]byte, error) {
	if !ownerSupplied {
		certPath, _ = boxCAPaths(certPath)
	}
	raw, err := os.ReadFile(certPath) //nolint:gosec // the configured certificate path, or the CA file next to it
	if err != nil {
		return nil, fmt.Errorf("tls: trust anchor: %w", err)
	}
	var out []byte
	for {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, pem.EncodeToMemory(blk)...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tls: %s holds no certificate", certPath)
	}
	return out, nil
}

// selfSignedPEM makes a server certificate for key, signed by the box CA, valid selfSignedLifetime, for
// hosts and localNames.
func selfSignedPEM(ca *boxCA, key crypto.Signer, hosts []string, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("tls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Vedette", Organization: []string{selfSignedOrg}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(selfSignedLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	for _, h := range append(append([]string(nil), hosts...), localNames()...) {
		if seen[h] {
			continue
		}
		seen[h] = true
		if a, err := netip.ParseAddr(h); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(a.AsSlice()))
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, fmt.Errorf("tls: create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// writeAtomic writes data to path with mode 0600 through a temporary file in the same directory, so a crash
// never leaves a half-written file under the final name.
func writeAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("tls: write %s: %w", path, err)
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	return nil
}

// checkKeyFile refuses a TLS private key that is not a regular file (a symlink to one is fine: certbot
// links its live key) or that group or other users can read, like core/secrets does for the master key: a
// key others can read lets them impersonate the box to every administrator.
func checkKeyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("tls: private key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("tls: private key %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("tls: private key %s has mode %#o; group and other access must be off (chmod 600)", path, perm)
	}
	return nil
}

// loadTLS loads the pair and returns the server configuration and the names the certificate covers (its
// DNS names and addresses; the common name only when it has none, as old certificates were).
func loadTLS(certPath, keyPath string) (*tls.Config, []string, error) {
	if err := checkKeyFile(keyPath); err != nil {
		return nil, nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: load certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("tls: parse certificate: %w", err)
	}
	if now := time.Now(); now.After(leaf.NotAfter) {
		return nil, nil, fmt.Errorf("tls: the certificate %s expired on %s", certPath, leaf.NotAfter.Format(time.DateOnly))
	}
	names := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			names = append(names, a.Unmap().String())
		}
	}
	if len(names) == 0 {
		if cn := strings.ToLower(leaf.Subject.CommonName); hostRE.MatchString(strings.TrimPrefix(cn, "*.")) {
			names = append(names, cn)
		}
	}
	// HTTP/1.1 only: the stack is built and tested for it, and h2 would add attack surface for nothing here.
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, names, nil
}
