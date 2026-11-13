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

// localNames is what a self-signed certificate covers besides -hosts and the box's name (certBoxName): the loopback names,
// "vedette" and the addresses of core's interfaces (so that opening the box by its LAN address works on first start). "vedette"
// is always there: it was the container's host name (HostName=vedette of the core unit, and the compose file's hostname), which
// every certificate and default Host allowlist made before the box took its name from vedette-host held, so a bookmark, hosts
// file entry or DNS record that uses it keeps working. core's own host name is not used: on an appliance it is the container's id.
func localNames() []string {
	out := []string{"localhost", "127.0.0.1", "::1", fallbackBoxName}
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

// certBoxName is the box's name (boxHostName.Get) as a DNS name of its self-signed certificate and of the Host allowlist made from
// it: only a name vedette-host reported (or core's own without a host; never the device row's while the host has not answered, ok
// false), lower case, RFC 1123 (api.ValidHostname, checked again here: the name is untrusted text) and not IP-shaped (a last label of
// digits only), so "10.0.0.5" never becomes an address the box answers to by name; "" otherwise.
func certBoxName(ctx context.Context, b *boxHostName) string {
	name, ok := b.Get(ctx)
	name = strings.ToLower(name)
	if !ok || !api.ValidHostname(name) {
		return ""
	}
	if strings.Trim(name[strings.LastIndexByte(name, '.')+1:], "0123456789") == "" {
		return ""
	}
	return name
}

// localSuffixes are the name spaces no one can register publicly: mDNS (.local, RFC 6762), home networks (.home.arpa, RFC 8375),
// private use (.internal, ICANN 2024) and the de facto home-router domain .lan.
var localSuffixes = []string{".local", ".lan", ".home.arpa", ".internal"}

// defaultAllowed says whether a name of the box's own certificate may be a Host the box answers to without -hosts: an IP address, a
// single label ("vedette", "office-box") or a name under localSuffixes. The machine's name may come from DHCP (option 12 sets the
// nodename on many distributions), so a hostile DHCP server could name the box rb.attacker.example; were that in the allowlist, a page
// on that domain could rebind it to the box. The certificate may still carry it; answering to it needs -hosts.
func defaultAllowed(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil || !strings.Contains(h, ".") {
		return true
	}
	for _, s := range localSuffixes {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

// ensureCertAt creates the self-signed certificate and its key on first start, like ensureKey: P-256, 825 days, both files mode
// 0600, the names of hosts (plus localNames) as subject alternative names, signed by the box CA (ca, D-262). When the key file
// exists the pair is kept as it is (the owner may have put their own there), except that a pair this function made (subject
// organization selfSignedOrg) that expires within 30 days, or that does not chain to the box CA, gets a new certificate for the
// same key, so a box that restarts now and then never runs out; delete both files to have new ones made. A key without its
// certificate is an error; a certificate without its key is a leftover of an interrupted first start and is replaced. now is the
// clock, log the logger (nil: the default logger).
func ensureCertAt(ctx context.Context, ca *boxCAStore, certPath, keyPath string, hosts []string, now func() time.Time, log *slog.Logger) error {
	if _, err := os.Lstat(keyPath); err == nil {
		if _, err := os.Lstat(certPath); err != nil {
			return fmt.Errorf("tls: %s exists but %s does not: restore the certificate or delete the key to make a new pair", keyPath, certPath)
		}
		_, err := renewSelfSigned(ctx, ca, certPath, keyPath, hosts, now, log)
		return err
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("tls key file: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tls: generate key: %w", err)
	}
	c, err := ca.ensure(ctx, now(), log, true) // no leaf yet: a CA is required
	if err != nil {
		return err
	}
	certPEM, err := selfSignedPEM(c, key, hosts, now())
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
// selfSignedRenewBefore of now(), or when it does not cover every entry of hosts (D-397: the owner changed -hosts,
// VEDETTE_HOSTS, and started again), signing with the key already there (one atomic file write: a crash cannot
// leave a certificate that does not match the key). It reports whether it replaced it. A pair it cannot
// read, or one that is not its own, is left for loadTLS to judge.
func renewSelfSigned(ctx context.Context, ca *boxCAStore, certPath, keyPath string, hosts []string, now func() time.Time, log *slog.Logger) (bool, error) {
	return reissueSelfSigned(ctx, ca, certPath, keyPath, hosts, now, func(l *x509.Certificate) bool { return l.NotAfter.Sub(now()) <= selfSignedRenewBefore }, log)
}

// reissueSelfSigned is renewSelfSigned with the reason as a parameter: a pair this program made is given a new
// certificate (same key, one atomic write) when need says so about the current one, or when it lacks an entry of
// hosts (uncoveredHosts). For a missing entry the new certificate keeps every name and address the old one had
// (a name dropped from -hosts is still refused by the Host allowlist; a bookmark of an address keeps working), is
// signed by the same box CA (agents pinned to it keep working, D-262) and is logged. Like the upgrade under the
// CA, it is optional: a CA that cannot be read or a directory that cannot be written keeps the leaf in use.
func reissueSelfSigned(ctx context.Context, cas *boxCAStore, certPath, keyPath string, hosts []string, now func() time.Time, need func(*x509.Certificate) bool, log *slog.Logger) (bool, error) {
	if log == nil {
		log = slog.Default()
	}
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
	// Nothing about the CA may stop a start while the leaf in use is valid and needs no new certificate
	// (H-1): the upgrade is optional, and the next Check (at start) tries again and logs why.
	optional := !need(leaf) && now().Before(leaf.NotAfter)
	ca, err := cas.ensure(ctx, now(), log, !optional)
	if err != nil {
		if optional {
			log.WarnContext(ctx, "the box CA is not available; the certificate in use is kept", "error", err)
			return false, nil
		}
		return false, err
	}
	upgrade, missing := notSignedBy(leaf, ca), uncoveredHosts(leaf, hosts)
	if upgrade || len(missing) > 0 { // an old self-signed leaf (D-262) or a -hosts change (D-397): same key, the names it had and the new ones, under the CA
		hosts = append(append(append([]string(nil), hosts...), leaf.DNSNames...), addrStrings(certIPs(leaf))...)
	} else if !need(leaf) {
		return false, nil
	}
	certPEM, err := selfSignedPEM(ca, signer, hosts, now())
	if err == nil {
		err = writeAtomic(certPath, certPEM)
	}
	if err != nil {
		if optional { // a data directory that cannot be written: serve the old leaf, as before the CA existed
			log.WarnContext(ctx, "the certificate could not be re-issued under the box CA; the certificate in use is kept", "error", err)
			return false, nil
		}
		return false, err
	}
	if len(missing) > 0 {
		log.InfoContext(ctx, "the self-signed certificate was re-issued for the names of -hosts or the box name it did not cover", "added", missing)
	}
	return true, nil
}

// uncoveredHosts is the entries of hosts (-hosts, the box's name) that leaf has neither as a DNS name (compared without case;
// a "*." entry is compared as written) nor as an IP address. localNames is left out: the container's own addresses change with
// every new container and are not names the owner chose (Check never re-issues for them either).
func uncoveredHosts(leaf *x509.Certificate, hosts []string) []string {
	local := map[string]bool{}
	for _, h := range localNames() {
		local[h] = true
	}
	ips := certIPs(leaf)
	var out []string
	for _, h := range hosts {
		if local[h] || slices.Contains(out, h) {
			continue
		}
		if a, err := netip.ParseAddr(h); err == nil {
			if !ips[a.Unmap()] {
				out = append(out, h)
			}
		} else if !slices.ContainsFunc(leaf.DNSNames, func(n string) bool { return strings.EqualFold(n, h) }) {
			out = append(out, h)
		}
	}
	return out
}

// selfSignedRenewer serves the box's own self-signed pair through tls.Config.GetCertificate and swaps in
// the renewed certificate while the process runs (a box that is never restarted would otherwise let it
// expire after 825 days). It only ever touches the pair the box made, never an owner's -tls-cert.
type selfSignedRenewer struct {
	certPath, keyPath string
	hosts             []string
	ca                *boxCAStore // the box CA (D-262, D-351)
	now               func() time.Time
	// mgmt is the management addresses of the box from vedette-host (D-139); nil without a host.
	mgmt func(ctx context.Context) ([]netip.Addr, error)
	// box is the box's name for the certificate (certBoxName): "" while vedette-host has not answered since start. nil: no name is
	// looked at (tests of other things).
	box func(ctx context.Context) string
	// addrs are the Box address and the earlier ones the box still answers to (D-465, boxAddr.Names): names of the certificate, added
	// when it lacks one; nil: none.
	addrs func(ctx context.Context) []string
	local func() []string // localNames; a test gives another
	kick  chan struct{}
	gap   time.Duration // between two address checks started by Kick; 0 = addrSyncGap
	// Used by Check only (one goroutine at a time).
	lastMgmt map[netip.Addr]bool // the management addresses of the last answer; nil before the first
	hostDown bool                // the last ask failed: one warning per outage

	mu   sync.RWMutex
	cert *tls.Certificate
}

// leaf is the certificate served now, parsed.
func (r *selfSignedRenewer) leaf() (*x509.Certificate, error) {
	r.mu.RLock()
	c := r.cert
	r.mu.RUnlock()
	return x509.ParseCertificate(c.Certificate[0]) //nolint:wrapcheck // the caller says what failed
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

// Check re-issues the pair, for the same key, when it expires soon, when its IP addresses are not those the
// box has: -hosts, localNames and the management addresses vedette-host reports (D-139), or when it lacks the box's
// name (certBoxName). A host that does not answer, or answers nothing, never removes an address or a name: the
// certificate keeps the ones it has. The new certificate is loaded for new handshakes; the Host allowlist is fixed
// at start (transport), so a name first known after start is answered to from the next start of core.
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
	// An unreadable CA is replaced only when a new leaf is truly required (expiring or expired), so an
	// error that never goes away cannot keep the box from renewing.
	ca, caErr := r.ca.ensure(ctx, r.now(), log, leaf.NotAfter.Sub(r.now()) <= selfSignedRenewBefore)
	hosts := append([]string(nil), r.hosts...)
	// The Box address (D-465): every link carries it, so the certificate names it, and the earlier ones the box still answers to (agents
	// and firewalls set up with them, review M1); one it lacks (a name or address an administrator just saved) re-issues it. A forgotten
	// one leaves at the next re-issue. Unknown (none) changes nothing.
	boxChange := false
	if r.addrs != nil {
		if names := r.addrs(ctx); len(names) > 0 {
			hosts = append(hosts, names...)
			boxChange = len(uncoveredHosts(leaf, names)) > 0
		}
	}
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
	// The box's name (D-316 follow-up of #471): added when vedette-host reports one the certificate lacks (an upgraded box, a host that
	// answered only after start, a renamed machine); a host that has not answered keeps the names the certificate has.
	// The order of the names no longer matters to links: they carry the Box address (D-465), never a name taken from the certificate.
	nameChange := boxChange
	var named []string
	if r.box != nil {
		if box := r.box(ctx); box != "" {
			named = []string{box}
			// "vedette" (no name from the host) is one of localNames: it rides along with the next re-issue, as before.
			nameChange = nameChange || box != fallbackBoxName && !slices.Contains(leaf.DNSNames, box)
		} else {
			named = leaf.DNSNames
		}
	}
	if !addrChange && !nameChange && leaf.NotAfter.Sub(r.now()) > selfSignedRenewBefore && (caErr != nil || !notSignedBy(leaf, ca)) {
		if now != nil {
			r.lastMgmt = now
		}
		if caErr != nil && log != nil { // the leaf in use needs nothing: keep serving it (H-1), say why
			log.WarnContext(ctx, "the box CA is not available; the certificate in use is kept", "error", caErr)
		}
		return nil
	}
	if caErr != nil {
		return caErr
	}
	certPEM, err := selfSignedPEM(ca, signer, append(append(hosts, r.localList()...), named...), r.now())
	if err != nil {
		return err
	}
	if err := writeAtomic(r.certPath, certPEM); err != nil {
		if !addrChange && !nameChange && leaf.NotAfter.After(r.now()) && notSignedBy(leaf, ca) && leaf.NotAfter.Sub(r.now()) > selfSignedRenewBefore {
			if log != nil { // the upgrade under the CA, on a data directory that cannot be written
				log.WarnContext(ctx, "the certificate could not be re-issued under the box CA; the certificate in use is kept", "error", err)
			}
			return nil
		}
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

// selfSignedPEM makes a server certificate for key, signed by the box CA, for hosts and localNames. It is valid
// selfSignedLifetime from NotBefore (an hour back, for clocks a little behind) to NotAfter: Apple's limit of 825 days is
// counted between those two (L-3).
func selfSignedPEM(ca *boxCA, key crypto.Signer, hosts []string, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("tls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Vedette", Organization: []string{selfSignedOrg}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(selfSignedLifetime - time.Hour),
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
