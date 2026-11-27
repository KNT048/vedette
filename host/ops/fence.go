package ops

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/core/domainfence/proofat"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The domain fence (host-api §6.17). vedette-host makes the box's fence key at its start when
// it is missing: <state>/fence.key, 32 random bytes, 0600, owned by the host's owner (root). Core never holds it: core asks
// exposure.token for a verified domain's box-bound token, and every executor checks a domain_ip job against the key itself.
//
// The host also keeps its own list of the domains it issued a token for (review r1 H1): <state>/fence-domains, root 0600, at most
// fenceMaxDomains; each new domain is an audit line of the host (fence_domain_added) that core cannot suppress, a domain beyond the
// cap is refused (fence_domains_full), and every executor refuses a domain that is not on the list. That bounds what a compromised
// core can do with the fence: it can still ask for tokens of domains of its own, up to the cap, each one audited.
//
// The scan container gets read-only copies of the key and the list in fenceScanDir (the directory 0500, the files 0400, owned by the
// sensor user), mounted at the same path by the scan unit only (scanUnitText); core's unit never mounts them nor the host's state
// directory. The directory is made even when the key is not usable (review r1 L1): the scan unit's mount needs it, and a worker
// without a key simply runs no domain_ip job. zap.baseline (kind domain, box-bound token) and exposure.fence_check (OpenVAS, asked by
// core: advisory) check the fence here.

const (
	fenceKeyName     = "fence.key"
	fenceListName    = "fence-domains" // in the state directory
	fenceIPsName     = "fence-ips"     // the typed public IPs, in the state directory
	fenceScanIPs     = "ips"           // in fenceScanDir, beside "domains"
	fenceMaxIPs      = 20              // typed IPs have a cap of their own, so unproved or many IPs never take a domain's place
	fenceScanList    = "domains"       // in fenceScanDir, what the worker reads (cmd/vedette-sensor loadFence)
	fenceMaxDomains  = 20              // the plan names no domain cap (§4 caps are per run): the director's 20
	fenceScanDir     = "/var/lib/vedette-fence"
	fenceTimeout     = 2 * time.Minute // exposure.fence_check: three lookups of at most 10 s each, with room
	auditDomainAdded = "fence_domain_added"
	// the line of a domain whose audit was written but whose list write failed (review r2 L-1), and the removal's two
	auditDomainNotAdded   = "fence_domain_not_added"
	auditDomainRemoved    = "fence_domain_removed"
	auditDomainNotRemoved = "fence_domain_not_removed"
)

// fenceResolver is the system resolver as the fence asks it, through the seams the zap tests already answer for (ZapTXT, ZapLookupIP)
// and Deps.FenceCNAME.
type fenceResolver struct{ o *Ops }

func (r fenceResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.o.zapTXT(ctx, name)
}
func (r fenceResolver) LookupNetIP(ctx context.Context, _, name string) ([]netip.Addr, error) {
	return r.o.zapLookupIP(ctx, name)
}

func (r fenceResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	if r.o.d.FenceCNAME != nil {
		return r.o.d.FenceCNAME(ctx, name)
	}
	return net.DefaultResolver.LookupCNAME(ctx, name)
}

// AuthTXT asks the zone's own name servers when the resolver's answer proves nothing (domainfence.Owned): Deps.FenceAuth, else the
// real servers when the TXT lookup is the system resolver's. A test world that answers ZapTXT without FenceAuth has none, so no test
// asks real DNS.
func (r fenceResolver) AuthTXT(ctx context.Context, name string) (domainfence.AuthAnswer, error) {
	switch {
	case r.o.d.FenceAuth != nil:
		return r.o.d.FenceAuth(ctx, name)
	case r.o.d.ZapTXT != nil:
		return domainfence.AuthAnswer{}, errors.New("the zone's name servers are not asked in this world")
	}
	return systemAuthority.AuthTXT(ctx, name)
}

// systemAuthority asks the zone's own name servers, found through the system resolver.
var systemAuthority = &domainfence.Authoritative{R: net.DefaultResolver}

// initFence loads or makes the key, loads the domain list and writes the scan container's copies. A failure leaves o.fence nil
// (exposure.token and the domain checks then refuse fence_unavailable) and is logged; nothing else of the host depends on it.
func (o *Ops) initFence() {
	scan := o.cfg.SensorUID > 0 && o.d.FenceKey == nil
	if scan { // review r1 L1: the scan unit mounts the directory, so it exists whatever happens to the key
		if err := o.fenceScanDir(0o700); err != nil {
			o.log.Error("the scan container's domain fence directory could not be made", "error", err.Error())
			scan = false
		} else {
			defer func() { // read-only for its owner once the copies are written (a worker without them runs no domain_ip job)
				if err := o.fenceScanDir(0o500); err != nil {
					o.log.Error("the scan container's domain fence directory could not be closed", "error", err.Error())
				}
			}()
		}
	}
	key := o.d.FenceKey
	if key == nil {
		var err error
		if key, err = o.fenceKey(); err != nil {
			o.log.Error("the domain fence key is not usable: domain_ip scans are refused", "error", err.Error())
			return
		}
	}
	list, err := o.loadFenceList()
	if err != nil {
		o.log.Error("the domain fence list is not usable: domain_ip scans are refused", "error", err.Error())
		return
	}
	o.fenceList = list
	ips, err := o.loadFenceIPs()
	if err != nil {
		o.log.Error("the typed IP fence list is not usable: typed IP scans are refused", "error", err.Error())
		ips = map[string]bool{}
	}
	o.fenceIPs = ips
	f, err := domainfence.New(key, fenceResolver{o}, o.fenceListed, o.d.Now)
	if err != nil {
		o.log.Error("the domain fence cannot start: domain_ip scans are refused", "error", err.Error())
		return
	}
	if o.d.FenceFetcher != nil {
		f.SetFetcher(o.d.FenceFetcher)
	}
	o.fence = f
	if scan {
		if err := o.fenceScanCopy(fenceKeyName, key); err != nil {
			o.log.Error("the scan container's copy of the domain fence key could not be written: its domain_ip jobs are refused", "error", err.Error())
		}
		if err := o.fenceScanCopy(fenceScanList, domainfence.ListText(list)); err != nil {
			o.log.Error("the scan container's copy of the domain fence list could not be written: its domain_ip jobs are refused", "error", err.Error())
		}
		if err := o.fenceScanCopy(fenceScanIPs, domainfence.ListText(ips)); err != nil {
			o.log.Error("the scan container's copy of the typed IP list could not be written: its typed IP jobs are refused", "error", err.Error())
		}
	}
}

// fenceKey reads <state>/fence.key, or makes it when it is not there (idempotent: an existing key is never replaced, so tokens stay).
func (o *Ops) fenceKey() ([]byte, error) {
	p := o.stateFile(fenceKeyName)
	key, err := domainfence.LoadKey(p)
	if errors.Is(err, fs.ErrNotExist) {
		if err := writeFileAtomic(p, domainfence.NewKey(), 0o600); err != nil {
			return nil, err
		}
		key, err = domainfence.LoadKey(p)
	}
	return key, err
}

// loadFenceList reads <state>/fence-domains (missing: an empty list).
func (o *Ops) loadFenceList() (map[string]bool, error) {
	p := o.stateFile(fenceListName)
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("ops: the domain fence list is not a regular file")
	}
	b, err := os.ReadFile(p) //nolint:gosec // the host's own state file, Lstat-ed as a regular file above
	if err != nil {
		return nil, err
	}
	return domainfence.ParseList(b)
}

func (o *Ops) fenceListed(domain string) bool {
	o.fenceMu.Lock()
	defer o.fenceMu.Unlock()
	if domainfence.ValidIPLiteral(domain) {
		return o.fenceIPs[domain]
	}
	return o.fenceList[domain]
}

// loadFenceIPs reads <state>/fence-ips (missing: none).
func (o *Ops) loadFenceIPs() (map[string]bool, error) {
	p := o.stateFile(fenceIPsName)
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("ops: the typed IP fence list is not a regular file")
	}
	b, err := os.ReadFile(p) //nolint:gosec // the host's own state file, Lstat-ed as a regular file above
	if err != nil {
		return nil, err
	}
	return domainfence.ParseIPList(b)
}

// fenceScanDir makes fenceScanDir, owned by the sensor user, with mode (0700 while the host writes the copies, then 0500).
func (o *Ops) fenceScanDir(mode os.FileMode) error {
	dir := o.path(fenceScanDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("ops: " + dir + " is not a directory")
	}
	if err := os.Lchown(dir, o.cfg.SensorUID, o.cfg.SensorGID); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}

// fenceScanCopy writes one file for the scan container in fenceScanDir: 0400, owned by the sensor user, rewritten only when the
// bytes differ (root writes through the directory's 0500). A new file is made whole beside the old one, given its owner and mode, and
// renamed over it (review r2 L-2): a reader sees the old file or the new one, never one it may not read.
func (o *Ops) fenceScanCopy(name string, data []byte) error {
	dir := o.path(fenceScanDir)
	p := filepath.Join(dir, name)
	if have, err := os.ReadFile(p); err == nil && string(have) == string(data) { //nolint:gosec // a fixed path under fenceScanDir
		if err := os.Lchown(p, o.cfg.SensorUID, o.cfg.SensorGID); err != nil {
			return err
		}
		return os.Chmod(p, 0o400)
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // gone after the rename; left only on a failure
	_, werr := f.Write(data)
	for _, err := range []error{werr, f.Sync(), f.Chown(o.cfg.SensorUID, o.cfg.SensorGID), f.Chmod(0o400), f.Close()} {
		if err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// fenceScanList rewrites the worker's copy of the list from the host's (review r2 L-3: at every fence op, not only on a change, so a
// copy that once failed to write is put right by the next op), logged when it fails.
func (o *Ops) fenceScanList(list map[string]bool) {
	if o.cfg.SensorUID <= 0 || o.d.FenceKey != nil {
		return
	}
	if err := o.fenceScanCopy(fenceScanList, domainfence.ListText(list)); err != nil {
		o.log.Error("the scan container's copy of the domain fence list could not be written", "error", err.Error())
	}
}

// fenceScanIPList rewrites the worker's copy of the typed IP list, logged when it fails.
func (o *Ops) fenceScanIPList(list map[string]bool) {
	if o.cfg.SensorUID <= 0 || o.d.FenceKey != nil {
		return
	}
	if err := o.fenceScanCopy(fenceScanIPs, domainfence.ListText(list)); err != nil {
		o.log.Error("the scan container's copy of the typed IP list could not be written", "error", err.Error())
	}
}

// listIP is exposure.token's work for a typed IP core says is proved: on the host's IP list (its own file and cap, audited first, then
// the state file, then the scan container's copy), idempotent.
func (o *Ops) listIP(ip string) error {
	o.fenceMu.Lock()
	defer o.fenceMu.Unlock()
	if o.fenceIPs[ip] {
		return nil
	}
	if len(o.fenceIPs) >= fenceMaxIPs {
		return refuse409(api.CodeFenceDomainsFull, "The host has already listed its limit of "+strconv.Itoa(fenceMaxIPs)+" typed public IPs, so "+ip+" is not listed. Deleting an IP target frees its place.")
	}
	next := maps.Clone(o.fenceIPs)
	next[ip] = true
	if err := o.noteErr(api.CmdExposureToken, auditDomainAdded, map[string]any{"domain": ip, "domains": len(next)}); err != nil {
		return fail(api.CodeFenceUnavailable, "The host could not audit the new IP, so it did not list it.")
	}
	if err := writeFileAtomic(o.stateFile(fenceIPsName), domainfence.ListText(next), 0o600); err != nil {
		o.note(api.CmdExposureToken, auditDomainNotAdded, map[string]any{"domain": ip})
		return fail(api.CodeFenceUnavailable, "The host could not record the IP in its fence list.")
	}
	o.fenceIPs = next
	o.fenceScanIPList(next)
	return nil
}

// forgetIP takes a typed IP off the host's IP list (idempotent).
func (o *Ops) forgetIP(ip string) (bool, error) {
	o.fenceMu.Lock()
	defer o.fenceMu.Unlock()
	if !o.fenceIPs[ip] {
		return false, nil
	}
	next := maps.Clone(o.fenceIPs)
	delete(next, ip)
	if err := o.noteErr(api.CmdExposureTokenForget, auditDomainRemoved, map[string]any{"domain": ip, "domains": len(next)}); err != nil {
		return false, fail(api.CodeFenceUnavailable, "The host could not audit the removal, so the IP stays on its fence list.")
	}
	if err := writeFileAtomic(o.stateFile(fenceIPsName), domainfence.ListText(next), 0o600); err != nil {
		o.note(api.CmdExposureTokenForget, auditDomainNotRemoved, map[string]any{"domain": ip})
		return false, fail(api.CodeFenceUnavailable, "The host could not write its fence list, so the IP stays on it.")
	}
	o.fenceIPs = next
	o.fenceScanIPList(next)
	return true, nil
}

// issueToken is exposure.token's work: a domain already on the list gets its token; a new one (at most fenceMaxDomains) is audited
// first (review r2 L-1: a crash after it over-reports, never hides a domain), then written to the state file, then to the scan
// container's copy, before its token is given.
func (o *Ops) issueToken(domain string) (string, error) {
	o.fenceMu.Lock()
	defer o.fenceMu.Unlock()
	if o.fenceList[domain] {
		o.fenceScanList(o.fenceList)
		return o.fence.Token(domain), nil
	}
	if len(o.fenceList) >= fenceMaxDomains {
		return "", refuse409(api.CodeFenceDomainsFull, "The host has already issued domain fence tokens for its limit of "+strconv.Itoa(fenceMaxDomains)+" domains, so "+domain+" gets none. Deleting a domain target frees its place.")
	}
	next := maps.Clone(o.fenceList)
	next[domain] = true
	if err := o.noteErr(api.CmdExposureToken, auditDomainAdded, map[string]any{"domain": domain, "domains": len(next)}); err != nil {
		return "", fail(api.CodeFenceUnavailable, "The host could not audit the new domain, so it issued no token.")
	}
	if err := writeFileAtomic(o.stateFile(fenceListName), domainfence.ListText(next), 0o600); err != nil {
		o.note(api.CmdExposureToken, auditDomainNotAdded, map[string]any{"domain": domain})
		return "", fail(api.CodeFenceUnavailable, "The host could not record the domain in its fence list.")
	}
	o.fenceList = next
	o.fenceScanList(next)
	return o.fence.Token(domain), nil
}

// forgetToken is exposure.token_forget's work (review r2 M-A): the domain off the list (audited first, then the state file, then the
// scan container's copy); a domain not on the list changes nothing (idempotent) but the copy is written again.
func (o *Ops) forgetToken(domain string) (bool, error) {
	o.fenceMu.Lock()
	defer o.fenceMu.Unlock()
	if !o.fenceList[domain] {
		o.fenceScanList(o.fenceList)
		return false, nil
	}
	next := maps.Clone(o.fenceList)
	delete(next, domain)
	if err := o.noteErr(api.CmdExposureTokenForget, auditDomainRemoved, map[string]any{"domain": domain, "domains": len(next)}); err != nil {
		return false, fail(api.CodeFenceUnavailable, "The host could not audit the removal, so the domain stays on its fence list.")
	}
	if err := writeFileAtomic(o.stateFile(fenceListName), domainfence.ListText(next), 0o600); err != nil {
		o.note(api.CmdExposureTokenForget, auditDomainNotRemoved, map[string]any{"domain": domain})
		return false, fail(api.CodeFenceUnavailable, "The host could not write its fence list, so the domain stays on it.")
	}
	o.fenceList = next
	o.fenceScanList(next)
	return true, nil
}

// cmdExposureTokenForget is exposure.token_forget (host-api §6.17). Read only for the system, no lock.
func (o *Ops) cmdExposureTokenForget() server.Command {
	return server.Define(server.Spec[api.ExposureTokenArgs]{
		Name: api.CmdExposureTokenForget, Write: false, Timeout: 10 * time.Second,
		Validate: func(a *api.ExposureTokenArgs) error { return tokenArgs(*a) },
		Run: func(_ context.Context, _ *server.RunContext, a api.ExposureTokenArgs) (any, error) {
			return o.exposureTokenForget(a)
		},
	})
}

func (o *Ops) exposureTokenForget(a api.ExposureTokenArgs) (any, error) {
	if err := tokenArgs(a); err != nil {
		return nil, err
	}
	if o.fence == nil {
		return nil, fail(api.CodeFenceUnavailable, "The host has no usable domain fence; its log says why.")
	}
	forget := o.forgetToken
	if domainfence.ValidIPLiteral(a.Domain) {
		forget = o.forgetIP
	}
	removed, err := forget(a.Domain)
	if err != nil {
		return nil, err
	}
	return api.ExposureTokenForgetResult{Removed: removed}, nil
}

// noteErr is note that says whether the audit line was written (no notifier, as in a test without a server, counts as written: nothing
// is listening, as for note).
func (o *Ops) noteErr(command, code string, detail map[string]any) error {
	o.mu.Lock()
	n, nw := o.notifier, o.noteOnly
	o.mu.Unlock()
	switch {
	case n != nil:
		return n.Note(command, code, detail)
	case nw != nil:
		return nw.Note(command, code, detail)
	}
	return nil
}

// fenceRefusal maps a refusal of the fence to the host's code: a refusal (412) for a fact about the target, a failure for
// "could not check".
func fenceRefusal(o domainfence.Outcome, what string) error {
	switch o.Reason {
	case domainfence.TokenForeign:
		return refuse412(api.CodeTokenForeign, "The token is not one this box's host issued for the domain (made before the box's domain fence, by another box, or for a domain not on the host's list), so "+what+" was not started.")
	case domainfence.NotOwned:
		return refuse412(api.CodeTargetNotOwned, "The domain no longer has its vedette-verify TXT record with this box's token, so "+what+" was not started.")
	case domainfence.NameMoved:
		return refuse412(api.CodeNameMoved, "The name no longer points at the address, so "+what+" was not started there.")
	case domainfence.CNAMEOutside:
		return refuse412(api.CodeCNAMEOutside, "The name points (CNAME) outside the domain, so the disruptive checks of "+what+" were not started.")
	case domainfence.Unchecked:
		return fail(api.CodeOwnershipUnchecked, "A DNS lookup of the domain fence failed, so "+what+" was not started.")
	}
	return server.Invalid("domain", o.Detail)
}

// cmdExposureToken is exposure.token (host-api §6.17): the box-bound token of a domain. Read only, no lock.
func (o *Ops) cmdExposureToken() server.Command {
	return server.Define(server.Spec[api.ExposureTokenArgs]{
		Name: api.CmdExposureToken, Write: false, Timeout: 10 * time.Second,
		Validate: func(a *api.ExposureTokenArgs) error { return tokenArgs(*a) },
		Run: func(_ context.Context, _ *server.RunContext, a api.ExposureTokenArgs) (any, error) {
			return o.exposureToken(a)
		},
	})
}

func tokenArgs(a api.ExposureTokenArgs) error {
	if !domainfence.ValidDomain(a.Domain) && !domainfence.ValidIPLiteral(a.Domain) { // a typed public IP is listed like a domain
		return server.Invalid("domain", "must be a domain name or a public IPv4 address")
	}
	return nil
}

func (o *Ops) exposureToken(a api.ExposureTokenArgs) (any, error) {
	if err := tokenArgs(a); err != nil {
		return nil, err
	}
	// The host does not trust core, so it never issues a token for a public suffix (co.uk, ddns.net,
	// github.io: the Public Suffix List, both sections), whose record at _vedette-verify.<suffix> could otherwise prove every customer's
	// name under it at the fence. Forgetting one stays possible.
	if !domainfence.ValidIPLiteral(a.Domain) && proofat.IsPublicSuffix(a.Domain) {
		return nil, server.Invalid("domain", "is a public suffix (like co.uk or ddns.net), under which many owners register their names; no token is issued for it")
	}
	if o.fence == nil {
		return nil, fail(api.CodeFenceUnavailable, "The host has no usable domain fence key; its log says why.")
	}
	if domainfence.ValidIPLiteral(a.Domain) { // a typed IP: its token is the box's HMAC; it takes a list place only once core says it is proved
		if a.Proved {
			if err := o.listIP(a.Domain); err != nil {
				return nil, err
			}
		}
		return api.ExposureTokenResult{Token: o.fence.Token(a.Domain)}, nil
	}
	tok, err := o.issueToken(a.Domain)
	if err != nil {
		return nil, err
	}
	return api.ExposureTokenResult{Token: tok}, nil
}

// typedProof is the fence's form of a typed IP's proof, nil for none.
func typedProof(t *api.ExposureTyped) *domainfence.TypedProof {
	if t == nil {
		return nil
	}
	return &domainfence.TypedProof{Method: t.Method, PTRName: t.PTRName, CoverDomain: t.CoverDomain, CoverToken: t.CoverToken, CoverProofAt: t.CoverProofAt}
}

// LookupAddr is the fence resolver's reverse DNS (a typed IP proved by its PTR name).
func (r fenceResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if r.o.d.FenceAddr != nil {
		return r.o.d.FenceAddr(ctx, addr)
	}
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

// fenceJob validates exposure.fence_check's args at the edge.
func fenceJob(a api.ExposureFenceCheckArgs) (domainfence.Job, error) {
	ip, err := netip.ParseAddr(a.IP)
	if err != nil || ip.String() != a.IP {
		return domainfence.Job{}, server.Invalid(fieldIP, "must be a public IPv4 address")
	}
	j := domainfence.Job{Domain: a.Domain, Name: a.Name, IP: ip, Token: a.Token, Disruptive: a.Disruptive, ProofAt: a.ProofAt, Typed: typedProof(a.Typed)}
	if err := j.Valid(); err != nil {
		return domainfence.Job{}, server.Invalid("domain", err.Error())
	}
	// The host trusts no core: the parent name a record is looked for on lies between the domain and its registered domain,
	// never on or above a public suffix (co.uk, ddns.net, github.io, s3.amazonaws.com; review r1 L1 of #960)
	if j.ProofAt != "" && (!proofat.Within(j.Domain, j.ProofAt) || !proofat.Within(j.Name, j.ProofAt)) {
		return domainfence.Job{}, server.Invalid("proof_at", "must be a parent name of the domain and of the name, down to its registered domain")
	}
	return j, nil
}

// cmdExposureFenceCheck is exposure.fence_check (host-api §6.17): the fence of an OpenVAS scan of a domain's address, right before the
// task starts and every 3 minutes while it runs (core asks; that is weaker than the scan container's fence). Every
// answer is a run, so the audit chain holds each refusal.
func (o *Ops) cmdExposureFenceCheck() server.Command {
	return server.Define(server.Spec[api.ExposureFenceCheckArgs]{
		Name: api.CmdExposureFenceCheck, Write: false, Timeout: fenceTimeout,
		Validate: func(a *api.ExposureFenceCheckArgs) error { _, err := fenceJob(*a); return err },
		Run: func(ctx context.Context, rc *server.RunContext, a api.ExposureFenceCheckArgs) (any, error) {
			return o.fenceCheck(ctx, rc.Log, a)
		},
	})
}

func (o *Ops) fenceCheck(ctx context.Context, logf func(string), a api.ExposureFenceCheckArgs) (any, error) {
	j, err := fenceJob(a)
	if err != nil {
		return nil, err
	}
	if o.fence == nil {
		return nil, fail(api.CodeFenceUnavailable, "The host has no usable domain fence key; its log says why.")
	}
	res := o.fence.Check(ctx, j, !a.Recheck) // review r1 M2: a re-check while the task runs always asks DNS again
	logf("domain fence of " + j.Name + " (" + j.Domain + ") at " + j.IP.String() + ", CNAME chain " + res.ChainText() + ": " + orYes(res.Reason))
	if res.Reason != "" {
		return nil, fenceRefusal(res, "OpenVAS")
	}
	return api.ExposureFenceCheckResult{Chain: res.ChainText()}, nil
}

func orYes(reason string) string {
	if reason == "" {
		return "yes"
	}
	return reason
}
