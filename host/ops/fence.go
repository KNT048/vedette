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
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The domain fence (FULL-5 slice 2, D-591, host-api §6.17, plan 2026-11-14 §5). vedette-host makes the box's fence key at its start when
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
// core: advisory, D-591 (3)) check the fence here.

const (
	fenceKeyName     = "fence.key"
	fenceListName    = "fence-domains" // in the state directory
	fenceScanList    = "domains"       // in fenceScanDir, what the worker reads (cmd/vedette-sensor loadFence)
	fenceMaxDomains  = 20              // the plan names no domain cap (§4 caps are per run): the director's 20
	fenceScanDir     = "/var/lib/vedette-fence"
	fenceTimeout     = 2 * time.Minute // exposure.fence_check: three lookups of at most 10 s each, with room
	auditDomainAdded = "fence_domain_added"
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
	f, err := domainfence.New(key, fenceResolver{o}, o.fenceListed, o.d.Now)
	if err != nil {
		o.log.Error("the domain fence cannot start: domain_ip scans are refused", "error", err.Error())
		return
	}
	o.fence = f
	if scan {
		if err := o.fenceScanCopy(fenceKeyName, key); err != nil {
			o.log.Error("the scan container's copy of the domain fence key could not be written: its domain_ip jobs are refused", "error", err.Error())
		}
		if err := o.fenceScanCopy(fenceScanList, domainfence.ListText(list)); err != nil {
			o.log.Error("the scan container's copy of the domain fence list could not be written: its domain_ip jobs are refused", "error", err.Error())
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
	return o.fenceList[domain]
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
// bytes differ (root writes through the directory's 0500).
func (o *Ops) fenceScanCopy(name string, data []byte) error {
	p := filepath.Join(o.path(fenceScanDir), name)
	if have, err := os.ReadFile(p); err != nil || string(have) != string(data) { //nolint:gosec // a fixed path under fenceScanDir
		if err := writeFileAtomic(p, data, 0o400); err != nil {
			return err
		}
	}
	if err := os.Lchown(p, o.cfg.SensorUID, o.cfg.SensorGID); err != nil {
		return err
	}
	return os.Chmod(p, 0o400)
}

// issueToken is exposure.token's work: a domain already on the list gets its token; a new one is added (at most fenceMaxDomains),
// written to the state file and the scan container's copy, and audited, before its token is given.
func (o *Ops) issueToken(domain string) (string, error) {
	o.fenceMu.Lock()
	defer o.fenceMu.Unlock()
	if o.fenceList[domain] {
		return o.fence.Token(domain), nil
	}
	if len(o.fenceList) >= fenceMaxDomains {
		return "", refuse409(api.CodeFenceDomainsFull, "The host has already issued domain fence tokens for its limit of "+strconv.Itoa(fenceMaxDomains)+" domains, so "+domain+" gets none.")
	}
	next := maps.Clone(o.fenceList)
	next[domain] = true
	if err := writeFileAtomic(o.stateFile(fenceListName), domainfence.ListText(next), 0o600); err != nil {
		return "", fail(api.CodeFenceUnavailable, "The host could not record the domain in its fence list.")
	}
	if err := o.noteErr(api.CmdExposureToken, auditDomainAdded, map[string]any{"domain": domain, "domains": len(next)}); err != nil {
		_ = writeFileAtomic(o.stateFile(fenceListName), domainfence.ListText(o.fenceList), 0o600) // not audited: not added
		return "", fail(api.CodeFenceUnavailable, "The host could not audit the new domain, so it issued no token.")
	}
	o.fenceList = next
	if o.cfg.SensorUID > 0 && o.d.FenceKey == nil {
		if err := o.fenceScanCopy(fenceScanList, domainfence.ListText(next)); err != nil {
			o.log.Error("the scan container's copy of the domain fence list could not be written", "error", err.Error())
		}
	}
	return o.fence.Token(domain), nil
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
	if !domainfence.ValidDomain(a.Domain) {
		return server.Invalid("domain", "must be a domain name")
	}
	return nil
}

func (o *Ops) exposureToken(a api.ExposureTokenArgs) (any, error) {
	if err := tokenArgs(a); err != nil {
		return nil, err
	}
	if o.fence == nil {
		return nil, fail(api.CodeFenceUnavailable, "The host has no usable domain fence key; its log says why.")
	}
	tok, err := o.issueToken(a.Domain)
	if err != nil {
		return nil, err
	}
	return api.ExposureTokenResult{Token: tok}, nil
}

// fenceJob validates exposure.fence_check's args at the edge.
func fenceJob(a api.ExposureFenceCheckArgs) (domainfence.Job, error) {
	ip, err := netip.ParseAddr(a.IP)
	if err != nil || ip.String() != a.IP {
		return domainfence.Job{}, server.Invalid(fieldIP, "must be a public IPv4 address")
	}
	j := domainfence.Job{Domain: a.Domain, Name: a.Name, IP: ip, Token: a.Token, Disruptive: a.Disruptive}
	if err := j.Valid(); err != nil {
		return domainfence.Job{}, server.Invalid("domain", err.Error())
	}
	return j, nil
}

// cmdExposureFenceCheck is exposure.fence_check (host-api §6.17): the fence of an OpenVAS scan of a domain's address, right before the
// task starts and every 3 minutes while it runs (core asks; D-591 says why that is weaker than the scan container's fence). Every
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
