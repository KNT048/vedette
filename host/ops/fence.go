package ops

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The domain fence (FULL-5 slice 2, D-591, host-api §6.17, plan 2026-11-14 §5). vedette-host makes the box's fence key at its start when
// it is missing: <state>/fence.key, 32 random bytes, 0600, owned by the host's owner (root). Core never holds it: core asks
// exposure.token for a verified domain's box-bound token, and every executor checks a domain_ip job against the key itself. The scan
// container gets its own read-only copy: fenceScanDir/fence.key, owned by the sensor user (0400 in a 0500 directory), mounted at the
// same path by the scan unit only (scanUnitText); core's unit never mounts it nor the host's state directory. zap.baseline (kind
// domain) and exposure.fence_check (OpenVAS) check the fence here.

const (
	fenceKeyName = "fence.key"
	// fenceScanDir holds the scan container's copy of the key; the scan unit mounts it read-only at the same path.
	fenceScanDir = "/var/lib/vedette-fence"
	fenceTimeout = 2 * time.Minute // exposure.fence_check: three lookups of at most 10 s each, with room
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

// initFence loads or makes the key and the scan container's copy. A failure leaves o.fence nil (exposure.token and the domain checks
// then refuse fence_unavailable) and is logged; nothing else of the host depends on it.
func (o *Ops) initFence() {
	key := o.d.FenceKey
	if key == nil {
		var err error
		if key, err = o.fenceKey(); err != nil {
			o.log.Error("the domain fence key is not usable: domain_ip scans are refused", "error", err.Error())
			return
		}
	}
	f, err := domainfence.New(key, fenceResolver{o}, o.d.Now)
	if err != nil {
		o.log.Error("the domain fence cannot start: domain_ip scans are refused", "error", err.Error())
		return
	}
	o.fence = f
	if o.cfg.SensorUID > 0 && o.d.FenceKey == nil {
		if err := o.fenceScanCopy(key); err != nil {
			o.log.Error("the scan container's copy of the domain fence key could not be written: its domain_ip jobs are refused", "error", err.Error())
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

// fenceScanCopy writes the key for the scan container: fenceScanDir (0500) and its fence.key (0400), both owned by the sensor user,
// rewritten only when the bytes differ.
func (o *Ops) fenceScanCopy(key []byte) error {
	dir := o.path(fenceScanDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := filepath.Join(dir, fenceKeyName)
	if have, err := domainfence.LoadKey(p); err != nil || string(have) != string(key) {
		if err := writeFileAtomic(p, key, 0o400); err != nil {
			return err
		}
	}
	for _, x := range []struct {
		path string
		mode os.FileMode
	}{{p, 0o400}, {dir, 0o500}} {
		if err := os.Lchown(x.path, o.cfg.SensorUID, o.cfg.SensorGID); err != nil {
			return err
		}
		if err := os.Chmod(x.path, x.mode); err != nil {
			return err
		}
	}
	return nil
}

// fenceRefusal maps a refusal of the fence to the host's code: a refusal (412) for a fact about the target, a failure for
// "could not check".
func fenceRefusal(o domainfence.Outcome, what string) error {
	switch o.Reason {
	case domainfence.TokenForeign:
		return refuse412(api.CodeTokenForeign, "The token is not this box's token for the domain (it was made before the box's domain fence, or by another box), so "+what+" was not started. Verify the domain again and add the TXT value it shows.")
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
	return api.ExposureTokenResult{Token: o.fence.Token(a.Domain)}, nil
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
	res := o.fence.Check(ctx, j, true)
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
