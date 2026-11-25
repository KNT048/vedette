package ops

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// box_agent.check (spec 6.19): the osquery agent on the box itself, set up by Vedette's own Linux install command, is stopped and
// its Vedette settings removed when it pins another CA than the one core gives and reports to this machine. Nothing in the request
// names a path or a unit: the files are the fixed ones that install command writes, the unit is osqueryd. The osquery package and
// osquery.conf stay (the install command's --uninstall removes those); running the install command on the box enrols it again.
const (
	boxAgentCA      = "etc/osquery/vedette-ca.pem" // only Vedette's install command writes this file: its presence says the agent is Vedette's
	boxAgentFlags   = "etc/osquery/osquery.flags"
	boxAgentSecret  = "etc/osquery/enroll.secret" //nolint:gosec // G101: the path of the file osquery reads its secret from, not a secret
	boxAgentDropDir = "etc/systemd/system/osqueryd.service.d"
	boxAgentDropIn  = boxAgentDropDir + "/vedette-restart.conf"
	boxAgentDB      = "var/osquery/osquery.db" // osqueryd's node key of the old enrolment and its unsent results
	boxAgentUnit    = "osqueryd.service"
	maxBoxAgentFile = 64 << 10
)

// argsDisableOsqueryd is the one systemctl call of box_agent.check on a unit that is not Vedette's (validateSystemctl).
var argsDisableOsqueryd = []string{"disable", "--now", boxAgentUnit}

func (o *Ops) cmdBoxAgentCheck() server.Command {
	return server.Define(server.Spec[api.BoxAgentCheckArgs]{
		// Not a write command (as os.timezone.set): it touches only osquery's own files and unit, which no other command writes, so
		// core's call at its start is never refused busy by a person's update or backup. boxAgentMu keeps one at a time.
		Name: api.CmdBoxAgentCheck, Write: false, Timeout: 2 * time.Minute,
		Validate: func(a *api.BoxAgentCheckArgs) error {
			if api.ParseAnchor([]byte(a.CA)) == nil {
				return server.Invalid("ca", "must be one or more PEM certificates, at most 16 KiB")
			}
			return nil
		},
		Run: func(ctx context.Context, rc *server.RunContext, a api.BoxAgentCheckArgs) (any, error) {
			o.boxAgentMu.Lock()
			defer o.boxAgentMu.Unlock()
			pinned, ok, err := o.readBoxAgentFile(boxAgentCA)
			if err != nil {
				return nil, err
			}
			if !ok {
				return api.BoxAgentCheckResult{State: api.BoxAgentNone}, nil
			}
			if anchorHolds(api.ParseAnchor([]byte(a.CA)), api.ParseAnchor(pinned)) {
				return api.BoxAgentCheckResult{State: api.BoxAgentCurrent}, nil
			}
			flags, _, err := o.readBoxAgentFile(boxAgentFlags)
			if err != nil {
				return nil, err
			}
			host := tlsHostOf(flags)
			if !o.isThisMachine(ctx, host) {
				rc.Log("The osquery agent on this machine reports to " + clipText(host, 120) + ", not to this box: left as it is.")
				return api.BoxAgentCheckResult{State: api.BoxAgentElsewhere}, nil
			}
			rc.Log("The osquery agent on this box pins a certificate authority the box no longer has (a reinstall or a data purge made a new one): stopping it and removing its Vedette settings.")
			if err := o.removeBoxAgent(ctx, rc); err != nil {
				return nil, err
			}
			return api.BoxAgentCheckResult{State: api.BoxAgentRemoved}, nil
		},
	})
}

// readBoxAgentFile reads one of the install command's files; ok is false when it does not exist. A link or anything but a small
// regular file is not what that command writes: it is an error, and nothing is removed.
func (o *Ops) readBoxAgentFile(rel string) ([]byte, bool, error) {
	p := o.path(rel)
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxBoxAgentFile {
		return nil, false, fail(api.CodeEffectNotVerified, "/"+rel+" is not a regular file of at most 64 KiB; it was left as it is.")
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: one of the fixed paths above under the root of Deps, never from a request
	return b, err == nil, err
}

// anchorHolds says whether the agent's pinned file holds one of the certificates core gave (the box CA, or a certificate of an
// owner's chain): such an agent still trusts the box.
func anchorHolds(now, pinned []*x509.Certificate) bool {
	for _, p := range pinned {
		for _, c := range now {
			if bytes.Equal(p.Raw, c.Raw) {
				return true
			}
		}
	}
	return false
}

// tlsHostOf is the host part of --tls_hostname in osquery.flags ("" when there is none).
func tlsHostOf(flags []byte) string {
	for line := range strings.SplitSeq(string(flags), "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "--tls_hostname=")
		if !ok {
			continue
		}
		if h, _, err := net.SplitHostPort(v); err == nil {
			return h
		}
		return strings.Trim(v, "[]")
	}
	return ""
}

// isThisMachine says whether host names this machine: a loopback address, an address of one of its cards, its host name (short or
// full), or a name the resolver answers with one of those addresses. Anything else (another box, a name that does not resolve) is not.
func (o *Ops) isThisMachine(ctx context.Context, host string) bool {
	if host == "" {
		return false
	}
	local := func(a netip.Addr) bool {
		a = a.Unmap()
		if a.IsLoopback() {
			return true
		}
		ifaces, err := o.d.Interfaces()
		if err != nil {
			return false
		}
		for _, i := range ifaces {
			for _, p := range i.Addrs {
				if p.Addr().Unmap() == a {
					return true
				}
			}
		}
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return local(a)
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if name == "localhost" {
		return true
	}
	if hn, err := o.d.Hostname(); err == nil && hn != "" {
		hn = strings.ToLower(hn)
		short, _, _ := strings.Cut(hn, ".")
		if name == hn || name == short {
			return true
		}
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := o.d.LookupHost(lctx, name)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if local(a) {
			return true
		}
	}
	return false
}

// removeBoxAgent stops and disables osqueryd, then removes what Vedette's install command wrote: the restart drop-in, the flags, the
// enroll secret, osquery's database (the old node key) and, last, the pinned CA, so a run cut short is done again at core's next start.
func (o *Ops) removeBoxAgent(ctx context.Context, rc *server.RunContext) error {
	if res, code, err := o.exec(ctx, binSystemctl, argsDisableOsqueryd...); err != nil {
		return err
	} else if code != 0 {
		// a unit that is gone (the osquery package was removed by hand) cannot be disabled: its files go all the same
		rc.Log("systemctl disable --now osqueryd.service exited " + strconv.Itoa(code) + ": " + clipText(strings.TrimSpace(string(res.Stderr)), 200))
	}
	if err := removeIfThere(o.path(boxAgentDropIn)); err != nil {
		return err
	}
	_ = os.Remove(o.path(boxAgentDropDir)) // only when empty: another drop-in stays with its folder
	if _, code, err := o.exec(ctx, binSystemctl, "daemon-reload"); err != nil {
		return err
	} else if code != 0 {
		rc.Log("systemctl daemon-reload exited " + strconv.Itoa(code))
	}
	for _, rel := range []string{boxAgentFlags, boxAgentSecret} {
		if err := removeIfThere(o.path(rel)); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(o.path(boxAgentDB)); err != nil { // a link there is removed, never followed
		return err
	}
	return removeIfThere(o.path(boxAgentCA))
}
