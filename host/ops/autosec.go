package ops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

const autoSecurityFile = "etc/apt/apt.conf.d/52vedette-unattended"

// autoSecurityTemplate renders the fixed apt configuration of unattended security updates for a
// distribution. It sorts after the distribution's own 50unattended-upgrades and 20auto-upgrades, so
// "#clear" first drops every origin they allow (updates, proposed, ...) and only this
// distribution's security pocket is added back. Nothing in it comes from a request except the
// on/off switch, which is "1" or "0".
func autoSecurityTemplate(distro string, enabled bool) string {
	sw := "0"
	if enabled {
		sw = "1"
	}
	var b strings.Builder
	b.WriteString("// Managed by vedette-host (os.auto_security.set). Changes are overwritten.\n")
	b.WriteString("#clear Unattended-Upgrade::Allowed-Origins;\n")
	b.WriteString("#clear Unattended-Upgrade::Origins-Pattern;\n")
	switch distro {
	case "ubuntu":
		b.WriteString("Unattended-Upgrade::Allowed-Origins {\n")
		b.WriteString("\t\"${distro_id}:${distro_codename}-security\";\n")
		b.WriteString("\t\"${distro_id}ESMApps:${distro_codename}-apps-security\";\n")
		b.WriteString("\t\"${distro_id}ESM:${distro_codename}-infra-security\";\n")
		b.WriteString("};\n")
	default: // debian
		b.WriteString("Unattended-Upgrade::Origins-Pattern {\n")
		b.WriteString("\t\"origin=Debian,codename=${distro_codename}-security,label=Debian-Security\";\n")
		b.WriteString("};\n")
	}
	b.WriteString("Unattended-Upgrade::Automatic-Reboot \"false\";\n")
	b.WriteString("APT::Periodic::Update-Package-Lists \"1\";\n")
	b.WriteString("APT::Periodic::Unattended-Upgrade \"" + sw + "\";\n")
	return b.String()
}

// cmdAutoSecurity is os.auto_security.set (spec 6.3).
func (o *Ops) cmdAutoSecurity() server.Command {
	return server.Define(server.Spec[api.OSAutoSecurityArgs]{
		Name: api.CmdOSAutoSecuritySet, Write: true, Timeout: 2 * time.Minute,
		Check: func(context.Context, api.OSAutoSecurityArgs) error {
			_, err := o.platform()
			return err
		},
		Run: func(ctx context.Context, rc *server.RunContext, a api.OSAutoSecurityArgs) (any, error) {
			plat, err := o.platform()
			if err != nil {
				return nil, err
			}
			path := o.path(autoSecurityFile)
			if st, err := os.Stat(filepath.Dir(path)); err != nil || !st.IsDir() {
				return nil, fail("apt_not_configured", "The apt configuration directory is missing.")
			}
			rc.Log("Writing " + autoSecurityFile)
			if err := writeFileAtomic(path, []byte(autoSecurityTemplate(plat.Distro, a.Enabled)), 0o644); err != nil {
				return nil, fail("write_failed", "The apt configuration file could not be written.")
			}
			verb := "disable"
			if a.Enabled {
				verb = "enable"
			}
			rc.Log("Setting the apt timers: " + verb)
			args := append([]string{verb, "--now"}, aptTimers...)
			if _, _, err := o.exec(ctx, binSystemctl, args...); err != nil {
				return nil, err
			}
			rc.Progress(70)
			if err := o.verifyAutoSecurity(ctx, a.Enabled); err != nil {
				return nil, err
			}
			return api.OSAutoSecurityResult(a), nil
		},
	})
}

// verifyAutoSecurity reads the effect back, ignoring exit codes: what apt will actually use
// (apt-config dump) and the state of both timers (systemctl is-enabled prints it, and exits
// non-zero for "disabled").
func (o *Ops) verifyAutoSecurity(ctx context.Context, enabled bool) error {
	res, code, err := o.exec(ctx, binAptConfig, "dump")
	if err != nil {
		return err
	}
	if code != 0 {
		return fail(api.CodeEffectNotVerified, "apt-config could not read the configuration back.")
	}
	cfg := ParseAptConfig(res.Stdout)
	if cfg.Enabled() != enabled {
		return fail(api.CodeEffectNotVerified, fmt.Sprintf("apt does not use the setting that was written (unattended upgrades are %s).", onOff(cfg.Enabled())))
	}
	if enabled && !cfg.SecurityOnly() {
		return fail(api.CodeEffectNotVerified, "apt still allows origins other than the security pocket; check the other files in /etc/apt/apt.conf.d.")
	}
	want := "disabled"
	if enabled {
		want = "enabled"
	}
	for _, t := range aptTimers {
		out, _, err := o.exec(ctx, binSystemctl, "is-enabled", t)
		if err != nil {
			return err
		}
		if got := strings.TrimSpace(string(out.Stdout)); got != want {
			return fail(api.CodeEffectNotVerified, fmt.Sprintf("%s is %s, expected %s.", t, clipText(got, 20), want))
		}
	}
	return nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
