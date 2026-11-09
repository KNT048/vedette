package honeypot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// Names of the files in the shared volume (Config.ConfigDir). The honeypot container reads the first two; core reads
// the log (D-89). Nothing here holds a secret: the files are readable by the container.
const (
	ConfFile       = "opencanary.conf"
	TokensFile     = "honeytokens.json"
	defaultLogFile = "opencanary.jsonl"
	sambaAuditFile = "/var/log/samba-audit.log"
)

// ConfigInput is the state the OpenCanary configuration is made from.
type ConfigInput struct {
	Enabled   []ServiceName // services whose trap is on and may listen (INV-6, INV-7)
	LogPath   string        // JSON-lines file the container writes (the shared volume)
	NASDecoy  bool          // a decoy with the NAS personality exists: the web trap shows a NAS login page
	FileNames []string      // names of the file tokens, for the container to plant in the share
}

// unusedServices are the OpenCanary modules that must stay off: INV-2 allows five services and FORBID-2 no other port.
var unusedServices = []string{"ftp", "git", "httpproxy", "llmnr", "mysql", "ntp", "portscan", "redis", "sip", "snmp", "tcpbanner", "telnet", "tftp", "vnc"}

// RenderConfig turns the state into opencanary.conf: a pure function, same input same bytes (golden test).
//
// OpenCanary has no per-service bind address (device.listen_addr is only read by git, rdp, redis and vnc), so the
// services listen on every address of the container; the container has only the macvlan addresses of the secondary IP
// and the enabled decoys, which the host assigns (D-90 (1)). The banners are fixed generic strings, never the box's own
// (FORBID-2). Credential tokens are not written: the five services accept any login and log the user name, and core
// recognises the bait name when it reads the log, so no password sits on the shared volume (D-90 (3)).
func RenderConfig(in ConfigInput) ([]byte, error) {
	if in.LogPath == "" {
		return nil, errors.New("honeypot: render: no log path")
	}
	on := func(s ServiceName) bool { return slices.Contains(in.Enabled, s) }
	skin := "basicLogin"
	if in.NASDecoy {
		skin = "nasLogin"
	}
	c := map[string]any{
		"device.node_id":     "vedette-honeypot",
		"device.listen_addr": "",
		"ip.ignorelist":      []string{},
		"ssh.enabled":        on(SSH), "ssh.port": SSH.Port(), "ssh.version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"smb.enabled": on(SMB), "smb.auditfile": sambaAuditFile,
		"rdp.enabled": on(RDP), "rdp.port": RDP.Port(),
		"mssql.enabled": on(MSSQL), "mssql.port": MSSQL.Port(), "mssql.version": "2012",
		"http.enabled": on(HTTP), "http.port": HTTP.Port(), "http.banner": "Apache/2.4.52 (Ubuntu)", "http.skin": skin,
		"logger": map[string]any{
			"class": "PyLogger",
			"kwargs": map[string]any{
				"formatters": map[string]any{"plain": map[string]any{"format": "%(message)s"}},
				"handlers": map[string]any{"file": map[string]any{
					"class": "logging.FileHandler", "formatter": "plain", "filename": in.LogPath,
				}},
			},
		},
	}
	for _, u := range unusedServices {
		c[u+".enabled"] = false
	}
	return marshalStable(c)
}

// RenderTokens is honeytokens.json: the file names the container plants in the SMB share (names only).
func RenderTokens(files []string) ([]byte, error) {
	f := slices.Clone(files)
	slices.Sort(f)
	f = slices.Compact(f)
	if f == nil {
		f = []string{}
	}
	return marshalStable(map[string]any{"files": f})
}

func marshalStable(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil { // map keys are sorted by encoding/json
		return nil, fmt.Errorf("honeypot: render: %w", err)
	}
	return b.Bytes(), nil
}

// writeAtomic replaces dir/name with data unless it already holds exactly that: temp file in the same directory,
// fsync, rename, fsync of the directory. It reports whether the file changed.
func writeAtomic(dir, name string, data []byte) (bool, error) {
	path := filepath.Join(dir, name)
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) { //nolint:gosec // path is the operator-set config directory plus a constant name
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // the container reads the directory; no secret in it
		return false, fmt.Errorf("honeypot: config dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return false, fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // a no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if d, err := os.Open(dir); err == nil { //nolint:gosec // the operator-set config directory
		_ = d.Sync()
		_ = d.Close()
	}
	return true, nil
}
