package honeypot

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
)

// Names of the files: the first two are written by core into Config.ConfigDir (mounted read-only into the honeypot
// container), the log is written by the container into Config.LogDir and only read by core (D-89). Nothing here holds a
// secret: the files are readable by the container.
const (
	ConfFile       = "opencanary.conf"
	TokensFile     = "honeytokens.json"
	defaultLogFile = "opencanary.jsonl"
	sambaAuditFile = "/var/log/samba-audit.log"
)

// The size bound of the trap log written by the container: logMaxBytes per file, logBackups rotated copies kept.
const (
	logMaxBytes = 10 << 20
	logBackups  = 3
)

// ConfigInput is the state the OpenCanary configuration is made from.
type ConfigInput struct {
	Enabled   []ServiceName // services whose trap is on and may listen (INV-6, INV-7)
	LogPath   string        // JSON-lines file the container writes (inside its writable log folder)
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
		// OpenCanary logs GET / (its redirect to the login page) and refused methods only when asked; without these the first request of any scanner is invisible.
		"http.log_redirect_request": on(HTTP), "http.log_unimplemented_method_requests": on(HTTP),
		"logger": map[string]any{
			"class": "PyLogger",
			"kwargs": map[string]any{
				"formatters": map[string]any{"plain": map[string]any{"format": "%(message)s"}},
				// A bounded log: a flood of connections cannot fill the file system of the database. The tailer follows the
				// name, so it notices the rotation (tail.go).
				"handlers": map[string]any{"file": map[string]any{
					"class": "logging.handlers.RotatingFileHandler", "formatter": "plain", "filename": in.LogPath,
					"maxBytes": logMaxBytes, "backupCount": logBackups,
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

// writeInRoot replaces dir/name with data: a new file with a random name (O_EXCL) created through os.Root, so no path
// component can leave dir, then fsync, rename over name and fsync of the directory. The directory belongs to core and
// the container mounts it read-only (D-89, amendment of the WP-14 review); core never reads back what it wrote, it
// compares against the hash it keeps in memory (Service.written), so nothing a hostile container leaves is ever opened.
func writeInRoot(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // the container reads the directory; no secret in it
		return fmt.Errorf("honeypot: config dir: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("honeypot: open config dir: %w", err)
	}
	defer func() { _ = root.Close() }()
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("honeypot: random: %w", err)
	}
	tmp := "." + name + "." + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	defer func() { _ = root.Remove(tmp) }() // a no-op once renamed
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("honeypot: write %s: %w", name, err)
	}
	if d, err := root.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
