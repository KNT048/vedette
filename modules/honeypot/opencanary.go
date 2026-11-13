package honeypot

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// Names of the files: the first two are written by core into Config.ConfigDir (mounted read-only into the honeypot
// container), the log is written by the container into Config.LogDir and only read by core (D-89). Nothing here is a secret of
// the box: the files are readable by the container. The one private key among them (in CertFile) is the HTTPS trap's own, which
// core made for it alone and which nothing trusts (https.go, D-467): the container has to read it to serve TLS.
const (
	ConfFile   = "opencanary.conf"
	TokensFile = "honeytokens.json"
	// CertFile is the HTTPS trap's key and certificate in one PEM file (OpenCanary reads it as both https.key and https.certificate;
	// OpenSSL takes the first block of the type it wants), so one rename replaces the pair. Present only while a Trap IP has HTTPS.
	CertFile       = "https.pem"
	defaultLogFile = "opencanary.jsonl"
	sambaAuditFile = "/var/log/samba-audit.log"
	// imageConfDir is where the honeypot image finds config/ (a symlink to the mount point, deploy/containers/honeypot/Containerfile).
	imageConfDir = "/etc/opencanaryd/"
)

// The size bound of the trap log written by the container: logMaxBytes per file, logBackups rotated copies kept.
const (
	logMaxBytes = 10 << 20
	logBackups  = 3
)

// Look is the Trap IP that decides how one service presents itself (its banner, its page): the first Trap IP handed to the host
// that has the service. OpenCanary is one process, so each service has one banner for the whole box (D-466 (4), D-467).
type Look struct {
	Name   string // host name of the Trap IP
	Preset Preset
	Vendor string // vendor id, "" for none
}

// ConfigInput is the state the OpenCanary configuration is made from.
type ConfigInput struct {
	Enabled   []ServiceName // services whose trap is on and may listen (INV-6, INV-7)
	LogPath   string        // JSON-lines file the container writes (inside its writable log folder)
	NASDecoy  bool          // the Trap IP that picks the box's one login page is a NAS (D-466 (4)): the web trap shows a NAS login page
	FileNames []string      // names of the file tokens, for the container to plant in the share
	// Looks are the Trap IPs that decide each service's banner (D-467); a service without one gets the generic banner.
	Looks map[ServiceName]Look
}

// unusedServices are the OpenCanary modules that must stay off (D-467, FORBID-2): snmp and llmnr need scapy (GPL-2, legal.md) and
// raw sockets, portscan needs iptables in the container (the host records the attempts instead, INV-24).
var unusedServices = []string{"llmnr", "portscan", "snmp"}

// windowsLike says whether a preset is a Windows machine (its banners are Microsoft's).
func windowsLike(p Preset) bool { return p == FileServer || p == Database }

// banners are what the services that show one say, picked by the Trap IP that decides each (Looks). Fixed generic strings of
// common products, never the box's own (FORBID-2); none has a "$", which OpenCanary would expand as an environment variable.
func banners(looks map[ServiceName]Look) map[string]any {
	ftp := "(vsFTPd 3.0.5)" // Twisted writes "220 " before it
	switch l := looks[FTP]; {
	case l.Preset == NAS:
		ftp = l.Name + " FTP server ready."
	case l.Preset == Printer:
		ftp = "JD FTP Server Ready"
	case windowsLike(l.Preset):
		ftp = "Microsoft FTP Service"
	}
	mysql := "5.7.42-0ubuntu0.18.04.1" // OpenCanary refuses a version that does not start with 3 to 6
	switch looks[MySQL].Preset {
	case NAS:
		mysql = "5.5.5-10.3.39-MariaDB"
	case FileServer, Database:
		mysql = "5.7.44-log"
	}
	mail := looks[TCPBanner]
	host := strings.ToLower(mail.Name)
	if host == "" {
		host = "mail"
	}
	greet, refuse := "220 "+host+" ESMTP Postfix (Ubuntu)\r\n", "502 5.5.2 Error: command not recognized\r\n"
	if windowsLike(mail.Preset) {
		greet, refuse = "220 "+mail.Name+" Microsoft ESMTP MAIL Service ready\r\n", "500 5.3.3 Unrecognized command\r\n"
	}
	https := "basicLogin"
	if looks[HTTPS].Preset == NAS {
		https = "nasLogin"
	}
	return map[string]any{"ftp.banner": ftp, "mysql.banner": mysql, "mongodb.version": "4.4.29", "tcpbanner_1.initbanner": greet,
		"tcpbanner_1.datareceivedbanner": refuse, "https.skin": https}
}

// RenderConfig turns the state into opencanary.conf: a pure function, same input same bytes (golden test).
//
// OpenCanary has no per-service bind address (device.listen_addr is one address for every module that reads it), so the
// services listen on every address of the container; the container has only the macvlan addresses of the enabled Trap
// IPs, which the host assigns (D-90 (1)), and the host closes on each address the ports of the services that Trap IP does
// not have (D-466). Enabled is the union of their services. Every service has its port key, on or off: OpenCanary refuses
// to start when two keys name one port. Credential tokens are not written: the services accept any login and log the user
// name, and core recognises the bait name when it reads the log, so no password sits on the shared volume (D-90 (3)).
func RenderConfig(in ConfigInput) ([]byte, error) {
	if in.LogPath == "" {
		return nil, errors.New("honeypot: render: no log path")
	}
	on := func(s ServiceName) bool { return slices.Contains(in.Enabled, s) }
	skin := "basicLogin"
	if in.NASDecoy {
		skin = "nasLogin"
	}
	web := on(HTTP) || on(HTTPS) // the HTTPS trap reads the http.* switches
	c := map[string]any{
		"device.node_id":     "vedette-honeypot",
		"device.listen_addr": "",
		"ip.ignorelist":      []string{},
		"ssh.version":        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		"smb.auditfile":      sambaAuditFile,
		"mssql.version":      "2012",
		"http.banner":        "Apache/2.4.52 (Ubuntu)", "http.skin": skin,
		// OpenCanary logs GET / (its redirect to the login page) and refused methods only when asked; without these the first request of any scanner is invisible.
		"http.log_redirect_request": web, "http.log_unimplemented_method_requests": web,
		// core's own certificate for the trap (https.go): OpenCanary would otherwise try to write one into the read-only image
		"https.certificate": imageConfDir + CertFile, "https.key": imageConfDir + CertFile,
		// a bare connection is a hit for these two too, as for SSH; FTP logs only a login (OpenCanary has no switch for its connect)
		"telnet.log_tcp_connection": on(Telnet), "mysql.log_connection_made": on(MySQL),
		"httpproxy.skin": "squid",
		// the SMTP greeting: one banner, logged on every connection (no alert string, no keep-alive)
		"tcpbanner.maxnum": 1, "tcpbanner_1.enabled": on(TCPBanner), "tcpbanner_1.port": TCPBanner.Port(),
		"tcpbanner_1.alertstring.enabled": false, "tcpbanner_1.keep_alive.enabled": false,
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
	for _, s := range Services {
		c[string(s)+".enabled"] = on(s)
		if s != SMB && s != TCPBanner { // Samba owns 445; the banner's port is tcpbanner_1.port
			c[string(s)+".port"] = s.Port()
		}
	}
	for k, v := range banners(in.Looks) {
		c[k] = v
	}
	for _, u := range unusedServices {
		c[u+".enabled"] = false
	}
	return marshalStable(c)
}

// RenderTokens is honeytokens.json: the file names the container plants in the SMB share (names only) and the NetBIOS name
// of the share (D-466 (4): the name of the first Trap IP with SMB; init.py writes it into Samba's include file, "" leaves the
// image's default). Only an empty or valid NetBIOS name is written: it ends up in a Samba configuration line.
func RenderTokens(files []string, netbiosName string) ([]byte, error) {
	f := slices.Clone(files)
	slices.Sort(f)
	f = slices.Compact(f)
	if f == nil {
		f = []string{}
	}
	if netbiosName != "" && !validHostname(netbiosName) {
		return nil, errors.New("honeypot: render: the NetBIOS name is not valid")
	}
	return marshalStable(map[string]any{"files": f, "netbios_name": netbiosName})
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

// removeInRoot removes dir/name through os.Root (no path component can leave dir); a name that is not there is no error.
func removeInRoot(dir, name string) error {
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("honeypot: open config dir: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("honeypot: remove %s: %w", name, err)
	}
	return nil
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
