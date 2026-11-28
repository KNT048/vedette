package ai

import (
	"regexp"
	"slices"
	"strings"
)

// Checking a configuration the AI drafted (mitigation-config). The draft is read from text the box does not trust (a CVE brief, device
// names, banners), so an injected line could open the network instead of closing it. The page always says "review before applying";
// on top of that the box reads each block the way the device would, by its syntax (FortiOS config/edit blocks, Cisco IOS and ASA,
// Junos set commands, iptables, nftables, pf, MikroTik, Linux and Windows commands), and marks every line that does one of the risky
// things below. A mark is a warning on that line; nothing is removed, so the person sees exactly what the AI wrote.

// The kinds of risky line.
const (
	RiskBroadAllow   = "broad_allow"        // allows any source to any destination, or makes accept the default
	RiskCredential   = "new_credential"     //nolint:gosec // the name of a kind of line, not a credential
	RiskLoggingOff   = "logging_off"        // turns logging off or removes it
	RiskAuthOff      = "auth_off"           // weakens or removes sign-in checks
	RiskProtectOff   = "protection_off"     // turns a firewall, its rules or another protection off
	RiskManagementUp = "management_exposed" // opens device management to any address or to the internet side
)

// ConfigWarning is one risky line of a block: its number (1 for the first line), its kind and the box's own words for it.
type ConfigWarning struct {
	Line int    `json:"line"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}

var riskText = map[string]string{ //nolint:gosec // sentences for the page, not credentials
	RiskBroadAllow:   "Allows traffic from any source to any destination.",
	RiskCredential:   "Creates a user, a password, a key or an SNMP community.",
	RiskLoggingOff:   "Turns logging off or removes it.",
	RiskAuthOff:      "Weakens or removes sign-in checks.",
	RiskProtectOff:   "Turns a firewall, its rules or another protection off.",
	RiskManagementUp: "Opens device management to any address or to the internet side.",
}

// maxConfigWarnings caps the marks of one block.
const maxConfigWarnings = 20

var (
	wanName   = regexp.MustCompile(`(?i)\b(wan\d*|outside|internet|untrust(ed)?|external|ppp\d*|pppoe\d*|dialer\d*)\b`)
	mgmtPorts = map[string]bool{"22": true, "23": true, "80": true, "161": true, "443": true, "3389": true, "5900": true, "8080": true, "8291": true, "8443": true, "8728": true, "8729": true,
		"ssh": true, "telnet": true, "http": true, "https": true, "snmp": true, "rdp": true, "winbox": true}
	mgmtServices = []string{"http", "https", "ssh", "telnet", "snmp", "fgfm", "winbox", "www", "www-ssl", "api", "api-ssl", "rdp"}
)

// anyAddr reports whether a token means every address.
func anyAddr(t string) bool {
	switch strings.ToLower(strings.Trim(t, `"'`)) {
	case "any", "any4", "any6", "all", "0.0.0.0/0", "::/0", "0/0", "*":
		return true
	}
	return false
}

// fields splits a line into words, keeping a quoted string as one word.
func fields(line string) []string {
	var out []string
	var cur strings.Builder
	quote := rune(0)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch {
		case quote != 0:
			cur.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
			cur.WriteRune(r)
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// fortiPolicy is the state of one FortiOS `edit` block of `config firewall policy`.
type fortiPolicy struct {
	src, dst, svc, accept bool
	acceptLine            int
}

// CheckConfig reads one block and returns its risky lines, in order, at most one mark per kind and line.
func CheckConfig(code string) []ConfigWarning {
	var out []ConfigWarning
	add := func(line int, kind string) {
		for _, w := range out {
			if w.Line == line && w.Kind == kind {
				return
			}
		}
		if len(out) < maxConfigWarnings {
			out = append(out, ConfigWarning{Line: line, Kind: kind, Text: riskText[kind]})
		}
	}
	var section []string // FortiOS: the open `config` sections; the innermost last
	edit := ""           // FortiOS: the name of the open `edit` block
	var pol *fortiPolicy
	junos := map[string]*fortiPolicy{} // Junos: per policy name, which match terms are any and where it permits
	cisco := ""                        // Cisco: the open mode line (line vty, interface ...)
	for i, raw := range strings.Split(code, "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "//") {
			continue
		}
		low := strings.ToLower(line)
		f := fields(low)
		cmd := f[0]

		// ---- FortiOS blocks
		switch {
		case cmd == "config" && len(f) > 1:
			section = append(section, strings.Join(f[1:], " "))
			continue
		case cmd == "end" && len(section) > 0:
			section = section[:len(section)-1]
			continue
		case cmd == "edit" && len(section) > 0:
			edit = strings.Trim(strings.Join(f[1:], " "), `"'`)
			if section[len(section)-1] == "firewall policy" || strings.HasSuffix(section[len(section)-1], "firewall policy6") {
				pol = &fortiPolicy{}
			}
			if section[len(section)-1] == "system admin" {
				add(n, RiskCredential)
			}
			continue
		case cmd == "next" && len(section) > 0:
			if pol != nil && pol.src && pol.dst && pol.accept {
				add(pol.acceptLine, RiskBroadAllow)
			}
			pol, edit = nil, ""
			continue
		}
		if cmd == "set" && len(section) > 0 && len(f) > 1 {
			sec := section[len(section)-1]
			key, vals := f[1], f[2:]
			switch {
			case pol != nil && (key == "srcaddr" || key == "srcaddr6"):
				pol.src = slices.ContainsFunc(vals, anyAddr)
			case pol != nil && (key == "dstaddr" || key == "dstaddr6"):
				pol.dst = slices.ContainsFunc(vals, anyAddr)
			case pol != nil && key == "service":
				pol.svc = slices.ContainsFunc(vals, anyAddr)
			case pol != nil && key == "action" && len(vals) > 0 && vals[0] == "accept":
				pol.accept, pol.acceptLine = true, n
			case key == "logtraffic" && len(vals) > 0 && vals[0] == "disable",
				strings.HasPrefix(sec, "log ") && key == "status" && len(vals) > 0 && vals[0] == "disable":
				add(n, RiskLoggingOff)
			case key == "allowaccess" && sec == "system interface" && wanName.MatchString(edit) && slices.ContainsFunc(vals, func(v string) bool { return slices.Contains(mgmtServices, v) }):
				add(n, RiskManagementUp)
			case key == "password" || key == "passwd" || key == "psksecret" || key == "secret" || strings.HasSuffix(key, "-password"):
				add(n, RiskCredential)
			case key == "status" && len(vals) > 0 && vals[0] == "disable" && (sec == "firewall policy" || sec == "system auto-update"):
				add(n, RiskProtectOff)
			}
			if pol != nil && pol.src && pol.dst && pol.accept { // a block written without `next` still counts at its accept line
				add(pol.acceptLine, RiskBroadAllow)
			}
			continue
		}

		// ---- Junos set commands
		if (cmd == "set" || cmd == "delete" || cmd == "deactivate") && len(f) > 2 && len(section) == 0 {
			rest := f[1:]
			if cmd != "set" && rest[0] == "system" && len(rest) > 1 && rest[1] == "syslog" {
				add(n, RiskLoggingOff)
				continue
			}
			if cmd == "set" && rest[0] == "security" && len(rest) > 1 && rest[1] == "policies" {
				name := ""
				for j := range rest {
					if rest[j] == "policy" && j+1 < len(rest) {
						name = strings.Join(rest[:j+2], " ")
					}
				}
				p := junos[name]
				if p == nil {
					p = &fortiPolicy{}
					junos[name] = p
				}
				for j := range rest {
					if j+1 < len(rest) && anyAddr(rest[j+1]) {
						switch rest[j] {
						case "source-address":
							p.src = true
						case "destination-address":
							p.dst = true
						}
					}
					if rest[j] == "then" && j+1 < len(rest) && rest[j+1] == "permit" {
						p.accept, p.acceptLine = true, n
					}
				}
				if p.src && p.dst && p.accept {
					add(p.acceptLine, RiskBroadAllow)
				}
				continue
			}
			if cmd == "set" && rest[0] == "system" && len(rest) > 2 && rest[1] == "login" && rest[2] == "user" {
				add(n, RiskCredential)
				continue
			}
			if cmd == "set" && rest[0] == "system" && len(rest) > 2 && rest[1] == "services" && (rest[2] == "telnet" || rest[2] == "web-management") {
				add(n, RiskManagementUp)
				continue
			}
			if cmd == "set" && slices.Contains(rest, "host-inbound-traffic") && slices.Contains(rest, "system-services") && (slices.Contains(rest, "all") || slices.Contains(rest, "telnet") || slices.Contains(rest, "ssh") || slices.Contains(rest, "https") || slices.Contains(rest, "http")) && wanName.MatchString(line) {
				add(n, RiskManagementUp)
				continue
			}
		}

		// ---- iptables and ip6tables
		if cmd == "iptables" || cmd == "ip6tables" || cmd == "sudo" && len(f) > 1 && (f[1] == "iptables" || f[1] == "ip6tables") {
			orig := fields(line) // iptables options are case-sensitive (-P policy, -p protocol)
			args := orig[1:]
			if cmd == "sudo" {
				args = orig[2:]
			}
			checkIptables(args, n, add)
			continue
		}

		// ---- nftables
		if cmd == "nft" || strings.Contains(low, " policy accept") || strings.HasPrefix(low, "policy accept") {
			switch {
			case strings.Contains(low, "flush ruleset"), strings.HasPrefix(low, "nft delete table"):
				add(n, RiskProtectOff)
			case strings.Contains(low, "policy accept") && (strings.Contains(low, "hook input") || strings.Contains(low, "hook forward") || cmd == "policy"):
				add(n, RiskBroadAllow)
			case strings.HasSuffix(low, " accept") && !strings.Contains(low, "saddr") && !strings.Contains(low, "ct state") && !strings.Contains(low, "iif") && !strings.Contains(low, "dport"):
				add(n, RiskBroadAllow)
			}
			continue
		}

		// ---- pf
		if cmd == "pass" {
			from, to := "", ""
			for j := range f {
				if f[j] == "from" && j+1 < len(f) {
					from = f[j+1]
				}
				if f[j] == "to" && j+1 < len(f) {
					to = f[j+1]
				}
			}
			if slices.Contains(f, "all") || anyAddr(from) && anyAddr(to) && !slices.Contains(f, "port") {
				add(n, RiskBroadAllow)
			}
			continue
		}

		// ---- MikroTik
		if strings.HasPrefix(cmd, "/") || strings.Contains(low, "chain=") {
			kv := map[string]string{}
			for _, w := range f {
				if k, v, ok := strings.Cut(w, "="); ok {
					kv[k] = strings.Trim(v, `"'`)
				}
			}
			path := strings.Join(f[:slices.IndexFunc(append(f, "add"), func(w string) bool {
				return w == "add" || w == "set" || w == "remove" || w == "disable" || strings.Contains(w, "=")
			})], " ")
			switch {
			case strings.Contains(path, "ip firewall filter") && kv["action"] == "accept" && (kv["chain"] == "input" || kv["chain"] == "forward") &&
				kv["src-address"] == "" && kv["src-address-list"] == "" && kv["connection-state"] == "" && kv["in-interface"] == "" && kv["dst-port"] == "":
				add(n, RiskBroadAllow)
			case strings.Contains(path, "ip firewall filter") && kv["action"] == "accept" && kv["chain"] == "input" && kv["src-address"] == "" && kv["src-address-list"] == "" && mgmtPorts[kv["dst-port"]]:
				add(n, RiskManagementUp)
			case strings.HasPrefix(path, "/user") && slices.Contains(f, "add"):
				add(n, RiskCredential)
			case strings.HasPrefix(path, "/ip service") && slices.Contains(f, "set") && (kv["address"] == "" || anyAddr(kv["address"])) && (strings.Contains(low, "address=") || kv["disabled"] == "no"):
				add(n, RiskManagementUp)
			case strings.HasPrefix(path, "/system logging") && (slices.Contains(f, "remove") || slices.Contains(f, "disable")):
				add(n, RiskLoggingOff)
			case strings.HasPrefix(path, "/snmp community") && (slices.Contains(f, "add") || slices.Contains(f, "set")):
				add(n, RiskCredential)
			}
			continue
		}

		// ---- Cisco IOS and ASA
		if strings.HasPrefix(low, "line vty") || strings.HasPrefix(low, "line con") || strings.HasPrefix(low, "interface ") {
			cisco = low
			continue
		}
		if i := slices.Index(f, "permit"); i >= 0 && (cmd == "access-list" || cmd == "permit" || i <= 3 && isNumber(cmd)) {
			if ciscoAnyAny(f[i+1:]) {
				add(n, RiskBroadAllow)
			}
			continue
		}
		switch {
		case cmd == "username" && (slices.Contains(f, "password") || slices.Contains(f, "secret")),
			cmd == "enable" && len(f) > 1 && (f[1] == "password" || f[1] == "secret"),
			cmd == "snmp-server" && len(f) > 1 && (f[1] == "community" || f[1] == "user"),
			cmd == "crypto" && strings.Contains(low, " key "),
			cmd == "password" && strings.HasPrefix(cisco, "line"):
			add(n, RiskCredential)
		case cmd == "no" && len(f) > 1 && f[1] == "logging",
			cmd == "logging" && len(f) > 1 && (f[1] == "off" || f[1] == "disable"):
			add(n, RiskLoggingOff)
		case cmd == "no" && len(f) > 1 && (f[1] == "aaa" || f[1] == "login" || f[1] == "password" || f[1] == "service" && len(f) > 2 && f[2] == "password-encryption"),
			cmd == "aaa" && slices.Contains(f, "authentication") && slices.Contains(f, "none"),
			cmd == "transport" && slices.Contains(f, "telnet") && strings.HasPrefix(cisco, "line vty"):
			add(n, RiskAuthOff)
		case cmd == "ip" && len(f) > 2 && f[1] == "http" && (f[2] == "server" || f[2] == "secure-server"):
			add(n, RiskManagementUp)
		case (cmd == "http" || cmd == "ssh" || cmd == "telnet") && len(f) == 4 && (f[1] == "0.0.0.0" || f[1] == "0") && wanName.MatchString(f[3]):
			add(n, RiskManagementUp)
		case cmd == "no" && len(f) > 2 && f[1] == "access-group":
			add(n, RiskProtectOff)
		}

		// ---- Linux and Windows commands, and sshd_config lines
		checkHostCommand(f, low, n, add)
	}
	if pol != nil && pol.src && pol.dst && pol.accept {
		add(pol.acceptLine, RiskBroadAllow)
	}
	slices.SortStableFunc(out, func(a, b ConfigWarning) int { return a.Line - b.Line })
	return out
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ciscoAnyAny reads the rest of a Cisco permit after the word permit: a protocol, the source, the destination. A source and a destination
// that are both any (any, any4, any6, or 0.0.0.0 255.255.255.255 / 0.0.0.0 0.0.0.0 as an address and wildcard or mask) is a broad allow.
func ciscoAnyAny(rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	i := 0
	if !anyAddr(rest[0]) && !strings.Contains(rest[0], ".") { // a protocol word or number
		i = 1
	}
	addr := func() bool {
		if i >= len(rest) {
			return false
		}
		if anyAddr(rest[i]) {
			i++
			return true
		}
		if rest[i] == "0.0.0.0" && i+1 < len(rest) && (rest[i+1] == "255.255.255.255" || rest[i+1] == "0.0.0.0") {
			i += 2
			return true
		}
		return false
	}
	src := addr() // the source first: addr moves past what it read
	return src && addr()
}

// checkIptables reads one iptables command: a default policy of ACCEPT, a flush, or an ACCEPT rule on INPUT or FORWARD that names no
// source (a management port: management exposed; no port and no interface or state match: a broad allow).
func checkIptables(args []string, n int, add func(int, string)) {
	opt := map[string]string{}
	var chain string
	policy, flush := false, false
	for j := 0; j < len(args); j++ {
		a := args[j]
		next := ""
		if j+1 < len(args) {
			next = args[j+1]
		}
		switch a {
		case "-P", "--policy":
			policy, chain = true, strings.ToUpper(next)
			if j+2 < len(args) {
				opt["-j"] = strings.ToUpper(args[j+2])
			}
		case "-F", "--flush", "-X":
			flush = true
		case "-A", "--append", "-I", "--insert":
			chain = strings.ToUpper(next)
		case "-s", "--source", "--src", "-i", "--in-interface", "-p", "--protocol", "--dport", "--destination-port", "--dports", "-j", "--jump", "--state", "--ctstate", "--src-range":
			opt[a] = next
		}
	}
	src := opt["-s"] + opt["--source"] + opt["--src"] + opt["--src-range"]
	target := strings.ToUpper(opt["-j"] + opt["--jump"])
	port := opt["--dport"] + opt["--destination-port"] + opt["--dports"]
	iface := opt["-i"] + opt["--in-interface"]
	switch {
	case flush:
		add(n, RiskProtectOff)
	case policy && target == "ACCEPT" && (chain == "INPUT" || chain == "FORWARD"):
		add(n, RiskBroadAllow)
	case target != "ACCEPT" || chain != "INPUT" && chain != "FORWARD" || src != "" && !anyAddr(src) || iface == "lo":
	case port != "" && slices.ContainsFunc(strings.Split(port, ","), func(p string) bool { return mgmtPorts[p] }):
		add(n, RiskManagementUp)
	case port == "" && opt["--state"]+opt["--ctstate"] == "" && opt["-p"]+opt["--protocol"] == "" && (iface == "" || wanName.MatchString(iface)):
		add(n, RiskBroadAllow)
	}
}

// checkHostCommand reads Linux and Windows commands and sshd_config lines.
func checkHostCommand(f []string, low string, n int, add func(int, string)) {
	if len(f) > 1 && f[0] == "sudo" {
		f = f[1:]
	}
	cmd := f[0]
	arg := func(i int) string {
		if i < len(f) {
			return f[i]
		}
		return ""
	}
	switch {
	case cmd == "useradd" || cmd == "adduser" || cmd == "passwd" || cmd == "chpasswd" || cmd == "htpasswd" || cmd == "new-localuser" ||
		cmd == "net" && arg(1) == "user" && slices.Contains(f, "/add") || cmd == "usermod" && (slices.Contains(f, "-ag") || slices.Contains(f, "-g")) ||
		cmd == "net" && arg(1) == "localgroup" && slices.Contains(f, "/add"):
		add(n, RiskCredential)
	case (cmd == "permitrootlogin" || cmd == "permitemptypasswords" || cmd == "passwordauthentication") && arg(1) == "yes":
		add(n, RiskAuthOff)
	case cmd == "systemctl" && (arg(1) == "stop" || arg(1) == "disable" || arg(1) == "mask"):
		for _, s := range f[2:] {
			s = strings.TrimSuffix(s, ".service")
			switch s {
			case "auditd", "rsyslog", "syslog", "syslog-ng", "systemd-journald":
				add(n, RiskLoggingOff)
			case "firewalld", "ufw", "nftables", "iptables", "apparmor", "fail2ban":
				add(n, RiskProtectOff)
			}
		}
	case cmd == "ufw" && arg(1) == "disable", cmd == "setenforce" && arg(1) == "0",
		cmd == "netsh" && strings.Contains(low, "advfirewall") && strings.Contains(low, "state off"),
		cmd == "set-netfirewallprofile" && strings.Contains(low, "-enabled false"),
		cmd == "set-mppreference" && strings.Contains(low, "disable") && strings.Contains(low, "$true"):
		add(n, RiskProtectOff)
	case cmd == "ufw" && arg(1) == "default" && arg(2) == "allow":
		add(n, RiskBroadAllow)
	case cmd == "ufw" && arg(1) == "allow" && !slices.Contains(f, "from"):
		if p, _, _ := strings.Cut(arg(2), "/"); mgmtPorts[p] {
			add(n, RiskManagementUp)
		}
	case cmd == "netsh" && strings.Contains(low, "add rule") && strings.Contains(low, "action=allow") && !strings.Contains(low, "remoteip="):
		if strings.Contains(low, "localport=") {
			for _, w := range f {
				if v, ok := strings.CutPrefix(w, "localport="); ok && slices.ContainsFunc(strings.Split(v, ","), func(p string) bool { return mgmtPorts[p] }) {
					add(n, RiskManagementUp)
				}
			}
		} else {
			add(n, RiskBroadAllow)
		}
	case cmd == "auditpol" && strings.Contains(low, ":disable"), cmd == "wevtutil" && (arg(1) == "cl" || arg(1) == "sl" && strings.Contains(low, "/e:false")):
		add(n, RiskLoggingOff)
	}
}
