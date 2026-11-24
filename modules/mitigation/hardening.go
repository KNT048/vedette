package mitigation

import (
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/modules/findings"
)

// General hardening (INV-8): while no maintainer-confirmed pack ships its own compromise signs for a CVE, every finding still gets
// general "Have I been hit?" checks for its software family, written here by reviewed code: signs any intruder tends to leave. Nothing
// in them is about the CVE, so they are not a recommendation and the page labels them so; Vedette never runs them (FORBID-1).
// The generated firewall configs that let only an admin network reach the device are gone: they told the user to allow
// traffic from the box to devices, which did not help.

// hardening is the general hardening of a finding, or nil when the confirmed pack has its own compromise signs (POST-1).
func hardening(r findings.Row, comp *findings.CompromiseCheck) *findings.Hardening {
	if comp != nil {
		return nil
	}
	h := generalHardening(r)
	return &h
}

// generalHardening builds the hardening block: the software, its family and the family's checks. It is pure, so every case is a
// unit test.
func generalHardening(r findings.Row) findings.Hardening {
	fam := familyOf(r)
	h := findings.Hardening{Software: softwareName(r), Family: fam.label}
	c := fam.checks(h.Software, r.CVE)
	h.Checks = &c
	return h
}

// softwareName is the software as the page names it: the KEV entry's plain name, else (a finding on no exploited list) the software
// line the finding is on, as the device names it.
func softwareName(r findings.Row) string {
	if r.Kev == nil {
		if r.Known != nil && strings.TrimSpace(r.Known.Software) != "" {
			return strings.TrimSpace(r.Known.Software)
		}
		return "the software"
	}
	if r.Kev.Display != "" {
		return r.Kev.Display
	}
	return strings.TrimSpace(r.Kev.Vendor + " " + r.Kev.Product)
}

// family is a software family the checks are written for. Only families the KEV entry names reliably.
type family struct {
	label  string
	checks func(software, cve string) findings.CompromiseCheck
}

func hasAny(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// familyOf maps the finding to a family from the KEV entry's vendor and product, then the device's type.
func familyOf(r findings.Row) family {
	var vendor, product string
	if r.Kev != nil {
		vendor, product = strings.ToLower(r.Kev.Vendor), strings.ToLower(r.Kev.Product)
	} else if r.Known != nil {
		product = strings.ToLower(r.Known.Software) // a finding on no exploited list: the name of its software line ("nginx", "Linux kernel")
	}
	vp := vendor + " " + product
	kind := ""
	if r.Asset != nil {
		kind = devicetypes.ActsAs(r.Asset.Kind)
	}
	switch {
	case vendor == "fortinet" && strings.Contains(product, "forticlient"): // r2 L4: FortiClient EMS is Windows server software
		return family{label: "Windows", checks: windowsChecks}
	case vendor == "fortinet" && hasAny(product, "fortios", "fortiproxy", "fortigate"):
		return family{label: "Fortinet FortiOS", checks: fortiosChecks}
	case vendor == "mikrotik" && strings.Contains(product, "routeros"): //nolint:misspell // RouterOS is the product name
		return family{label: "MikroTik RouterOS", checks: routerosChecks}
	case (vendor == "vmware" || vendor == "broadcom" || vendor == "") && strings.Contains(product, "esxi"):
		return family{label: "VMware ESXi", checks: esxiChecks}
	case (vendor == "synology" && !hasAny(product, "srm", "router")) || vendor == "" && hasAny(product, "synology", "diskstation manager", "dsm "):
		return family{label: "Synology DSM", checks: dsmChecks}
	case vendor == "juniper" && strings.Contains(product, "junos"):
		return family{label: "Juniper Junos OS", checks: junosChecks}
	case vendor == "cisco" && (strings.HasPrefix(product, "ios") || strings.Contains(product, " ios")) && !strings.Contains(product, "xr"): // r1 L4: IOS XR differs
		return family{label: "Cisco IOS", checks: ciscoChecks}
	case strings.Contains(product, "openssh"):
		return family{label: "OpenSSH", checks: opensshChecks}
	case vendor == "microsoft" && hasAny(product, "exchange"):
		return family{label: "Windows web server (IIS)", checks: iisChecks}
	case vendor == "microsoft" && hasAny(product, "sharepoint", "internet information services", "iis") || hasAny(vp, "moveit"): // r1 M5: MOVEit runs on IIS
		return family{label: "Windows web server (IIS)", checks: iisChecks}
	case vendor == "microsoft" || hasAny(vp, "veeam", "solarwinds", "serv-u", "kaseya"): // r1 M5: Windows-only software
		return family{label: "Windows", checks: windowsChecks}
	case hasAny(vp, "http server", "httpd", "nginx", "tomcat", "struts", "weblogic", "confluence", "jira", "gitlab", "jenkins", "drupal",
		"wordpress", "joomla", "magento", "coldfusion", "ofbiz", "zimbra", "roundcube", "teamcity", "php", "atlassian"):
		return family{label: "Web server", checks: webChecks}
	case hasAny(vendor, "linux", "canonical", "debian", "red hat", "redhat", "suse", "gnu", "sudo", "polkit", "samba") || hasAny(product, "linux", "kernel", "glibc", "polkit", "samba"): // r2 L4: Samba
		if strings.Contains(vp, "samba") {
			return family{label: "Linux file server (Samba)", checks: linuxChecks}
		}
		return family{label: "Linux", checks: linuxChecks}
	case hasAny(vendor, "fortinet", "juniper", "cisco", "palo alto", "citrix", "ivanti", "pulse secure", "sonicwall", "f5", "zyxel", "d-link",
		"tp-link", "netgear", "draytek", "ubiquiti", "sophos", "watchguard", "array networks", "tenda", "totolink", "mikrotik", "check point") ||
		slices.Contains([]string{"firewall", "router", "switch", "ap"}, kind):
		return family{label: "Network device", checks: netdeviceChecks}
	}
	return family{label: "General", checks: genericChecks}
}

// ---- "Have I been hit?": general signs per family (text only, INV-6, INV-8) ----

// familyProduct is the product name that alone says a vendor's family, for a KEV display name without the vendor ("Junos OS").
var familyProduct = map[string]string{"VMware ESXi": "ESXi", "Synology DSM": "DSM", "Juniper Junos OS": "Junos", "Fortinet FortiOS": "FortiOS", "MikroTik RouterOS": "RouterOS", "Cisco IOS": "IOS"}

// summaryFor names the family after the software only when the software's name does not already say it ("General checks for
// Juniper Junos OS (Juniper Junos OS)"), and never the catch-all "General" family, which says nothing more.
func summaryFor(family, software, cve string) string {
	sw := strings.ToLower(software)
	says := strings.Contains(sw, strings.ToLower(family)) || familyProduct[family] != "" && strings.Contains(sw, strings.ToLower(familyProduct[family]))
	if family != "General" && !says {
		software += " (" + family + ")"
	}
	return fmt.Sprintf("General checks for %s: signs any intruder tends to leave. They are not specific to %s: the vendor advisory and the exploited-list entry (links in What to do) name the files, accounts and addresses seen for this CVE.", software, cve)
}

var ifFound = []string{
	"Take the device off the network, but leave it powered on: its memory and temporary files are evidence.",
	"Keep what you found: copy the logs and the files before you change anything.",
	"From a clean computer, change every password and key the device holds or uses (admin accounts, VPN users, service accounts), and anywhere they are reused.",
	"Rebuild the device from a known good install or firmware and update it before you connect it again: an update alone does not remove what an intruder left.",
	"Get help: your incident response provider or your national CERT.",
}

var outbound = findings.Indicator{Kind: "log", Title: "Connections the device started to the internet",
	Detail: "In your firewall's traffic log, look for connections from the device to outside addresses it has no reason to reach, above all at night or in a steady rhythm (every few minutes): intruders' tools call home."}

func check(family, software, cve string, in ...findings.Indicator) findings.CompromiseCheck {
	return findings.CompromiseCheck{Summary: summaryFor(family, software, cve), Indicators: append(in, outbound), IfFound: slices.Clone(ifFound)}
}

func cmd(label, code string) findings.Command { return findings.Command{Label: label, Code: code} }

var windowsIndicators = []findings.Indicator{
	{Kind: "log", Title: "New or changed accounts", Detail: "Security log events 4720 (account created), 4722 (enabled), 4724 (password reset), 4728, 4732 and 4756 (added to a group) that nobody in your team did, and members of Administrators you do not know.",
		Commands: []findings.Command{
			cmd("PowerShell as administrator: account changes in the last 30 days", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4722,4724,4728,4732,4756; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message"),
			cmd("PowerShell: members of Administrators", "Get-LocalGroupMember -Group Administrators"),
		}},
	{Kind: "log", Title: "Remote sign-ins and cleared logs", Detail: "Network and remote desktop sign-ins (event 4624, logon types 3 and 10) from addresses you do not know, and event 1102: someone cleared the Security log.",
		Commands: []findings.Command{
			cmd("PowerShell as administrator: remote sign-ins in the last 7 days", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Where-Object { $_.Properties[8].Value -in 3,10 } | Format-Table TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='From';e={$_.Properties[18].Value}}"),
			cmd("PowerShell as administrator: the Security log was cleared", "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue | Format-List TimeCreated, Message"),
		}},
	{Kind: "process", Title: "New services, scheduled tasks and listening programs", Detail: "Services installed recently (System log event 7045), scheduled tasks outside Microsoft's folder, and programs listening on ports you cannot explain, above all from user or temporary folders.",
		Commands: []findings.Command{
			cmd("PowerShell as administrator: services installed in the last 30 days", "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue | Format-List TimeCreated, Message"),
			cmd("PowerShell: scheduled tasks outside Microsoft's folder", "Get-ScheduledTask | Where-Object TaskPath -notlike '\\Microsoft\\*' | Format-Table TaskPath, TaskName, State"),
			cmd("PowerShell as administrator: listening programs", "Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table LocalAddress, LocalPort, @{n='Program';e={(Get-Process -Id $_.OwningProcess).Path}}"),
		}},
}

func windowsChecks(software, cve string) findings.CompromiseCheck {
	return check("Windows", software, cve, windowsIndicators...)
}

func iisChecks(software, cve string) findings.CompromiseCheck {
	web := []findings.Indicator{
		{Kind: "web", Title: "New script files in the web folders", Detail: "Web shells are small .aspx, .ashx or .asmx files dropped in a web folder: under C:\\inetpub, Exchange's FrontEnd\\HttpProxy folder, or SharePoint's LAYOUTS folder. Look for ones changed recently that no update explains.",
			Commands: []findings.Command{cmd("PowerShell as administrator: script files under C:\\inetpub changed in the last 30 days", "Get-ChildItem -Path C:\\inetpub -Recurse -Include *.aspx,*.ashx,*.asmx,*.asp -File -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) | Format-Table LastWriteTime, FullName")}},
		{Kind: "log", Title: "Web server log", Detail: "IIS logs are in C:\\inetpub\\logs\\LogFiles. Look for POST requests to .aspx files you do not know, and one address requesting many pages within seconds."},
		{Kind: "process", Title: "The web server starting a command shell", Detail: "w3wp.exe (the IIS worker) should not start cmd.exe or powershell.exe.",
			Commands: []findings.Command{cmd("PowerShell as administrator: shells started by w3wp.exe", "Get-CimInstance Win32_Process -Filter \"Name='cmd.exe' OR Name='powershell.exe'\" | Where-Object { (Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.ParentProcessId)\").Name -eq 'w3wp.exe' } | Format-List ProcessId, CommandLine")}},
	}
	return check("Windows web server", software, cve, append(web, windowsIndicators...)...)
}

var linuxIndicators = []findings.Indicator{
	{Kind: "log", Title: "Sign-ins", Detail: "Sign-ins at odd hours or from addresses you do not know. The log is /var/log/auth.log (Debian, Ubuntu) or /var/log/secure (Red Hat family), or the journal.",
		Commands: []findings.Command{
			cmd("Last sign-ins", "sudo last -a -n 50"),
			cmd("SSH sign-ins in the last 30 days", "sudo journalctl _COMM=sshd --since \"30 days ago\" | grep -E \"Accepted|Invalid user\""),
		}},
	{Kind: "file", Title: "New accounts and keys", Detail: "Accounts with user id 0 besides root, accounts nobody created, members of sudo or wheel you do not know, and authorized_keys files changed recently.",
		Commands: []findings.Command{
			cmd("Accounts with a login shell or user id 0", "awk -F: '$3 == 0 || $3 >= 1000 { print $1, $3, $7 }' /etc/passwd"),
			cmd("Members of the admin groups", "getent group sudo wheel"),
			cmd("authorized_keys changed in the last 30 days", "sudo find /root /home -name authorized_keys -mtime -30 -ls"),
		}},
	{Kind: "process", Title: "Listening programs and programs run from temporary folders", Detail: "Ports you cannot explain, and programs running from /tmp, /var/tmp or /dev/shm, or whose file was deleted after start.",
		Commands: []findings.Command{
			cmd("Listening ports and their programs", "sudo ss -tulpn"),
			cmd("Programs running from temporary folders or deleted files", "sudo ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '/tmp/|/dev/shm/|/var/tmp/|\\(deleted\\)'"),
			cmd("Established connections and their programs", "sudo ss -tnp state established"),
		}},
	{Kind: "file", Title: "Start-up entries and changed system files", Detail: "Cron jobs, systemd units and /etc/ld.so.preload changed recently, and system files that no longer match their package.",
		Commands: []findings.Command{
			cmd("Start-up entries changed in the last 30 days", "sudo find /etc/cron* /var/spool/cron /etc/systemd/system /etc/ld.so.preload -mtime -30 -ls 2>/dev/null"),
			cmd("Debian, Ubuntu: files that differ from their package", "sudo dpkg --verify"),
			cmd("Red Hat family: files that differ from their package", "sudo rpm -Va"),
		}},
}

func linuxChecks(software, cve string) findings.CompromiseCheck {
	return check("Linux", software, cve, linuxIndicators...)
}

func opensshChecks(software, cve string) findings.CompromiseCheck {
	ssh := findings.Indicator{Kind: "file", Title: "SSH server settings", Detail: "Settings nobody in your team changed: root sign-in or passwords allowed again, another keys file, a keys command.",
		Commands: []findings.Command{
			cmd("The settings sshd runs with", "sudo sshd -T | grep -Ei '^(permitrootlogin|passwordauthentication|authorizedkeysfile|authorizedkeyscommand) '"),
			cmd("When the settings files changed", "ls -l --time-style=long-iso /etc/ssh/sshd_config /etc/ssh/sshd_config.d/"),
		}}
	return check("Linux", software, cve, append([]findings.Indicator{ssh}, linuxIndicators...)...)
}

func webChecks(software, cve string) findings.CompromiseCheck {
	web := []findings.Indicator{
		{Kind: "web", Title: "New script files in the web folders", Detail: "Web shells are small .php, .jsp or .jspx files dropped where the web server serves files. Look for ones changed recently that no update explains.",
			Commands: []findings.Command{cmd("Linux: script files changed in the last 30 days", "sudo find /var/www /srv /usr/share/nginx /opt -type f \\( -name '*.php' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.jspx' \\) -mtime -30 -ls 2>/dev/null"),
				cmd("Windows, PowerShell as administrator: script files under C:\\inetpub and the application folders changed in the last 30 days", "Get-ChildItem -Path C:\\inetpub, 'C:\\Program Files', 'C:\\ColdFusion*' -Recurse -Include *.aspx,*.ashx,*.jsp,*.jspx,*.cfm,*.php -File -ErrorAction SilentlyContinue | Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) | Format-Table LastWriteTime, FullName")}},
		{Kind: "log", Title: "Web server log", Detail: "On Windows, IIS logs are in C:\\inetpub\\logs\\LogFiles. On Linux the access log is /var/log/apache2/access.log, /var/log/httpd/access_log, /var/log/nginx/access.log, or Tomcat's logs/localhost_access_log. Look for POST requests to script files you do not know, and long encoded parameters.",
			Commands: []findings.Command{cmd("Linux: POST requests to script files", "sudo grep -hE '\"POST [^\"]*\\.(php|phtml|jsp|jspx)' /var/log/apache2/access.log /var/log/httpd/access_log /var/log/nginx/access.log 2>/dev/null | tail -n 50")}},
		{Kind: "process", Title: "The web server running other programs", Detail: "Programs of the web server's user that are not the web server itself (a shell, curl, wget, a miner).",
			Commands: []findings.Command{cmd("Linux: programs of the web server's user", "ps -eo user,pid,ppid,lstart,cmd | grep -E '^(www-data|apache|nginx|tomcat) ' | grep -vE 'apache2|httpd|nginx|java|php-fpm'")}},
		{Kind: "web", Title: "The application's own administrators and add-ons", Detail: "In the application's admin pages: administrators, API tokens and plugins or extensions nobody in your team added."},
	}
	// r1 M5: the OS is often unknown (ColdFusion, WebLogic run on both), so the commands name their OS.
	return check("Web server", software, cve, append(web, linuxIndicators...)...)
}

// esxiChecks: the ESXi Shell and esxcli commands are from Broadcom's ESXCLI reference and its KB 89619 ("Mitigation and Threat
// Hunting Guidance for Unsigned vSphere Installation Bundles"), the backdoor VIBs Mandiant described for ESXi hosts; the log files are
// ESXi's own (/var/log/auth.log, shell.log, hostd.log).
func esxiChecks(software, cve string) findings.CompromiseCheck {
	return check("VMware ESXi", software, cve,
		findings.Indicator{Kind: "log", Title: "Sign-ins and shell commands", Detail: "SSH or ESXi Shell sign-ins from addresses you do not know, and commands nobody in your team ran. SSH and the ESXi Shell turned on although you keep them off (Host Client: Host, Manage, Services).",
			Commands: []findings.Command{
				cmd("ESXi Shell: sign-ins", "grep -E 'Accepted|Failed' /var/log/auth.log | tail -n 50"),
				cmd("ESXi Shell: commands run in the shell", "tail -n 100 /var/log/shell.log"),
			}},
		findings.Indicator{Kind: "file", Title: "Accounts and installed bundles (VIBs)", Detail: "Local accounts and permissions nobody created, and installed bundles (VIBs) you did not install or whose signature does not check out: intruders have kept ESXi hosts with backdoor VIBs installed with --force.",
			Commands: []findings.Command{
				cmd("ESXi Shell: local accounts", "esxcli system account list"),
				cmd("ESXi Shell: permissions", "esxcli system permission list"),
				cmd("ESXi Shell: installed bundles with their acceptance level", "esxcli software vib list"),
				cmd("ESXi Shell: bundles whose signature does not verify", "esxcli software vib signature verify"),
				cmd("ESXi Shell: the lowest acceptance level the host allows", "esxcli software acceptance get"),
			}},
		findings.Indicator{Kind: "process", Title: "Connections and virtual machines", Detail: "Listening ports and connections the host has no reason for, and virtual machines nobody in your team created.",
			Commands: []findings.Command{
				cmd("ESXi Shell: network connections", "esxcli network ip connection list"),
				cmd("ESXi Shell: registered virtual machines", "vim-cmd vmsvc/getallvms"),
			}},
	)
}

// dsmChecks: DSM's own screens (Synology Knowledge Center: Log Center, Control Panel, Package Center, Security Advisor); no shell
// commands, which DSM leaves off by default.
func dsmChecks(software, cve string) findings.CompromiseCheck {
	return check("Synology DSM", software, cve,
		findings.Indicator{Kind: "log", Title: "Sign-ins", Detail: "In Log Center, Logs: sign-ins (connection logs) from addresses you do not know, above all from the internet, and many failed sign-ins in a row."},
		findings.Indicator{Kind: "file", Title: "Accounts", Detail: "In Control Panel, User & Group: users nobody created, members of the administrators group you do not know, and the admin or guest account turned on again."},
		findings.Indicator{Kind: "process", Title: "Scheduled tasks and packages", Detail: "In Control Panel, Task Scheduler: tasks nobody added (a script run as root keeps an intruder in). In Package Center: packages nobody installed."},
		findings.Indicator{Kind: "file", Title: "Malware scan and access from the internet", Detail: "Run Security Advisor's scan. In Control Panel, External Access: QuickConnect and router port forwarding nobody in your team turned on."},
	)
}

func junosChecks(software, cve string) findings.CompromiseCheck {
	return check("Juniper Junos OS", software, cve,
		findings.Indicator{Kind: "log", Title: "Configuration changes and sign-ins", Detail: "Commits nobody in your team made, and sign-ins from addresses you do not know.",
			Commands: []findings.Command{
				cmd("Junos CLI: who committed and when", "show system commit"),
				cmd("Junos CLI: what the last commit changed", "show system rollback 1 compare 0"),
				cmd("Junos CLI: sign-ins in the log", "show log messages | match \"UI_LOGIN_EVENT|UI_AUTH_EVENT|UI_COMMIT\""),
			}},
		findings.Indicator{Kind: "file", Title: "Accounts and files", Detail: "Login accounts nobody created, and files in /var/tmp or /tmp you did not put there.",
			Commands: []findings.Command{
				cmd("Junos CLI: login accounts", "show configuration system login | display set"),
				cmd("Junos CLI: who is signed in", "show system users"),
				cmd("Junos CLI: files in /var/tmp", "file list /var/tmp/ detail"),
			}},
		findings.Indicator{Kind: "process", Title: "Listening ports", Detail: "Ports the device listens on that its configuration does not explain.",
			Commands: []findings.Command{cmd("Junos CLI: listening ports", "show system connections | match LISTEN")}},
	)
}

func fortiosChecks(software, cve string) findings.CompromiseCheck {
	return check("Fortinet FortiOS", software, cve,
		findings.Indicator{Kind: "log", Title: "Admin sign-ins and configuration changes", Detail: "In Log & Report, System Events: admin sign-ins from addresses you do not know and configuration changes nobody in your team made.",
			Commands: []findings.Command{
				cmd("FortiGate CLI: admin accounts", "show system admin"),
				cmd("FortiGate CLI: local VPN users", "show user local"),
			}},
		findings.Indicator{Kind: "file", Title: "Policies and admin access", Detail: "Firewall policies that allow traffic nobody asked for, and admin access (set allowaccess) on interfaces facing the internet.",
			Commands: []findings.Command{
				cmd("FortiGate CLI: firewall policies", "show firewall policy"),
				cmd("FortiGate CLI: interfaces and their admin access", "show system interface"),
			}},
		findings.Indicator{Kind: "process", Title: "Unknown processes", Detail: "Process names that are not FortiOS daemons (sh, busybox, nc, unknown names).",
			Commands: []findings.Command{cmd("FortiGate CLI: top processes", "diagnose sys top 1 30")}},
	)
}

func routerosChecks(software, cve string) findings.CompromiseCheck {
	return check("MikroTik RouterOS", software, cve,
		findings.Indicator{Kind: "file", Title: "Users and sign-ins", Detail: "Users nobody created, and sign-ins from addresses you do not know.",
			Commands: []findings.Command{
				cmd("RouterOS: users", "/user print detail"),
				cmd("RouterOS: who is signed in", "/user active print"),
				cmd("RouterOS: sign-ins in the log", "/log print where message~\"logged in\""),
			}},
		findings.Indicator{Kind: "process", Title: "Scheduler, scripts and files", Detail: "Scheduled jobs and scripts nobody added (a classic way to keep a router), and .rsc or .npk files you did not upload.",
			Commands: []findings.Command{
				cmd("RouterOS: scheduled jobs", "/system scheduler print detail"),
				cmd("RouterOS: scripts", "/system script print detail"),
				cmd("RouterOS: files", "/file print"),
			}},
		findings.Indicator{Kind: "file", Title: "Proxy, DNS and redirects", Detail: "A SOCKS or web proxy turned on, DNS servers changed, or NAT rules that send traffic somewhere else: signs of a router used by someone else.",
			Commands: []findings.Command{
				cmd("RouterOS: SOCKS and web proxy", "/ip socks print\n/ip proxy print"),
				cmd("RouterOS: DNS and NAT", "/ip dns print\n/ip firewall nat print"),
				cmd("RouterOS: services and the networks they accept", "/ip service print"),
			}},
	)
}

func ciscoChecks(software, cve string) findings.CompromiseCheck {
	return check("Cisco IOS", software, cve,
		findings.Indicator{Kind: "file", Title: "Accounts and configuration changes", Detail: "Local users nobody created, and configuration changes nobody in your team made (the archive log only exists when archive logging is on).",
			Commands: []findings.Command{
				cmd("IOS: local users", "show running-config | include username"),
				cmd("IOS: who is signed in", "show users"),
				cmd("IOS: configuration change log", "show archive log config all"),
				cmd("IOS: sign-ins and changes in the log", "show logging | include LOGIN|CONFIG_I"),
			}},
		findings.Indicator{Kind: "web", Title: "Web interface and open ports", Detail: "The web interface turned on although you do not use it, and ports the device listens on that its configuration does not explain.",
			Commands: []findings.Command{
				cmd("IOS: web interface settings", "show running-config | include ip http"),
				cmd("IOS: listening ports", "show control-plane host open-ports"),
			}},
		findings.Indicator{Kind: "file", Title: "Files on the device", Detail: "Files you did not put on flash or bootflash.",
			Commands: []findings.Command{cmd("IOS: files", "dir flash:\ndir bootflash:")}},
	)
}

func netdeviceChecks(software, cve string) findings.CompromiseCheck {
	return check("Network device", software, cve,
		findings.Indicator{Kind: "file", Title: "Admin accounts", Detail: "In the device's admin pages: administrators and VPN users nobody in your team created, and API keys or SSH keys nobody added."},
		findings.Indicator{Kind: "log", Title: "Admin sign-ins and configuration changes", Detail: "In the device's system or audit log: sign-ins from addresses you do not know, and changes nobody in your team made. Compare the running configuration with your last backup."},
		findings.Indicator{Kind: "file", Title: "Firmware and files", Detail: "A firmware version you did not install, and files or scripts on the device you did not upload."},
	)
}

func genericChecks(software, cve string) findings.CompromiseCheck {
	return check("General", software, cve,
		findings.Indicator{Kind: "file", Title: "Accounts", Detail: "In the software's own user list: administrators, users, API keys and tokens nobody in your team created."},
		findings.Indicator{Kind: "log", Title: "Sign-ins and changes", Detail: "In the software's log: sign-ins at odd hours or from addresses you do not know, and settings changed by nobody in your team."},
		findings.Indicator{Kind: "file", Title: "Files", Detail: "Files in the software's folders changed recently that no update explains, and programs started from temporary folders."},
	)
}
