// The script lists, made from testdata/nse-7.95-categories.txt (nmap 7.95 --script-help in the scan image, no packet sent) and
// reviewed by the lead (FULL-4, D-526, review r1 M2/M3/L5/L6). Edit the lists here, never the categories: a newer nmap's new
// scripts stay out until someone reviews them, and a listed script the image lacks fails the run (an honest failure).

package nmapargv

import "slices"

// fullScripts are the scripts of ExternalFull: nmap's default, safe and vuln categories without dos, brute, external and
// broadcast, minus excludedScripts and disruptiveMoved. 309 scripts.
var fullScripts = []string{
	"acarsd-info", "address-info", "afp-ls", "afp-path-vuln", "afp-serverinfo", "afp-showmount", "ajp-auth", "ajp-headers",
	"ajp-methods", "ajp-request", "allseeingeye-info", "amqp-info", "auth-owners", "auth-spoof", "backorifice-info", "banner",
	"bitcoin-getaddr", "bitcoin-info", "bitcoinrpc-info", "bittorrent-discovery", "bjnp-discover", "cassandra-info", "cics-info",
	"citrix-enum-apps", "citrix-enum-apps-xml", "citrix-enum-servers", "citrix-enum-servers-xml", "clock-skew", "coap-resources",
	"couchdb-databases", "couchdb-stats", "creds-summary", "cups-info", "cups-queue-info", "daap-get-library", "daytime",
	"db2-das-info", "dhcp-discover", "dicom-ping", "dict-info", "distcc-cve2004-2687", "dns-nsid", "dns-service-discovery",
	"drda-info", "duplicates", "epmd-info", "eppc-enum-processes", "finger", "flume-master-info", "freelancer-info", "ftp-anon",
	"ftp-proftpd-backdoor", "ftp-syst", "ftp-vsftpd-backdoor", "ganglia-info", "giop-info", "gkrellm-info", "gopher-ls",
	"gpsd-info", "hadoop-datanode-info", "hadoop-jobtracker-info", "hadoop-namenode-info", "hadoop-secondary-namenode-info",
	"hadoop-tasktracker-info", "hbase-master-info", "hbase-region-info", "hddtemp-info", "hnap-info",
	"http-adobe-coldfusion-apsa1301", "http-affiliate-id", "http-apache-negotiation", "http-apache-server-status",
	"http-aspnet-debug", "http-auth", "http-auth-finder", "http-avaya-ipoffice-users", "http-awstatstotals-exec",
	"http-axis2-dir-traversal", "http-backup-finder", "http-bigip-cookie", "http-cakephp-version", "http-cisco-anyconnect",
	"http-comments-displayer", "http-cookie-flags", "http-cors", "http-csrf", "http-date", "http-dlink-backdoor",
	"http-dombased-xss", "http-enum", "http-favicon", "http-frontpage-login", "http-generator", "http-git",
	"http-gitweb-projects-enum", "http-grep", "http-headers", "http-hp-ilo-info", "http-huawei-hg5xx-vuln", "http-iis-webdav-vuln",
	"http-internal-ip-disclosure", "http-jsonp-detection", "http-litespeed-sourcecode-download", "http-ls",
	"http-majordomo2-dir-traversal", "http-malware-host", "http-mcmp", "http-method-tamper", "http-methods",
	"http-mobileversion-checker", "http-ntlm-info", "http-passwd", "http-php-version", "http-phpmyadmin-dir-traversal",
	"http-phpself-xss", "http-qnap-nas-info", "http-referer-checker", "http-sap-netweaver-leak", "http-security-headers",
	"http-shellshock", "http-slowloris-check", "http-sql-injection", "http-stored-xss", "http-svn-enum", "http-svn-info",
	"http-title", "http-tplink-dir-traversal", "http-trace", "http-traceroute", "http-trane-info", "http-useragent-tester",
	"http-vlcstreamer-ls", "http-vmware-path-vuln", "http-vuln-cve2006-3392", "http-vuln-cve2009-3960", "http-vuln-cve2010-0738",
	"http-vuln-cve2010-2861", "http-vuln-cve2011-3192", "http-vuln-cve2011-3368", "http-vuln-cve2012-1823",
	"http-vuln-cve2013-0156", "http-vuln-cve2013-6786", "http-vuln-cve2013-7091", "http-vuln-cve2014-2126",
	"http-vuln-cve2014-2127", "http-vuln-cve2014-2128", "http-vuln-cve2014-2129", "http-vuln-cve2014-3704",
	"http-vuln-cve2014-8877", "http-vuln-cve2015-1635", "http-vuln-cve2017-1001000", "http-vuln-cve2017-5638",
	"http-vuln-cve2017-5689", "http-vuln-cve2017-8917", "http-vuln-misfortune-cookie", "http-vuln-wnr1000-creds",
	"http-webdav-scan", "http-wordpress-users", "icap-info", "ike-version", "imap-capabilities", "imap-ntlm-info",
	"ip-https-discover", "ipidseq", "ipmi-cipher-zero", "ipmi-version", "ipv6-node-info", "irc-botnet-channels", "irc-info",
	"irc-unrealircd-backdoor", "iscsi-info", "isns-info", "jdwp-info", "knx-gateway-info", "ldap-rootdse", "ldap-search",
	"lexmark-config", "maxdb-info", "mcafee-epo-agent", "membase-http-info", "memcached-info", "mongodb-databases", "mongodb-info",
	"mqtt-subscribe", "ms-sql-config", "ms-sql-dac", "ms-sql-dump-hashes", "ms-sql-hasdbaccess", "ms-sql-info", "ms-sql-ntlm-info",
	"ms-sql-query", "ms-sql-tables", "msrpc-enum", "mysql-audit", "mysql-dump-hashes", "mysql-info", "mysql-query", "nat-pmp-info",
	"nbns-interfaces", "nbstat", "ncp-enum-users", "ncp-serverinfo", "ndmp-fs-info", "netbus-auth-bypass", "netbus-info", "nfs-ls",
	"nfs-showmount", "nfs-statfs", "nntp-ntlm-info", "ntp-info", "omp2-enum-targets", "openflow-info", "openlookup-info",
	"openwebnet-discovery", "oracle-tns-version", "p2p-conficker", "path-mtu", "pop3-capabilities", "pop3-ntlm-info", "port-states",
	"qconn-exec", "qscan", "quake1-info", "quake3-info", "quake3-master-getservers", "rdp-enum-encryption", "rdp-ntlm-info",
	"realvnc-auth-bypass", "redis-info", "reverse-index", "rfc868-time", "riak-http-info", "rmi-dumpregistry",
	"rmi-vuln-classloader", "rpcap-info", "rpcinfo", "rsa-vuln-roca", "rsync-list-modules", "rtsp-methods", "rusers", "servicetags",
	"sip-methods", "smb-double-pulsar-backdoor", "smb-enum-services", "smb-ls", "smb-mbenum", "smb-os-discovery", "smb-protocols",
	"smb-security-mode", "smb-vuln-ms17-010", "smb-vuln-webexec", "smb2-capabilities", "smb2-security-mode", "smb2-time",
	"smb2-vuln-uptime", "smtp-commands", "smtp-ntlm-info", "smtp-strangeport", "snmp-hh3c-logins", "snmp-info", "snmp-interfaces",
	"snmp-netstat", "snmp-processes", "snmp-sysdescr", "snmp-win32-services", "snmp-win32-shares", "snmp-win32-software",
	"snmp-win32-users", "socks-auth-info", "ssh-hostkey", "ssh2-enum-algos", "sshv1", "ssl-ccs-injection", "ssl-cert",
	"ssl-cert-intaddr", "ssl-date", "ssl-dh-params", "ssl-heartbleed", "ssl-known-key", "ssl-poodle", "sslv2", "sslv2-drown",
	"sstp-discover", "stun-info", "supermicro-ipmi-conf", "telnet-encryption", "telnet-ntlm-info", "tftp-version", "tls-alpn",
	"tls-nextprotoneg", "tls-ticketbleed", "tn3270-screen", "ubiquiti-discovery", "unusual-port", "upnp-info", "uptime-agent-info",
	"ventrilo-info", "versant-info", "vmware-version", "vnc-info", "voldemort-info", "vuze-dht-info", "wdb-version",
	"weblogic-t3-info", "wsdd-discover", "x11-access", "xdmcp-discover", "xmlrpc-methods", "xmpp-info",
}

// disruptiveExtra are the scripts ExternalDisruptive adds: the dos and brute categories minus excludedScripts, plus
// disruptiveMoved. 90 scripts.
var disruptiveExtra = []string{
	"afp-brute", "ajp-brute", "backorifice-brute", "cassandra-brute", "cics-enum", "cics-user-brute", "cics-user-enum",
	"citrix-brute-xml", "cvs-brute", "cvs-brute-repository", "deluge-rpc-brute", "dicom-brute", "domcon-brute", "dpap-brute",
	"drda-brute", "ftp-brute", "ftp-libopie", "ftp-vuln-cve2010-4221", "http-brute", "http-form-brute", "http-iis-short-name-brute",
	"http-joomla-brute", "http-slowloris", "http-wordpress-brute", "iax2-brute", "imap-brute", "impress-remote-discover",
	"informix-brute", "ipmi-brute", "irc-brute", "irc-sasl-brute", "iscsi-brute", "ldap-brute", "lu-enum", "membase-brute",
	"metasploit-msgrpc-brute", "metasploit-xmlrpc-brute", "mikrotik-routeros-brute", "mmouse-brute", "mongodb-brute", //nolint:misspell // nmap's script name
	"ms-sql-brute", "mysql-brute", "mysql-enum", "mysql-vuln-cve2012-2122", "nessus-brute", "nessus-xmlrpc-brute", "netbus-brute",
	"nexpose-brute", "nje-node-brute", "nje-pass-brute", "nping-brute", "omp2-brute", "openvas-otp-brute", "oracle-brute",
	"oracle-brute-stealth", "oracle-sid-brute", "pcanywhere-brute", "pgsql-brute", "pop3-brute", "rdp-vuln-ms12-020", "redis-brute",
	"rexec-brute", "rlogin-brute", "rpcap-brute", "rsync-brute", "rtsp-url-brute", "samba-vuln-cve-2012-1182", "sip-brute",
	"smb-brute", "smb-flood", "smb-vuln-conficker", "smb-vuln-cve2009-3103", "smb-vuln-ms06-025", "smb-vuln-ms07-029",
	"smb-vuln-ms08-067", "smb-vuln-ms10-054", "smb-vuln-regsvc-dos", "smtp-brute", "smtp-vuln-cve2010-4344",
	"smtp-vuln-cve2011-1720", "snmp-brute", "socks-brute", "ssh-brute", "svn-brute", "telnet-brute", "tso-enum", "vmauthd-brute",
	"vnc-brute", "vtam-enum", "xmpp-brute",
}

// excludedScripts never run in any shape, with why: they reach a host or resolver other than the target, write or change
// something on it, or act on the box's own LAN.
var excludedScripts = map[string]string{ //nolint:gosec // G101: script names and reasons, no credential
	"clamav-exec":                  "can send a command such as SHUTDOWN to ClamAV",
	"dns-client-subnet-scan":       "asks a DNS server about a domain of its arguments",
	"dns-recursion":                "makes the target's DNS server resolve a name on the Internet",
	"dns-srv-enum":                 "asks DNS about a domain of its arguments",
	"dns-update":                   "writes a record into the target's DNS zone",
	"fcrdns":                       "resolves the target's PTR and forward names through the box's resolver (not the target)",
	"firewalk":                     "sends TTL-limited probes that end at routers on the way, not the target",
	"firewall-bypass":              "opens a hole through a firewall helper",
	"ftp-bounce":                   "resolves scanme.nmap.org and asks the FTP server to connect to a third host",
	"http-fetch":                   "downloads files from the target onto the box's disk",
	"http-fileupload-exploiter":    "uploads files to the target",
	"http-vuln-cve2015-1427":       "creates data in the target's Elasticsearch",
	"ip-forwarding":                "checks forwarding to a host of its arguments",
	"ip-geolocation-map-kml":       "writes a map file on the box (postrule); needs arguments",
	"ipv6-ra-flood":                "floods the box's LAN with IPv6 router advertisements, not the target",
	"ldap-novell-getpass":          "needs credentials; reads a user's password",
	"metasploit-info":              "logs in to a Metasploit RPC service",
	"multicast-profinet-discovery": "sends a multicast on the box's LAN",
	"nat-pmp-mapport":              "creates a port mapping on the router",
	"puppet-naivesigning":          "submits a certificate signing request to the target",
	"resolveall":                   "resolves host names (prerule): DNS outside the target",
	"smb-vuln-cve-2017-7494":       "can write a library onto a writable share",
	"smb-vuln-ms10-061":            "can start a print job on the target's printer spooler",
	"smtp-vuln-cve2011-1764":       "sends an e-mail through the target",
	"targets-traceroute":           "adds the hops on the way as new targets",
	"targets-xml":                  "adds targets from a file",
	"unittest":                     "nmap's own self test",
	"url-snarf":                    "sniffs the box's own network interface",
}

// disruptiveMoved are in nmap's default, safe or vuln categories but try logins or can crash a service: only with the
// disruptive tick (the terms say passwords are not guessed without it).
var disruptiveMoved = map[string]string{
	"ftp-libopie":              "can crash the FTP server",
	"ftp-vuln-cve2010-4221":    "can crash the FTP server",
	"mysql-vuln-cve2012-2122":  "about 1500 root login attempts",
	"rdp-vuln-ms12-020":        "can crash the Remote Desktop service",
	"samba-vuln-cve-2012-1182": "malformed RPC that can crash Samba",
	"smtp-vuln-cve2010-4344":   "sends a large message that can crash Exim",
	"smtp-vuln-cve2011-1720":   "can crash the mail server",
}

// noOutputScripts can print credentials, password hashes or files that hold them: their output is not kept (StoresOutput).
// Every brute script, and the ones that read secrets. 94 scripts.
var noOutputScripts = []string{
	"afp-brute", "ajp-brute", "backorifice-brute", "cassandra-brute", "cics-enum", "cics-user-brute", "cics-user-enum",
	"citrix-brute-xml", "creds-summary", "cvs-brute", "cvs-brute-repository", "deluge-rpc-brute", "dicom-brute", "domcon-brute",
	"dpap-brute", "drda-brute", "ftp-brute", "http-adobe-coldfusion-apsa1301", "http-axis2-dir-traversal", "http-brute",
	"http-form-brute", "http-iis-short-name-brute", "http-joomla-brute", "http-litespeed-sourcecode-download",
	"http-majordomo2-dir-traversal", "http-passwd", "http-phpmyadmin-dir-traversal", "http-tplink-dir-traversal",
	"http-vuln-cve2010-2861", "http-vuln-cve2013-7091", "http-vuln-wnr1000-creds", "http-wordpress-brute", "iax2-brute",
	"imap-brute", "impress-remote-discover", "informix-brute", "ipmi-brute", "irc-brute", "irc-sasl-brute", "iscsi-brute",
	"ldap-brute", "ldap-search", "lu-enum", "membase-brute", "metasploit-msgrpc-brute", "metasploit-xmlrpc-brute",
	"mikrotik-routeros-brute", "mmouse-brute", "mongodb-brute", "ms-sql-brute", "ms-sql-dump-hashes", "ms-sql-query", "mysql-brute", //nolint:misspell // nmap's script name
	"mysql-dump-hashes", "mysql-enum", "mysql-query", "mysql-vuln-cve2012-2122", "nessus-brute", "nessus-xmlrpc-brute",
	"netbus-brute", "nexpose-brute", "nje-node-brute", "nje-pass-brute", "nping-brute", "omp2-brute", "openvas-otp-brute",
	"oracle-brute", "oracle-brute-stealth", "oracle-sid-brute", "pcanywhere-brute", "pgsql-brute", "pop3-brute", "redis-brute",
	"rexec-brute", "rlogin-brute", "rpcap-brute", "rsync-brute", "rtsp-url-brute", "sip-brute", "smb-brute", "smtp-brute",
	"snmp-brute", "snmp-hh3c-logins", "snmp-win32-users", "socks-brute", "ssh-brute", "supermicro-ipmi-conf", "svn-brute",
	"telnet-brute", "tso-enum", "vmauthd-brute", "vnc-brute", "vtam-enum", "xmpp-brute",
}

// StoresOutput says whether the output text of script id may be kept; false: only its id, state and CVEs are (review r1 M4).
func StoresOutput(id string) bool { return !slices.Contains(noOutputScripts, id) }
