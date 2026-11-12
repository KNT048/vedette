package surface

// kind is what the scan does with an open port besides listing it.
type kind int

const (
	plain   kind = iota // listed only
	web                 // one GET of / over plain HTTP
	webTLS              // one GET of / over HTTPS, and its certificate
	tlsOnly             // a TLS handshake for the certificate (mail, LDAP, MQTT…)
)

type portSpec struct {
	port    int
	service string
	kind    kind
}

// commonPorts is the fixed list of TCP ports the scan connects to (D-229): services that are commonly exposed to the Internet by
// mistake or on purpose (web and admin pages, remote access, file sharing, databases, mail, VPN, devices and their remote
// management). It is a fixed list, never a range: about as many ports as the top-100 default of naabu, chosen for what an
// attacker probes first. No UDP. Service is the usual name of the port, not a detection.
var commonPorts = []portSpec{
	{21, "ftp", plain}, {22, "ssh", plain}, {23, "telnet", plain}, {25, "smtp", plain}, {53, "domain", plain},
	{80, "http", web}, {81, "http", web}, {88, "kerberos", plain}, {102, "s7comm", plain}, {110, "pop3", plain},
	{111, "rpcbind", plain}, {135, "msrpc", plain}, {139, "netbios-ssn", plain}, {143, "imap", plain}, {179, "bgp", plain},
	{389, "ldap", plain}, {443, "https", webTLS}, {445, "microsoft-ds", plain}, {465, "smtps", tlsOnly}, {502, "modbus", plain},
	{515, "printer", plain}, {554, "rtsp", plain}, {587, "submission", plain}, {631, "ipp", plain}, {636, "ldaps", tlsOnly},
	{873, "rsync", plain}, {993, "imaps", tlsOnly}, {995, "pop3s", tlsOnly}, {1080, "socks", plain}, {1194, "openvpn", plain},
	{1433, "ms-sql", plain}, {1521, "oracle", plain}, {1723, "pptp", plain}, {1883, "mqtt", plain}, {2049, "nfs", plain},
	{2082, "http", web}, {2083, "https", webTLS}, {2086, "http", web}, {2087, "https", webTLS}, {2222, "ssh", plain},
	{2375, "docker", plain}, {2376, "docker-tls", tlsOnly}, {2379, "etcd", plain}, {3000, "http", web}, {3128, "http-proxy", plain},
	{3306, "mysql", plain}, {3389, "rdp", plain}, {4443, "https", webTLS}, {4899, "radmin", plain}, {5000, "http", web},
	{5001, "https", webTLS}, {5060, "sip", plain}, {5061, "sips", tlsOnly}, {5432, "postgresql", plain}, {5601, "http", web},
	{5672, "amqp", plain}, {5900, "vnc", plain}, {5901, "vnc", plain}, {5938, "teamviewer", plain}, {5984, "http", web},
	{5985, "winrm", plain}, {5986, "winrm-https", tlsOnly}, {6379, "redis", plain}, {6443, "kubernetes", tlsOnly}, {7001, "http", web},
	{7002, "https", webTLS}, {7547, "cwmp", plain}, {8000, "http", web}, {8006, "https", webTLS}, {8008, "http", web},
	{8009, "ajp13", plain}, {8080, "http", web}, {8081, "http", web}, {8088, "http", web}, {8089, "https", webTLS},
	{8090, "http", web}, {8123, "http", web}, {8291, "winbox", plain}, {8443, "https", webTLS}, {8728, "mikrotik-api", plain},
	{8729, "mikrotik-api-ssl", tlsOnly}, {8834, "https", webTLS}, {8880, "http", web}, {8883, "mqtts", tlsOnly}, {8888, "http", web},
	{9000, "http", web}, {9042, "cassandra", plain}, {9090, "http", web}, {9100, "jetdirect", plain}, {9200, "http", web},
	{9443, "https", webTLS}, {10000, "https", webTLS}, {10250, "kubelet", tlsOnly}, {10443, "https", webTLS}, {11211, "memcached", plain},
	{27017, "mongodb", plain}, {34567, "dvr", plain}, {37777, "dvr", plain},
}

var portByNumber = func() map[int]portSpec {
	m := make(map[int]portSpec, len(commonPorts))
	for _, p := range commonPorts {
		m[p.port] = p
	}
	return m
}()
