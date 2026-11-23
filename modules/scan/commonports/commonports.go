// Package commonports is the fixed list of TCP ports Vedette always probes on the box's own public IP: the scan module's
// surface scan connects to each of them (and reads web titles and certificates there), and sensor-active's external nmap shape
// names all of them in its -sV run, next to nmap's own most common ports its discovery probed (nmapargv.External). It is a leaf
// with no import at all: the sensor binary links it through nmapargv (TestBinaryDependencies).
package commonports

// Use is what the surface scan does with an open port besides listing it.
type Use int

// The uses of a port.
const (
	Plain   Use = iota // listed only
	Web                // one GET of / over plain HTTP
	WebTLS             // one GET of / over HTTPS, and its certificate
	TLSOnly            // a TLS handshake for the certificate (mail, LDAP, MQTT…)
)

// Port is one port of the list. Service is the usual name of the port, not a detection.
type Port struct {
	Number  int
	Service string
	Use     Use
}

// List is the fixed list of TCP ports: services that are commonly exposed to the Internet by mistake or on purpose (web
// and admin pages, remote access, file sharing, databases, mail, VPN, devices and their remote management). It is a fixed list,
// never a range: about as many ports as the top-100 default of naabu, chosen for what an attacker probes first; about a third of them
// are not among nmap's 1000 most common ports. No UDP.
var List = []Port{
	{21, "ftp", Plain}, {22, "ssh", Plain}, {23, "telnet", Plain}, {25, "smtp", Plain}, {53, "domain", Plain},
	{80, "http", Web}, {81, "http", Web}, {88, "kerberos", Plain}, {102, "s7comm", Plain}, {110, "pop3", Plain},
	{111, "rpcbind", Plain}, {135, "msrpc", Plain}, {139, "netbios-ssn", Plain}, {143, "imap", Plain}, {179, "bgp", Plain},
	{389, "ldap", Plain}, {443, "https", WebTLS}, {445, "microsoft-ds", Plain}, {465, "smtps", TLSOnly}, {502, "modbus", Plain},
	{515, "printer", Plain}, {554, "rtsp", Plain}, {587, "submission", Plain}, {631, "ipp", Plain}, {636, "ldaps", TLSOnly},
	{873, "rsync", Plain}, {993, "imaps", TLSOnly}, {995, "pop3s", TLSOnly}, {1080, "socks", Plain}, {1194, "openvpn", Plain},
	{1433, "ms-sql", Plain}, {1521, "oracle", Plain}, {1723, "pptp", Plain}, {1883, "mqtt", Plain}, {2049, "nfs", Plain},
	{2082, "http", Web}, {2083, "https", WebTLS}, {2086, "http", Web}, {2087, "https", WebTLS}, {2222, "ssh", Plain},
	{2375, "docker", Plain}, {2376, "docker-tls", TLSOnly}, {2379, "etcd", Plain}, {3000, "http", Web}, {3128, "http-proxy", Plain},
	{3306, "mysql", Plain}, {3389, "rdp", Plain}, {4443, "https", WebTLS}, {4899, "radmin", Plain}, {5000, "http", Web},
	{5001, "https", WebTLS}, {5060, "sip", Plain}, {5061, "sips", TLSOnly}, {5432, "postgresql", Plain}, {5601, "http", Web},
	{5672, "amqp", Plain}, {5900, "vnc", Plain}, {5901, "vnc", Plain}, {5938, "teamviewer", Plain}, {5984, "http", Web},
	{5985, "winrm", Plain}, {5986, "winrm-https", TLSOnly}, {6379, "redis", Plain}, {6443, "kubernetes", TLSOnly}, {7001, "http", Web},
	{7002, "https", WebTLS}, {7547, "cwmp", Plain}, {8000, "http", Web}, {8006, "https", WebTLS}, {8008, "http", Web},
	{8009, "ajp13", Plain}, {8080, "http", Web}, {8081, "http", Web}, {8088, "http", Web}, {8089, "https", WebTLS},
	{8090, "http", Web}, {8123, "http", Web}, {8291, "winbox", Plain}, {8443, "https", WebTLS}, {8728, "mikrotik-api", Plain},
	{8729, "mikrotik-api-ssl", TLSOnly}, {8834, "https", WebTLS}, {8880, "http", Web}, {8883, "mqtts", TLSOnly}, {8888, "http", Web},
	{9000, "http", Web}, {9042, "cassandra", Plain}, {9090, "http", Web}, {9100, "jetdirect", Plain}, {9200, "http", Web},
	{9443, "https", WebTLS}, {10000, "https", WebTLS}, {10250, "kubelet", TLSOnly}, {10443, "https", WebTLS}, {11211, "memcached", Plain}, {11443, "https", WebTLS},
	{27017, "mongodb", Plain}, {34567, "dvr", Plain}, {37777, "dvr", Plain},
}

// MaxBelievableOpen is how many TCP ports of one address may be open before the address is taken to answer on every port: an
// ISP router or a firewall with a SYN proxy completes the handshake on all of them, so nmap -sV would read hundreds of
// "tcpwrapped" rows or run into its host timeout. It is a count of open ports, not a share of the probed ones, and it holds for the
// surface scan's 99 ports and for the default scan's about 1,070 (nmap's top 1000 and this list) alike:
//   - a SYN proxy answers on all of the probed ports (99, or about 1,070), far above it either way, so widening the scan does not
//     make it miss one;
//   - a real small office exposes a handful of services (internet-wide scans such as Shodan's and Censys' find one to three open
//     ports on a typical host); one with more than 40 open among the 1,000 most common ports is not a configuration to identify
//     port by port, it is a device answering for everything, or one to fix first;
//   - it bounds the -sV run: nmap reads about 20 ports at a time at the default timing, so 40 identifications fit the external
//     shape's 3-minute host timeout.
//
// With more open than this, the default scan of the public IP still runs -sV over the fixed list (never skipped: real services sit
// behind SYN proxies too) and keeps only the ports where -sV named a real service, dropping the tcpwrapped rows of the proxy, and
// exposure says the address answers everywhere; the deep scan (every port) is not sent, and its rows are discarded the same way.
const MaxBelievableOpen = 40

// Numbers returns the port numbers of List, in its order (ascending).
func Numbers() []int {
	out := make([]int, len(List))
	for i, p := range List {
		out[i] = p.Number
	}
	return out
}
