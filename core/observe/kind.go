package observe

import "strings"

// agentOS is the device kind of an os_version platform (osquery, Wazuh) other than Windows (D-503). The Linux distributions the agent
// supports (INV-2 of agent-intake) and their close kin are run as servers (the install is for servers only, D-34); macOS is a pc.
// Another Linux (a desktop distribution) gives no kind.
var agentOS = map[string]string{
	"ubuntu": "server", "debian": "server", "rhel": "server", "centos": "server", "rocky": "server",
	"almalinux": "server", "ol": "server", "amzn": "server", "sles": "server", "darwin": "pc",
}

// osNames maps the start of an os_version name (lower case, a whole word) to its platform, for an OS stored before agents sent a kind:
// the inventory keeps "name version", not the platform.
var osNames = []struct{ prefix, platform string }{
	{"ubuntu", "ubuntu"}, {"debian", "debian"}, {"red hat enterprise linux", "rhel"}, {"centos", "centos"}, {"rocky linux", "rocky"},
	{"almalinux", "almalinux"}, {"oracle linux", "ol"}, {"amazon linux", "amzn"}, {"sles", "sles"}, {"suse linux enterprise server", "sles"},
	{"macos", "darwin"}, {"mac os x", "darwin"}, {"microsoft windows", "windows"},
}

// AgentKind is the device kind of an agent's os_version row (D-503), within the inventory's kind list: Windows Server is a server and
// another Windows a pc, a supported Linux a server, macOS a pc; anything else "" (no kind observation, the device keeps what it has).
func AgentKind(platform, name string) string {
	p := strings.ToLower(platform)
	if p == "windows" {
		if strings.Contains(strings.ToLower(name), "server") {
			return "server"
		}
		return "pc"
	}
	return agentOS[p]
}

// AgentKindOfOS is AgentKind for the OS text an agent stored ("name version", agent-intake mapper.go), whose platform is not kept: the
// platform is read from the start of the name. It types a device whose agent reported its OS before agents sent a kind (D-503, the
// upgrade path).
func AgentKindOfOS(os string) string {
	s := strings.ToLower(strings.TrimSpace(os))
	for _, n := range osNames {
		if s == n.prefix || strings.HasPrefix(s, n.prefix+" ") {
			return AgentKind(n.platform, s)
		}
	}
	return ""
}
