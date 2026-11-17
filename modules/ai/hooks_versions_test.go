package ai

import (
	"context"
	"strings"
	"testing"
)

// versionStrings are real version, build, update and advisory identifiers as device inventories, vendor bulletins and AI answers
// write them. None of them is personal data: the personal-data hook passes each one through unchanged.
var versionStrings = []string{
	// Windows builds, with and without the 10.0. prefix, and the products that ship with Windows
	"10.0.26100.1742", "26100.1742", "OS build 26100.1742", "Windows 11 24H2 (26100.1742)", "Windows 11 26100.1742", "26100.2314",
	"22631.4460", "10.0.22631.4460", "Windows 11 23H2 (OS Build 22631.4317)", "19045.5131", "10.0.19045.5131", "Windows 10 22H2 19045.5131",
	"17763.6532", "Windows Server 2019 build 17763.6532", "20348.2849", "Windows Server 2022 20348.2849", "14393.7428", "Windows 10 1607 14393.7428",
	"9600.21620", "6.3.9600.21620", "7601.24546", "6.1.7601.24546", "Windows Server 2025 26100.1742", "updated from 26100.1742 to 26100.2314",
	"26100.1742 / 26100.2314", "26100.1742.", "builds 22621.4317, 22631.4317 and 26100.1742", "Office 16.0.17928.20156",
	"Version 2409 (Build 18025.20140)", "Edge 131.0.2903.51", "Chrome 131.0.6778.86", "Defender 1.421.1234.0", "platform 4.18.24090.11",
	"Visual Studio 17.11.35312.102", "SQL Server 2022.160.4145.4", "Exchange 15.2.1544.14", "Teams 24295.605.3225.8804",
	// Microsoft update numbers
	"KB5034441", "KB 5034441", "KB5044284 and KB5046617", "KB5034441 (26100.1742)", "install KB5046617 then reboot", "ADV240001",
	// FortiOS and other appliances
	"FortiOS 7.2.13", "7.2.13", "v7.2.13 build1749", "v7.4.5,build2702", "FortiOS 7.4.5 build2702 (GA.M)", "7.0.15 build0632 (GA)",
	"FG-IR-24-015", "PAN-OS 10.2.9-h1", "NetScaler 14.1-29.72", "ESXi 8.0 Update 3 build 24022510", "vCenter 8.0.3.00300 build 24305161",
	"QTS 5.2.1.2930 build 20241025", "DSM 7.2.2-72806 Update 2", "SonicOS 7.0.1-5145", "Ivanti Connect Secure 22.7R2.3",
	"Cisco IOS XE 17.9.4a", "15.2(7)E10", "ASA 9.18(4)24", "version 2024.003.20180", "release 2402.123.456", "firmware 1.234.567.890",
	// Junos
	"Junos OS 21.4R3-S5.4", "22.4R3.25", "23.2R2-S1", "15.1R7.9", "20.4R3-S9", "JSA88100",
	// Linux and other packages
	"1:2.4.52-1ubuntu4.8", "apache2 1:2.4.52-1ubuntu4.8", "3.0.13-0ubuntu3.4", "1:9.18.28-0ubuntu0.24.04.1", "4.18.0-553.22.1.el8_10",
	"kernel-5.14.0-427.40.1.el9_4", "6.8.0-48-generic", "2:8.2.3995-1ubuntu2.21", "intel-microcode 3.20240910.0ubuntu0.24.04.1",
	"linux-firmware 20240318.git3b128b60-0ubuntu2.5", "openssl 3.0.2-0ubuntu1.18", "1.1.1w-0+deb11u1", "Android UP1A.231005.007",
	"AP2A.240905.003", "TP1A.220624.014", "1.2.3-1+deb12u1", "0.9.8zh",
	// vulnerability and advisory identifiers
	"CVE-2024-12345", "cve-2024-12345", "CVE 2024-12345", "CVE2024-12345", "CVE-2023-36844, CVE-2023-36845 and CVE-2023-36846",
	"GHSA-4v7x-pqxf-cx7m", "GHSA-2345-6789-2345", "ghsa-9999-9999-9999", "ELSA-2024-12345", "CNVD-2024-12345", "EUVD-2025-14498",
	"BDU:2024-01234", "MAL-2024-12345", "NTAP-20240621-0002", "BIT-nginx-2024-12345", "RHSA-2024:12345", "openSUSE-SU-2024:12345-1",
	"USN-7088-1", "DSA-5791-1", "ALAS2-2024-2600", "TALOS-2024-2042", "PYSEC-2024-110", "GO-2024-3107", "RUSTSEC-2024-0375",
	"ICSA-24-123-01", "MS17-010", "ZDI-24-1234",
	// CPE names
	"cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.1742:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_11_24h2:26100.1742:*:*:*:*:*:*:*",
	"cpe:2.3:o:fortinet:fortios:7.2.13:*:*:*:*:*:*:*", "cpe:/o:juniper:junos:21.4:r3-s5", "cpe:2.3:a:vendor:product:2024.123.456:*:*:*:*:*:*:*",
	// ports, addresses, hashes and digests
	"ports 8080 8443 9443", "port 3389 8443 9100 open", "ports 22 443 3389 8443", "443/tcp 8443/tcp 9443/tcp", "cổng 8080 8443 9443",
	"192.168.100.200", "fe80::1c2b:3a4d:5e6f:7081", "10.0.26.100",
	"sha256:9f3a123456789e0b44c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3", "md5 123456789abcdef0123456789abcdef0",
	"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC", "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==",
	"sha1=123456789abcdef0123456789abcdef012345678",
	// a build next to another number, in a list or a table
	"26100.1742\n- 120 devices", "22631.4460 - 120", "26100.1742   312", "build 26100.1742\n- 120 devices", "publicsuffix 20260129.1928",
	// counts with thousands separators, and port lists written with commas
	"123,456,789 lines", "1,234,567,890 events", "ports 135, 139, 445", "ports 135, 139 and 445 are open",
	// lists written with slashes: ports, speeds, VLANs, versions, paths
	"TCP 135/139/445", "ports 135/139/445", "UDP 137/138/139", "Block TCP 135/139/445 and UDP 137/138", "cổng 135/139/445",
	"Chrome 120/121/122", "100/1000/10000 Mbps", "10/100/1000 Mbps", "eth 100/200/300", "vlan 100/200/300", "/var/log/123/456/789",
	"nmap -p 22,80,443,135,139,445",
	// port lists written with spaces
	"Top ports: 80 443 135 139 445", "open: 21 22 23 25 53 80 110 143 443", "ports 21 22 23 25 53 80 110 143 443",
}

// TestVersionStringsAreNotPersonalData: every version, build, update and advisory identifier goes through the personal-data hook
// unchanged, at every moment it runs (the question, a tool result, the answer).
func TestVersionStringsAreNotPersonalData(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	for _, s := range versionStrings {
		if got := findIDNumbers(s); len(got) > 0 {
			t.Errorf("%q read as an ID number at %v", s, got)
		}
		for _, when := range []HookWhen{BeforeAI, AfterAI} {
			if res := run(t, r, when, s); res.Outcome != OutcomePass || res.Text != s {
				t.Errorf("%s %q -> %s %q", when, s, res.Outcome, res.Text)
			}
		}
		if res, err := r.RunPersonalData(context.Background(), s); err != nil || res.Outcome != OutcomePass {
			t.Errorf("tool result %q -> %s %q (%v)", s, res.Outcome, res.Text, err)
		}
	}
}

// TestPersonalDataNextToVersionsIsStillFound: ID numbers, phone numbers, card numbers and email addresses are still blocked or masked,
// alone and when they stand next to a version, a build, an update or an advisory id.
func TestPersonalDataNextToVersionsIsStillFound(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	blocked := []string{
		// citizen ID (12 digits) and old ID card (9 digits) numbers as people write them
		"079201234567", "001085012345", "CCCD 079201234567", "căn cước 001 085 012 345", "CCCD: 0790.1234.5678", "079.201.234.567",
		"079 201 234 567", "0792-0123-4567", "CMND 123456789", "chứng minh nhân dân 024 123 456", "123 456 789", "123.456.789",
		"123-456-789", "CMND: 025.123.456", "so dinh danh 038201004321",
		// after a label, in any shape, also a shape a version or a decimal number has
		"CCCD 079201.234567", "CMND 12345.6789", "ID: 12345.6789", "CCCD.26100.1742", "CMND 2024-12345", "ID-2012-34567",
		// passport numbers after a label
		"passport C1234567", "hộ chiếu B7654321", "passport no. N2345678",
		// an ID number next to a version, an update, an advisory id, a CPE or a port list
		"build 26100.1742 owner 079201234567", "KB5034441 079201234567", "CVE-2024-12345 079 201 234 567",
		"GHSA-4v7x-pqxf-cx7m 123 456 789", "ELSA-2024-12345 CMND 123456789", "26100.1742 CCCD 079201234567",
		"cpe:2.3:o:microsoft:windows_11:10.0.26100.1742:*:*:*:*:*:*:* 079201234567", "ports 8080 8443, owner 079 201 234 567",
		"version 7.2.13 079 201 234 567", "port 8443 079 201 234 567", "sha256:9f3a123456789e0b44c1d2e3 079201234567",
		"2023-36844", "owner 2012-34567", "x 123456789 y", "ab123456789",
		// a 12-digit ID split into two groups by one dot, and a 9-digit ID split 3/6 (not a build: a first group of 4-5 digits not
		// starting with 0)
		"079201.234567", "0792.01234567", "0792012.34567", "Số CCCD của tôi là 079201.234567", "271.234567",
		// after a version word: a first group with a leading zero, or groups of three digits, is an ID
		"firmware 0792.0123.4567", "v079.201.234.567", "rev.079.201.234.567", "ver 123.456.789", "build: 123.456.789",
		"build 079.201.234.567", "release 079.201.234.567", "Kernel: 079.201.234.567", "version 7.2.13 and my ID 079.201.234.567",
		"build 100.234.567", "v123.456.789",
		// next to a bare build
		"26100.1742 079201234567", "079201234567 26100.1742",
		// after a port word: three 3-digit groups, or a list cut short by a group that is not a port
		"port 271 234 567", "cổng 271 234 567", "ports 123 456 789/tcp", "port 271 034 567", "port 271 234 567 890",
		// after KB: a KB number never starts with 0
		"KB 079201 234567", "KB 0792012 34567",
		// an abbreviation that is not an advisory source
		"HN-2012-34567", "SO-2012-34567", "MST-2012-34567", "ID: AB-2012-34567", "VN-201234-567", "HCM-20120345-6789",
		// glued to a CPE or a digest
		"cpe:/a:x:y:079201234567", "cpe:2.3:a:x:y:1.0|cmd:079201234567", "md5=079201234567/home",
		// next to another number: the ID is read on its own
		"Windows 11 079201234567", "room 5 079201234567", "079201234567 2", "079 201 234 567 2", "room 5 079 201 234 567",
		"1234 079201234567", "ports 22 079201234567", "CMND AS201234567 5", "079 201 234 567 1234", "8443 079-201 234-567",
		// separators: dashes of every kind, slash, underscore, and a comma in a number that starts with 0
		"079–201–234–567", "079—201—234—567", "079‐201‐234‐567", "079−201−234−567", "079/201/234/567", "079_201_234_567",
		"079,201,234,567", "123–456–789", "079 / 201 / 234 / 567", "0792/0123/4567",
		// joined by a slash or an underscore to a short number: a path, a date, a file name
		"079201234567/2", "079201234567/2024", "079201234567/12/2020", "/uploads/079201234567/1", "scan_079201234567_2.jpg",
		"079201234567_1.jpg", "IMG_079201234567_01.png", "271234567/2", "x_271234567_2.jpg",
	}
	for _, s := range blocked {
		if res := run(t, r, BeforeAI, s); res.Outcome != OutcomeBlocked {
			t.Errorf("%q -> %s %q, want blocked", s, res.Outcome, res.Text)
		}
	}
	masked := map[string]string{
		"call 0912 345 678":                            "call [masked]",
		"Zalo 0987.654.321 after KB5034441":            "Zalo [masked] after KB5034441",
		"+84 91 234 5678 about 26100.1742":             "[masked] about 26100.1742",
		"call +1 415-555-2671 about FortiOS 7.2.13":    "call [masked] about FortiOS 7.2.13",
		"mail an.nguyen@example.com re CVE-2024-12345": "mail [masked] re CVE-2024-12345",
		"0912345678 on build 26100.1742":               "[masked] on build 26100.1742",
	}
	for in, want := range masked {
		if res := run(t, r, BeforeAI, in); res.Outcome != OutcomeMasked || res.Text != want {
			t.Errorf("%q -> %s %q, want %q", in, res.Outcome, res.Text, want)
		}
	}
}

// TestAnswerNamingAWindowsBuildIsNotStopped: an answer that names a Windows build and its update goes through the after-AI hooks of
// a plain and of a structured answer, and through the check a tool result gets, unchanged.
func TestAnswerNamingAWindowsBuildIsNotStopped(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	answer := "PC-ACCOUNTS-03 runs Windows 11 24H2 build 26100.1742 (KB5034441). Install the November cumulative update KB5046617 " +
		"(build 26100.2314) to fix CVE-2024-43451, then check that Settings > Windows Update shows OS build 26100.2314."
	for _, structured := range []bool{false, true} {
		text := answer
		if structured {
			text = `{"paragraphs":["` + answer + `"],"steps":["Install KB5046617 (10.0.26100.2314)."]}`
		}
		res, err := afterHooks(context.Background(), r, structured, text)
		if err != nil || res.Outcome != OutcomePass || len(res.Hits) != 0 {
			t.Fatalf("structured=%v: %s %q %+v (%v)", structured, res.Outcome, res.Text, res.Hits, err)
		}
		if !strings.Contains(res.Text, "build 26100.1742 (KB5034441)") {
			t.Fatalf("structured=%v: answer changed: %q", structured, res.Text)
		}
	}
	tool := "Device: PC-ACCOUNTS-03, IP 192.168.1.20, kind workstation, Windows 11 Pro 10.0.26100.1742, OS build 26100.1742, last update KB5034441; " +
		"cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.1742:*:*:*:*:*:*:*"
	for _, when := range []HookWhen{BeforeAI, AfterAI} {
		if res := run(t, r, when, tool); res.Outcome != OutcomePass || res.Text != tool {
			t.Fatalf("%s: %s %q", when, res.Outcome, res.Text)
		}
	}
}
