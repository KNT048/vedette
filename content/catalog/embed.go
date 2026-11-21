// Package catalogdata embeds the data files of the product catalog, which the web interface imports too:
// ONE data source for both sides (INV-12, D-58: knowledge about products is data, not code).
//
//   - curated.json: products small businesses use, by commercial name, in popularity order.
//   - kev-products.json: every vendor/product pair ever in CISA KEV (CC0), made by `pnpm fixtures`. It is a
//     stand-in until feeds (WP-20) supplies the live list through inventory.KEV.
package catalogdata

import "embed"

// Curated is curated.json.
//
//go:embed curated.json
var Curated []byte

// KEVProducts is kev-products.json.
//
//go:embed kev-products.json
var KEVProducts []byte

// Products is products/*.json, the product catalogue: per product the names each source gives it (package and program names,
// the CPE nmap prints, the names CVE records give it), its NVD CPE products, its exploited-list keys, version scheme (a
// core/versionscheme name), release trains and runtime family. Read only by core/productid.
//
//go:embed products/*.json
var Products embed.FS

// PlatformLimits is platform-limits.json: exploited CVEs that affect a product only on some platforms, read by findings.
//
//go:embed platform-limits.json
var PlatformLimits []byte

// NetworkOS is network-os.json: the OS a network device states over SNMP (or, for Junos, LLDP) as the NVD product the matcher
// compares, with its version scheme (#910), read by findings.
//
//go:embed network-os.json
var NetworkOS []byte

// ESXiBuilds is esxi-builds.json: the ESXi build number of each 8.0 and 7.0 release, as NVD names it (version and update), read by
// core/versionscheme (the ESXi version scheme: a build's update train), which sensor-active asks to give a host's own statement
// the right CPE.
//
//go:embed esxi-builds.json
var ESXiBuilds []byte

// ExploitAuthors is exploit-authors.json: the GitHub accounts whose proof-of-concept repositories pass the public-exploit quality rule
// on their own, read by feeds (the PoC-in-GitHub feed).
//
//go:embed exploit-authors.json
var ExploitAuthors []byte

// CWENames is cwe-names.json: the name of every weakness and grouping of MITRE's CWE List, read by feeds to name a CVE's weaknesses.
//
//go:embed cwe-names.json
var CWENames []byte
