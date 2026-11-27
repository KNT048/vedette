package productid

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/versionscheme"
)

// Trains says how a product's release trains install side by side on one machine: one software line per train. "" (none) is
// one line whatever the version; "major" one per major release (Java 8 and Java 21, Node.js 20 and 22, Visual C++ 2013 (12) and
// 2015-2022 (14)); "major.minor" one per minor release (.NET 6.0 and 8.0, Python 3.13 and 3.14).
type Trains string

// The train rules.
const (
	TrainsNone       Trains = ""
	TrainsMajor      Trains = "major"
	TrainsMajorMinor Trains = "major.minor"
)

// Class marks a product that sits at the edge of a network or manages one (open vocabulary; "" for any other product).
type Class string

// The product classes.
const (
	ClassNone         Class = ""
	ClassFirewall     Class = "firewall"
	ClassVPN          Class = "vpn"
	ClassMail         Class = "mail"
	ClassFileTransfer Class = "file_transfer"
	ClassRemoteAccess Class = "remote_access"
	ClassBackup       Class = "backup"
	ClassRouter       Class = "router"     // an internet router
	ClassNetwork      Class = "network"    // a switch, access point or router inside the network
	ClassNAS          Class = "nas"        // network storage
	ClassHypervisor   Class = "hypervisor" // a hypervisor or its management
	ClassManagement   Class = "management" // a management console of security products
)

// Valid says whether c is a class of the vocabulary.
func (c Class) Valid() bool {
	switch c {
	case ClassNone, ClassFirewall, ClassVPN, ClassMail, ClassFileTransfer, ClassRemoteAccess, ClassBackup, ClassRouter, ClassNetwork,
		ClassNAS, ClassHypervisor, ClassManagement:
		return true
	}
	return false
}

// CPEName is an NVD CPE product: part (a, o, h), vendor and product as NVD writes them (lower case, "_" for spaces). Prefix:
// the product is a prefix that names every NVD product starting with it ("f5:big-ip_*").
type CPEName struct {
	Part, Vendor, Product string
	Prefix                bool
}

// Base is "part:vendor:product" ("a:apache:http_server"); a prefix name keeps its "*".
func (c CPEName) Base() string {
	b := c.Part + ":" + c.Vendor + ":" + c.Product
	if c.Prefix {
		b += "*"
	}
	return b
}

// Product is one product of the catalogue, or what Resolve found for a name.
type Product struct {
	ID      string // stable catalogue id ("openjdk"); "" for a product built from a CPE the catalogue does not list
	Display string // "Java"
	// Vendor and Product are the product's inventory and exploited-list name; Key is their key.
	Vendor, Product, Key string
	// Also are other "vendor|product" names of the same product (an older name an inventory or a list still uses).
	Also []string
	CPEs []CPEName
	KEV  []string // the exploited-list keys of the product, Key first
	// Scheme is the product's version scheme, a core/versionscheme name ("vmware-esxi", "java"); "" for dotted numbers.
	Scheme string
	Trains Trains
	Class  Class
	// VersionPrefix are words a vendor writes before the release in the version a program reports ("ad " of AnyDesk's "ad 9.7.6"),
	// lower case; OwnVersion drops them.
	VersionPrefix []string

	// Set by Resolve:
	Distribution string // the runtime family's distribution a name stated ("Temurin"); "" when none
	Version      string // the release the name states ("21.0.7" of "Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)")
	// VersionNotOwn: the version a source reports with this name is not the product's release (a distribution's own build
	// number): use Version, or no version at all.
	VersionNotOwn bool
	Upstream      bool // a vendor's own package (google-chrome-stable): its version is the product's release, not a distribution build

	agent bool // an agent's package or program name maps to it
}

// HasCPE says whether the product has an NVD name to compare.
func (p Product) HasCPE() bool { return len(p.CPEs) > 0 }

// ---- the catalogue files ----

type fileEntry struct {
	ID            string        `json:"id"`
	Display       string        `json:"display"`
	Vendor        string        `json:"vendor"`
	Product       string        `json:"product"`
	Also          []string      `json:"also"`
	CPE           []string      `json:"cpe"`
	KEV           []string      `json:"kev"`
	Scheme        string        `json:"scheme"`
	Trains        Trains        `json:"trains"`
	Class         Class         `json:"class"`
	Linux         []string      `json:"linux"`
	LinuxPrefix   []string      `json:"linux_prefix"`
	LinuxUpstream []string      `json:"linux_upstream"`
	Windows       []string      `json:"windows"`
	WindowsPrefix []string      `json:"windows_prefix"`
	Nmap          []string      `json:"nmap"`
	Patterns      []filePattern `json:"patterns"`
	VersionPrefix []string      `json:"version_prefix"`
	Record        []string      `json:"record"`
	KEVShared     []string      `json:"kev_shared"`
}

type filePattern struct {
	Re           string `json:"re"`
	Distribution string `json:"distribution"`
	// Version is the release the name states, a template of the expression's groups ("$1", "1.8.0_$1"); "-" when the name states
	// none and the version the source reports is not the product's own; "" to keep the reported version.
	Version string `json:"version"`
}

type file struct {
	About    string      `json:"_about"`
	Products []fileEntry `json:"products"`
}

type pattern struct {
	re           *regexp.Regexp
	distribution string
	version      string
}

type entry struct {
	p        Product
	patterns []pattern
	// named are the exploited-list names the catalogue really gives the product: its key, its entry's own list (products files,
	// network OS rows) and the curated names that pass ownName. A curated-only product (a picker row) names its key alone: the names
	// its fragments reach are for the row, never a reason to move another product's item onto it (ByKEV).
	named map[string]bool
	// shared are exploited-list names that name the product together with others ("VMware|ESXi and Workstation"): kept in its match
	// keys, never resolved to it (ByKEV), so a person who picks that row for Workstation gets no ESXi line.
	shared []string
}

// name records that the product names an exploited-list name (entry.named).
func (e *entry) name(k string) {
	if e.named == nil {
		e.named = map[string]bool{}
	}
	e.named[k] = true
}

type prefixRow struct {
	prefix string
	e      *entry
}

type linuxName struct {
	e        *entry
	upstream bool
}

// catalogue is the loaded catalogue with its lookups.
type catalogue struct {
	entries     []*entry
	linux       map[string]linuxName
	linuxPrefix []prefixRow
	windows     map[string]*entry
	winPrefix   []prefixRow
	byIdentity  map[string]*entry // Norm(vendor) + "|" + Norm(product) of the product, its other names and its NVD names
	byCPE       map[string]*entry // "part:vendor:product" of its NVD names and of the CPEs nmap prints for it
	nmap        map[string]*entry // "part:vendor:product" nmap prints
	byKey       map[string]*entry // Key of every product, the curated ones too
	byRecord    map[string]*entry // the names a CVE record gives a product of the files (ByRangeName)
	curated     []*entry          // the curated products the catalogue files do not list
}

var cat = mustLoad(catalogdata.Products, catalogdata.Curated, catalogdata.KEVProducts)

func mustLoad(fsys fs.FS, curated, kev []byte) *catalogue {
	c, err := load(fsys, curated, kev)
	if err != nil {
		panic("productid: " + err.Error()) // embedded data; TestCatalogue_Loads names the fault
	}
	return c
}

var (
	cpeRE  = regexp.MustCompile(`^[aoh]:[a-z0-9_.\-~+&!]+:[a-z0-9_.\-~+&!]+\*?$`)
	idRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,60}$`)
	nameRE = regexp.MustCompile(`^[^A-Z\s][^A-Z]{0,99}$`) // a lower-case package or program name
	// versionPrefixRE is a vendor's word before a release: letters, then a space or a hyphen ("ad ")
	versionPrefixRE = regexp.MustCompile(`^[a-z]{1,20}[ -]$`)
	errData         = errors.New("catalogue data")
)

func load(fsys fs.FS, curated, kev []byte) (*catalogue, error) {
	c := &catalogue{linux: map[string]linuxName{}, windows: map[string]*entry{}, byIdentity: map[string]*entry{}, byCPE: map[string]*entry{},
		nmap: map[string]*entry{}, byKey: map[string]*entry{}, byRecord: map[string]*entry{}}
	names, err := fs.Glob(fsys, "products/*.json")
	if err != nil || len(names) == 0 {
		return nil, fmt.Errorf("%w: no products/*.json", errData)
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, name := range names {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		var f file
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", errData, path.Base(name), err)
		}
		for _, fe := range f.Products {
			e, err := c.add(fe)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %q: %w", errData, path.Base(name), fe.ID, err)
			}
			if ids[e.p.ID] || keys[e.p.Key] {
				return nil, fmt.Errorf("%w: %s: id %q or key %q is listed twice", errData, path.Base(name), e.p.ID, e.p.Key)
			}
			ids[e.p.ID], keys[e.p.Key] = true, true
			c.byKey[e.p.Key] = e
			for _, k := range e.p.KEV { // the key and the entry's own list
				e.name(k)
			}
		}
	}
	if err := c.addCurated(curated, kev); err != nil {
		return nil, fmt.Errorf("%w: curated.json: %w", errData, err)
	}
	for _, e := range c.entries { // a shared name is matched, never owned (after the curated rows named what they reach)
		for _, k := range e.shared {
			if !slices.Contains(e.p.KEV, k) {
				e.p.KEV = append(e.p.KEV, k)
			}
			delete(e.named, k)
		}
	}
	return c, nil
}

func (c *catalogue) add(fe fileEntry) (*entry, error) {
	if !idRE.MatchString(fe.ID) || strings.TrimSpace(fe.Display) == "" || strings.TrimSpace(fe.Vendor) == "" || strings.TrimSpace(fe.Product) == "" {
		return nil, errors.New("id, display, vendor and product are required")
	}
	if !fe.Class.Valid() || (fe.Trains != TrainsNone && fe.Trains != TrainsMajor && fe.Trains != TrainsMajorMinor) {
		return nil, errors.New("unknown class or trains")
	}
	if _, ok := versionscheme.Lookup(fe.Scheme); fe.Scheme != "" && !ok {
		return nil, fmt.Errorf("scheme %q is not a core/versionscheme scheme", fe.Scheme)
	}
	p := Product{ID: fe.ID, Display: fe.Display, Vendor: fe.Vendor, Product: fe.Product, Key: Key(fe.Vendor, fe.Product), Also: fe.Also,
		Scheme: fe.Scheme, Trains: fe.Trains, Class: fe.Class, VersionPrefix: fe.VersionPrefix}
	for _, w := range fe.VersionPrefix {
		if !versionPrefixRE.MatchString(w) {
			return nil, fmt.Errorf("version_prefix %q must be lower-case letters, then a space or a hyphen", w)
		}
	}
	p.KEV = []string{p.Key}
	for _, k := range fe.KEV {
		v, pr, ok := strings.Cut(k, "|")
		if !ok || k != Key(v, pr) || slices.Contains(p.KEV, k) {
			return nil, fmt.Errorf("kev %q is not a distinct lower-case vendor|product key", k)
		}
		p.KEV = append(p.KEV, k)
	}
	for _, s := range fe.CPE {
		if !cpeRE.MatchString(s) {
			return nil, fmt.Errorf("cpe %q is not part:vendor:product", s)
		}
		f := strings.SplitN(s, ":", 3)
		p.CPEs = append(p.CPEs, CPEName{Part: f[0], Vendor: f[1], Product: strings.TrimSuffix(f[2], "*"), Prefix: strings.HasSuffix(f[2], "*")})
	}
	e := &entry{p: p}
	for _, k := range fe.KEVShared {
		v, pr, ok := strings.Cut(k, "|")
		if !ok || k != Key(v, pr) || k == p.Key {
			return nil, fmt.Errorf("kev_shared %q is not a lower-case vendor|product key of another name", k)
		}
		e.shared = append(e.shared, k)
	}
	for _, fp := range fe.Patterns {
		re, err := regexp.Compile(fp.Re)
		if err != nil || !strings.HasPrefix(fp.Re, "(?i)^") {
			return nil, fmt.Errorf("pattern %q must compile and start with (?i)^", fp.Re)
		}
		e.patterns = append(e.patterns, pattern{re: re, distribution: fp.Distribution, version: fp.Version})
	}
	names := slices.Concat(fe.Linux, fe.LinuxPrefix, fe.LinuxUpstream, fe.Windows, fe.WindowsPrefix)
	for _, n := range names {
		if !nameRE.MatchString(n) {
			return nil, fmt.Errorf("name %q must be lower case", n)
		}
	}
	e.p.agent = len(names) > 0 || len(e.patterns) > 0
	for _, n := range fe.Linux {
		if _, dup := c.linux[n]; dup {
			return nil, fmt.Errorf("package %q is listed twice", n)
		}
		c.linux[n] = linuxName{e: e}
	}
	for _, n := range fe.LinuxUpstream {
		if _, dup := c.linux[n]; dup {
			return nil, fmt.Errorf("package %q is listed twice", n)
		}
		c.linux[n] = linuxName{e: e, upstream: true}
	}
	for _, n := range fe.LinuxPrefix {
		c.linuxPrefix = append(c.linuxPrefix, prefixRow{prefix: n, e: e})
	}
	for _, n := range fe.Windows {
		if _, dup := c.windows[n]; dup {
			return nil, fmt.Errorf("program %q is listed twice", n)
		}
		c.windows[n] = e
	}
	for _, n := range fe.WindowsPrefix {
		c.winPrefix = append(c.winPrefix, prefixRow{prefix: n, e: e})
	}
	for _, s := range fe.Nmap {
		if !cpeRE.MatchString(s) || strings.HasSuffix(s, "*") {
			return nil, fmt.Errorf("nmap %q is not part:vendor:product", s)
		}
		c.nmap[s], c.byCPE[s] = e, e
	}
	ident := func(vendor, product string) {
		if k := NormKey(vendor, product); len(k) > 2 {
			if _, taken := c.byIdentity[k]; !taken {
				c.byIdentity[k] = e
			}
		}
	}
	ident(fe.Vendor, fe.Product)
	for _, s := range fe.Nmap {
		f := strings.SplitN(s, ":", 3)
		ident(f[1], f[2])
	}
	for _, a := range fe.Also {
		v, pr, ok := strings.Cut(a, "|")
		if !ok {
			return nil, fmt.Errorf("also %q is not vendor|product", a)
		}
		ident(v, pr)
	}
	for _, n := range e.p.CPEs {
		if !n.Prefix {
			ident(n.Vendor, n.Product)
			if _, taken := c.byCPE[n.Base()]; !taken {
				c.byCPE[n.Base()] = e
			}
		}
	}
	// the names a CVE record's affected entry gives the product, keyed as feeds keys a record range (recordKey): its own name, its
	// other names, its exploited-list names and the record names of the entry
	record := func(vendor, product string) error {
		k := recordKey(vendor, product)
		if k == "|" || strings.HasPrefix(k, "|") || strings.HasSuffix(k, "|") {
			return fmt.Errorf("record name %q|%q has no vendor or product", vendor, product)
		}
		if _, taken := c.byRecord[k]; !taken {
			c.byRecord[k] = e
		}
		return nil
	}
	if err := record(fe.Vendor, fe.Product); err != nil {
		return nil, err
	}
	for _, n := range slices.Concat(fe.Also, fe.KEV, fe.Record) {
		v, pr, ok := strings.Cut(n, "|")
		if !ok {
			return nil, fmt.Errorf("name %q is not vendor|product", n)
		}
		if err := record(v, pr); err != nil {
			return nil, err
		}
	}
	c.entries = append(c.entries, e)
	return e, nil
}

// recordKey is a CVE record's vendor and product as feeds keys a record range (feeds.RecordProductKey: NormVendor, NormProduct).
func recordKey(vendor, product string) string {
	return NormVendor(vendor) + "|" + NormProduct(product, vendor)
}

// ByRangeName is the product of the catalogue files that a vulnerability range names, to read its versions with the product's
// scheme: part, vendor and product of an NVD CPE (part "a", "o" or "h"), or, for a CVE record's range without a CPE (part ""), the
// record key feeds stores (feeds.RecordProductKey of the entry's vendor and product: "vmware", "esxi"). A record names a product by
// its own name, one of its other or exploited-list names, or a name its "record" list gives ("NetScaler", "ADC"). ok is false for a
// product the files do not list (a curated product has no scheme).
func ByRangeName(part, vendor, product string) (Product, bool) {
	if part != "" {
		e, ok := cat.byCPE[strings.ToLower(part+":"+vendor+":"+product)]
		if !ok || strings.HasPrefix(e.p.ID, "curated-") {
			return Product{}, false
		}
		return e.p, true
	}
	e, ok := cat.byRecord[recordKey(vendor, product)]
	if !ok {
		return Product{}, false
	}
	return e.p, true
}

// Products is every product of the catalogue, in file and file order.
func Products() []Product {
	out := make([]Product, len(cat.entries))
	for i, e := range cat.entries {
		out[i] = e.p
	}
	return out
}

// AgentProducts is every product an agent's package or program name maps to (the software rows an agent can give).
func AgentProducts() []Product {
	var out []Product
	for _, e := range cat.entries {
		if e.p.agent {
			out = append(out, e.p)
		}
	}
	return out
}

// NmapAliases is the NVD names of the product whose CPE nmap prints as base ("a:igor_sysoev:nginx" is "a:f5:nginx" and
// "a:nginx:nginx" in NVD: nmap's service database keeps a vendor's old name), without base itself; nil when no product has it.
func NmapAliases(base string) []string {
	e, ok := cat.nmap[strings.ToLower(base)]
	if !ok {
		return nil
	}
	var out []string
	for _, n := range e.p.CPEs {
		if !n.Prefix && n.Base() != base {
			out = append(out, n.Base())
		}
	}
	return out
}

// ---- the curated products a person picks when declaring a device (content/catalog/curated.json, read by the web picker too) ----

type curatedRow struct {
	Display  string   `json:"display"`
	Category string   `json:"category"`
	Kind     string   `json:"kind"`
	Vendor   string   `json:"vendor"`
	Product  string   `json:"product"`
	KevMatch []string `json:"kev_match"`
	CPE      []string `json:"cpe"`
}

// curatedFileTransfer are curated products that move files for others (their category says "tools" or "network device").
var curatedFileTransfer = map[string]bool{"Progress MOVEit Transfer": true, "ProFTPD / vsFTPd (FTP server)": true}

// curatedClass is the class of a curated product from its category and kind.
func curatedClass(r curatedRow) Class {
	switch {
	case curatedFileTransfer[r.Display]:
		return ClassFileTransfer
	case r.Kind == "firewall":
		return ClassFirewall
	case r.Category == "Firewall and router" && r.Kind == "router":
		return ClassRouter
	case r.Category == "Network device" && (r.Kind == "router" || r.Kind == "switch" || r.Kind == "ap"):
		return ClassNetwork
	case r.Category == "VPN and remote access" && r.Kind == "server":
		return ClassVPN
	case r.Category == "NAS and storage" || r.Kind == "nas" && r.Category != "Backup":
		return ClassNAS
	case r.Category == "Virtualization" && r.Kind == "server":
		return ClassHypervisor
	case r.Category == "Remote support" && r.Kind == "server":
		return ClassRemoteAccess
	case r.Category == "Email":
		return ClassMail
	case r.Category == "Backup":
		return ClassBackup
	case r.Category == "Security software" && r.Kind == "server":
		return ClassManagement
	}
	return ClassNone
}

var slugRE = regexp.MustCompile(`[^a-z0-9]+`)

// addCurated makes every curated product resolvable: a product the catalogue files list takes the curated class when it has
// none; any other becomes a product of its own with the curated CPEs and the exploited-list keys its kev_match fragments name
// (FragmentMatch, as the inventory reads them).
// Curated products are not in Products: their CPEs are names a scan prints, not aliases for the matcher.
func (c *catalogue) addCurated(data, kevData []byte) error {
	var rows []curatedRow
	if err := json.Unmarshal(data, &rows); err != nil {
		return err
	}
	var kev []struct{ Vendor, Product string }
	if err := json.Unmarshal(kevData, &kev); err != nil {
		return err
	}
	// the list names a product of the files claims (its key and its kev list) are that product's: a curated row of a neighbour never
	// gives them to another product ("Edge and Internet Explorer" is Internet Explorer's, "FortiClient EMS" is the EMS server's)
	claimed := map[string]string{}
	for _, e := range c.byKey {
		for _, k := range e.p.KEV {
			claimed[k] = e.p.ID
		}
	}
	for _, r := range rows {
		if strings.TrimSpace(r.Vendor) == "" || strings.TrimSpace(r.Product) == "" {
			return fmt.Errorf("%q has no vendor or product", r.Display)
		}
		class, key := curatedClass(r), Key(r.Vendor, r.Product)
		e, ok := c.byKey[key]
		if !ok {
			e, ok = c.byIdentity[NormKey(r.Vendor, r.Product)]
		}
		if ok { // a product the files list: it takes the curated class when it has none and the keys the curated row names
			if e.p.Class == ClassNone {
				e.p.Class = class
			}
			e.p.KEV = curatedKEV(e.p.KEV, r.KevMatch, kev, &e.p, claimed)
			for _, k := range e.p.KEV { // own names only (curatedKEV checked them)
				e.name(k)
			}
			continue
		}
		p := Product{ID: "curated-" + strings.Trim(slugRE.ReplaceAllString(strings.ToLower(r.Display), "-"), "-"), Display: r.Display,
			Vendor: r.Vendor, Product: r.Product, Key: key, KEV: []string{key}, Class: class}
		p.KEV = curatedKEV(p.KEV, r.KevMatch, kev, nil, claimed)
		for _, s := range r.CPE {
			if !cpeRE.MatchString(s) || strings.HasSuffix(s, "*") {
				return fmt.Errorf("%q: cpe %q is not part:vendor:product", r.Display, s)
			}
			f := strings.SplitN(s, ":", 3)
			p.CPEs = append(p.CPEs, CPEName{Part: f[0], Vendor: f[1], Product: f[2]})
		}
		e = &entry{p: p}
		e.name(key) // a picker row names its key alone
		c.byKey[key] = e
		c.curated = append(c.curated, e)
		if k := NormKey(r.Vendor, r.Product); len(k) > 2 {
			if _, taken := c.byIdentity[k]; !taken {
				c.byIdentity[k] = e
			}
		}
		for _, n := range p.CPEs {
			if _, taken := c.byCPE[n.Base()]; !taken {
				c.byCPE[n.Base()] = e
			}
		}
	}
	return nil
}

// curatedKEV adds to keys the exploited-list keys a curated row's kev_match fragments name (FragmentMatch: whole words, a list name
// of several products lands on the ones it names), as the inventory's catalogue reads them. For a product the catalogue
// files list (own set), only the product's own names are taken: a list name that holds the product's name or is held by it
// ("Connect Secure, Policy Secure, and Neurons", "Pulse Connect Secure" for Connect Secure; "Exchange" for Exchange Server), never a
// neighbour the fragment also reaches (WinRAR for 7-Zip, FortiOS for FortiClient), nor a name another product of the files claims
// (claimed: "FortiClient EMS", "Edge and Internet Explorer"). Such a product is what agents and scans read, so its keys must name it
// alone.
func curatedKEV(keys, match []string, kev []struct{ Vendor, Product string }, own *Product, claimed map[string]string) []string {
	for _, m := range match {
		for _, k := range kev {
			kk := Key(k.Vendor, k.Product)
			if !FragmentMatch(m, k.Vendor, k.Product) || slices.Contains(keys, kk) {
				continue
			}
			if own != nil && (!ownName(own.Product, own.Vendor, k.Product) || claimed[kk] != "" && claimed[kk] != own.ID) {
				continue
			}
			keys = append(keys, kk)
		}
	}
	return keys
}

// ownName says whether a list's product name names the product: the words of one hold every word of the other, the vendor's words
// left out ("Jenkins Command Line Interface (CLI)" for Jenkins, "Exchange" for Exchange Server, "Internet Explorer and Edge" for
// Edge; never "PHPMailer" for PHP or "Internet Key Exchange" for Exchange Server).
func ownName(product, vendor, listed string) bool {
	drop := map[string]bool{"and": true}
	for _, w := range nameWords(vendor) {
		drop[w] = true
	}
	words := func(s string) map[string]bool {
		out := map[string]bool{}
		for _, w := range nameWords(s) {
			if !drop[w] {
				out[w] = true
			}
		}
		return out
	}
	if len(words(product)) == 0 { // the product is the vendor's name ("Jenkins", "GitLab"): its words are the name
		drop = map[string]bool{"and": true}
	}
	holds := func(a, b map[string]bool) bool {
		for w := range b {
			if !a[w] {
				return false
			}
		}
		return len(b) > 0
	}
	a, b := words(product), words(listed)
	return holds(a, b) || holds(b, a)
}

// nameWords are the lower-case words of a name, split at anything but a letter or a digit.
func nameWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(spaced(s)), func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') })
}

// spaced writes the no-break spaces a list name may hold ("Commerce and\u202fMagento") as plain spaces.
func spaced(s string) string { return strings.NewReplacer("\u00a0", " ", "\u202f", " ").Replace(s) }

// ByKey is the product whose Key is key (lower(vendor)|lower(product)), a curated one too.
func ByKey(key string) (Product, bool) {
	e, ok := cat.byKey[NormalizeKey(key)]
	if !ok {
		return Product{}, false
	}
	return e.p, true
}

var byKEV = sync.OnceValue(func() map[string]*entry {
	out := map[string]*entry{}
	keys := make([]string, 0, len(cat.byKey))
	for k := range cat.byKey {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys { // a product's own key first, then the first product (by key) that lists the name
		out[k] = cat.byKey[k]
	}
	listers := map[string][]*entry{}
	for _, k := range keys {
		for _, n := range cat.byKey[k].p.KEV {
			if !cat.byKey[k].named[n] || strings.HasSuffix(n, "|multiple products") {
				continue // a name the product's picker row reaches but the product does not name; a vendor's "Multiple Products" is no one product
			}
			if !slices.Contains(listers[n], cat.byKey[k]) {
				listers[n] = append(listers[n], cat.byKey[k])
			}
		}
	}
	for n, l := range listers {
		if _, own := out[n]; !own && len(l) == 1 { // a name several products list ("Microsoft|Windows") is no one's
			out[n] = l[0]
		}
	}
	return out
})

// ByKEV is the product an exploited-list name belongs to: the product whose key it is, else the one product that names it (entry.named:
// Internet Explorer for "Microsoft|Edge and Internet Explorer", Office for "Microsoft|Word"); false for a name several products name
// ("Microsoft|Windows") or only a picker row reaches ("Cisco|Identity Services Engine" is no RV router's).
func ByKEV(key string) (Product, bool) {
	e, ok := byKEV()[NormalizeKey(key)]
	if !ok {
		return Product{}, false
	}
	return e.p, true
}
