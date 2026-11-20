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

	catalogdata "github.com/knt048/vedette/content/catalog"
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
	Also   []string
	CPEs   []CPEName
	KEV    []string // the exploited-list keys of the product, Key first
	Scheme string   // version scheme ("java"; "" for dotted numbers)
	Trains Trains
	Class  Class

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
	cpeRE   = regexp.MustCompile(`^[aoh]:[a-z0-9_.\-~+&!]+:[a-z0-9_.\-~+&!]+\*?$`)
	idRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,60}$`)
	nameRE  = regexp.MustCompile(`^[^A-Z\s][^A-Z]{0,99}$`) // a lower-case package or program name
	errData = errors.New("catalogue data")
)

func load(fsys fs.FS, curated, kev []byte) (*catalogue, error) {
	c := &catalogue{linux: map[string]linuxName{}, windows: map[string]*entry{}, byIdentity: map[string]*entry{}, byCPE: map[string]*entry{},
		nmap: map[string]*entry{}, byKey: map[string]*entry{}}
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
		}
	}
	if err := c.addCurated(curated, kev); err != nil {
		return nil, fmt.Errorf("%w: curated.json: %w", errData, err)
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
	p := Product{ID: fe.ID, Display: fe.Display, Vendor: fe.Vendor, Product: fe.Product, Key: Key(fe.Vendor, fe.Product), Also: fe.Also,
		Scheme: fe.Scheme, Trains: fe.Trains, Class: fe.Class}
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
	c.entries = append(c.entries, e)
	return e, nil
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
// (a key whose vendor contains the vendor fragment and whose product contains the product fragment, as the inventory reads them).
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
			e.p.KEV = curatedKEV(e.p.KEV, r.KevMatch, kev, &e.p)
			continue
		}
		p := Product{ID: "curated-" + strings.Trim(slugRE.ReplaceAllString(strings.ToLower(r.Display), "-"), "-"), Display: r.Display,
			Vendor: r.Vendor, Product: r.Product, Key: key, KEV: []string{key}, Class: class}
		p.KEV = curatedKEV(p.KEV, r.KevMatch, kev, nil)
		for _, s := range r.CPE {
			if !cpeRE.MatchString(s) || strings.HasSuffix(s, "*") {
				return fmt.Errorf("%q: cpe %q is not part:vendor:product", r.Display, s)
			}
			f := strings.SplitN(s, ":", 3)
			p.CPEs = append(p.CPEs, CPEName{Part: f[0], Vendor: f[1], Product: f[2]})
		}
		e = &entry{p: p}
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

// curatedKEV adds to keys the exploited-list keys a curated row's kev_match fragments name: a key whose vendor contains the vendor
// fragment and whose product contains the product fragment, as the inventory's catalogue reads them. For a product the catalogue
// files list (own set), only the product's own names are taken: a list name that holds the product's name or is held by it
// ("Connect Secure, Policy Secure, and Neurons", "Pulse Connect Secure" for Connect Secure; "Exchange" for Exchange Server), never a
// neighbour the fragment also reaches (WinRAR for 7-Zip, FortiOS for FortiClient). Such a product is what agents and scans read,
// so its keys must name it alone.
func curatedKEV(keys, match []string, kev []struct{ Vendor, Product string }, own *Product) []string {
	for _, m := range match {
		v, pr, _ := strings.Cut(strings.ToLower(m), "|")
		for _, k := range kev {
			kk := Key(k.Vendor, k.Product)
			if !strings.Contains(strings.ToLower(k.Vendor), v) || pr != "" && !strings.Contains(spaced(strings.ToLower(k.Product)), pr) || slices.Contains(keys, kk) {
				continue
			}
			if own != nil && !ownName(own.Product, own.Vendor, k.Product) {
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
