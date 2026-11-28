package findings

import (
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/productid"
)

// The closing gate's evidence (gate.go). A Proof is one statement a published source makes about a CVE, with the scope it speaks for:
// which product, which builds of it (upstream, a distribution's own build, an Ubuntu Pro pocket), which versions and which platforms.
// A pair is closed as not affected only when a Proof that says so contains the installation on every one of these (Scope.Contains)
// and its kind is one its format can state (gate.go, allowedProof). Nothing here is inferred from the absence of a statement.

// ProofKind is what a not-affected statement says.
type ProofKind uint8

// The kinds of proof. ProofFixedAt is also the kind of an "affected" statement's version span (Says).
const (
	ProofFixedAt           ProofKind = iota + 1 // the version is at or past a fix the source names
	ProofStatedUnaffected                       // the source states these versions are not affected
	ProofBeforeIntroduced                       // the version is older than the release the flaw came in with
	ProofOtherPlatform                          // the source states the flaw only on other platforms (OS, architecture)
	ProofOtherHardware                          // the source states the flaw only on other hardware models
	ProofPersonNotAffected                      // a person answered not affected for this line and CVE
)

var proofKindNames = [...]string{"", "fixed_at", "stated_unaffected", "before_introduced", "other_platform", "other_hardware", "person_not_affected"}

func (k ProofKind) String() string {
	if int(k) < len(proofKindNames) {
		return proofKindNames[k]
	}
	return "unknown"
}

// Format is the standard a statement was read from. Only published data formats and a person's answer exist: a reading produced by a
// language model has no Format value, so it cannot be a Proof.
type Format uint8

// The formats a proof may come from.
const (
	FormatCVE5          Format = iota + 1 // a CVE JSON 5 record (CNA or ADP container)
	FormatNVDCPE                          // an NVD CPE match configuration
	FormatOSV                             // an OSV record
	FormatCSAF                            // a CSAF 2.0 advisory
	FormatOpenVEX                         // an OpenVEX document
	FormatDistroTracker                   // a distribution's security tracker (Debian tracker, Ubuntu OSV/VEX, Alpine secdb)
	FormatMSRelease                       // Microsoft's release and monthly update data
	FormatLineSource                      // a vendor's release-line statement (feeds' line sources)
	FormatPerson                          // a person's answer on the box
)

var formatNames = [...]string{"", "cve5", "nvd_cpe", "osv", "csaf", "openvex", "distro_tracker", "ms_release", "line_source", "person"}

func (f Format) String() string {
	if int(f) < len(formatNames) && f != 0 {
		return formatNames[f]
	}
	return "unknown"
}

// known says f is one of the declared formats.
func (f Format) known() bool { return f >= FormatCVE5 && f <= FormatPerson }

// ProofSource is who stated a proof and where.
type ProofSource struct {
	Format    Format
	Publisher string    // "Debian", "NVD", the CNA's short name
	OwnCNA    bool      // the publisher is the CNA of the product's vendor
	Ref       string    // the record, advisory or row the statement is in
	StatedAt  time.Time // when the source made the statement; zero when not known
	// DefaultUnaffected: the record states that versions it does not list are not affected (CVE JSON 5 defaultStatus "unaffected";
	// OSV's own semantics). Only then may an exact list or a range start prove anything about another version.
	DefaultUnaffected bool
}

// The version schemes a VersionSet and an installation's version are read in.
const (
	SchemeGeneric = "generic" // the matcher's own ordering of vendor versions (CompareVersions)
	SchemeDeb     = "deb"     // dpkg's order (Debian, Ubuntu packages)
	SchemeAPK     = "apk"     // apk's order (Alpine packages)
)

// Span is a version interval in a scheme: From included (excluded with FromExcl), To excluded (included with ToIncl); an empty bound is
// open on that side.
type Span struct {
	From     string
	FromExcl bool
	To       string
	ToIncl   bool
}

// VersionSet is the versions a proof speaks for. Every: all versions. AllExceptListed: every version but those Ranges and Exact list
// (the listed ones are the affected ones). Lines: the release lines the statement is about; with Lines, the installation's release line
// must be one of them, and the other fields are read within it.
type VersionSet struct {
	Scheme          string
	Ranges          []Span
	Exact           []string
	AllExceptListed bool
	Every           bool
	Lines           []string
}

// ProductRef names a product as vendor and product (normalised when compared).
type ProductRef struct{ Vendor, Product string }

func (p ProductRef) zero() bool { return p.Vendor == "" && p.Product == "" }

func (p ProductRef) same(o ProductRef) bool {
	if p == o {
		return true
	}
	return productid.Norm(p.Vendor) == productid.Norm(o.Vendor) && productid.Norm(p.Product) == productid.Norm(o.Product)
}

// OriginKind is who built an installation.
type OriginKind uint8

// The builders of an installation.
const (
	OriginUnknown  OriginKind = iota // not known
	OriginUpstream                   // the vendor's own build
	OriginDistro                     // a distribution's own build (Distro, Release, Pocket)
)

// Origin is the build an installation runs: upstream, or a distribution's build of one release, from its main archive (Pocket "") or
// another pocket ("esm": Ubuntu Pro).
type Origin struct {
	Kind                    OriginKind
	Distro, Release, Pocket string
}

// OriginSet is the builds a proof speaks for: every build (Any), the upstream build, or the distribution builds listed.
type OriginSet struct {
	Any      bool
	Upstream bool
	Builds   []Origin
}

// Platform is what an installation states about where it runs; "" is not stated.
type Platform struct{ OS, Arch, Hardware string }

// PlatformSet is the platforms a proof speaks for: every platform (Any), or the values listed for each dimension a list is given for
// (Except: every value but the listed ones, as an "only on other platforms" statement reads).
type PlatformSet struct {
	Any                bool
	OS, Arch, Hardware []string
	Except             bool
}

// Scope is what a proof speaks for. Install, when set, is the one installation (software line) it is about: a sibling line of the
// same product is another installation.
type Scope struct {
	Product  ProductRef
	Origin   OriginSet
	Versions VersionSet
	Platform PlatformSet
	Install  string
}

// Says is the direction of a statement.
type Says uint8

// The directions of a statement.
const (
	SaysAffected Says = iota + 1
	SaysNotAffected
)

// Proof is one statement about a CVE with its scope. Producer names the matcher step that read it (for the coverage and audits);
// Quote and Note are for display.
type Proof struct {
	Kind     ProofKind
	CVE      string
	Src      ProofSource
	Scope    Scope
	Says     Says
	Producer string
	Quote    string
	Note     string
}

// Blocker is a fact that forbids closing a CVE on the line whatever the proofs say (a record row the reader dropped, a row it cannot
// read, a distribution still triaging, records that conflict).
type Blocker struct {
	CVE      string
	Cause    GateCause
	Producer string
}

// VersionValue is an installation's version in its scheme.
type VersionValue struct{ Scheme, Raw string }

// Installation is one software line of one device as the gate reads it.
type Installation struct {
	Device, Line, InstallKey string
	Product                  []ProductRef // every name the line is identified by
	Origin                   Origin
	Version                  VersionValue
	ReleaseLine              string // the release line of Version in the product's numbering; "" when not known
	Platform                 Platform
}

// GateCause is why a pair stays undecided (or the cause of a Blocker).
type GateCause string

// The causes of an undecided gate decision, in the order one is chosen when several apply (gateCauseRank).
const (
	CauseOtherInstallation GateCause = "other_installation" // the proof is about another installation of the product
	CauseConflict          GateCause = "conflict_may_cover" // an affected statement may cover the installation
	CauseProductUnproved   GateCause = "product_unproved"   // the proof names a product the line is not identified as
	CauseOriginOtherBuild  GateCause = "origin_other_build" // the proof speaks for another build (upstream, distribution, pocket)
	CauseLineNotStated     GateCause = "line_not_stated"    // the proof does not state the installation's version or release line
	CauseSchemeMismatch    GateCause = "scheme_mismatch"    // the proof's versions are in another scheme than the installation's
	CausePlatformUnknown   GateCause = "platform_unknown"   // the proof is limited to platforms the installation does not state
	CauseVersionUnreadable GateCause = "version_unreadable" // the installation's version cannot be compared
	CauseKindNotAllowed    GateCause = "kind_not_allowed"   // the source's format cannot state this kind of proof
	CauseExploitedKind     GateCause = "exploited_kind"     // the kind is an inference not allowed for an exploited CVE
	CauseNoProof           GateCause = "no_proof"           // no statement says not affected
	// Blocker causes.
	CauseLostRow      GateCause = "lost_row"        // the record reader dropped a statement about the product
	CauseRowUnread    GateCause = "row_unread"      // a row about the product cannot be read
	CauseDistroTriage GateCause = "distro_triage"   // the distribution is still triaging the CVE for the package
	CauseRecordClash  GateCause = "record_conflict" // two records about the product disagree
	CauseIdentityRule GateCause = "identity_rule"   // not a decision about this product at all: an identity rule says it is another one
)

var gateCauseRank = map[GateCause]int{
	CauseOtherInstallation: 1, CauseConflict: 2, CauseLostRow: 3, CauseRowUnread: 4, CauseDistroTriage: 5, CauseRecordClash: 6,
	CauseProductUnproved: 7, CauseOriginOtherBuild: 8, CauseLineNotStated: 9, CauseSchemeMismatch: 10, CausePlatformUnknown: 11,
	CauseVersionUnreadable: 12, CauseKindNotAllowed: 13, CauseExploitedKind: 14, CauseNoProof: 15,
}

// firstCause is the cause of cs that gateCauseRank puts first (unknown causes last, then by name): independent of their order.
func firstCause(cs []GateCause) GateCause {
	if len(cs) == 0 {
		return ""
	}
	return slices.MinFunc(cs, func(a, b GateCause) int {
		ra, rb := gateCauseRank[a], gateCauseRank[b]
		if ra == 0 {
			ra = 1000
		}
		if rb == 0 {
			rb = 1000
		}
		if ra != rb {
			return ra - rb
		}
		return strings.Compare(string(a), string(b))
	})
}

// Contains says whether the scope speaks for installation in: Yes only when the installation, product, origin, versions and platform
// each are Yes. A No on any of them is No; else an Unknown is Unknown. The cause is that of the first dimension in that order that is
// not Yes.
func (s Scope) Contains(in Installation) (Tri, GateCause) {
	out, cause := Yes, GateCause("")
	for i := range 5 {
		var t Tri
		var c GateCause
		switch i {
		case 0:
			t, c = s.installIn(in)
		case 1:
			t, c = s.productIn(in)
		case 2:
			t, c = s.Origin.contains(in.Origin)
		case 3:
			t, c = s.Versions.contains(in.Version, in.ReleaseLine)
		default:
			t, c = s.Platform.contains(in.Platform)
		}
		switch {
		case t == No:
			return No, c
		case t == Unknown && out == Yes:
			out, cause = Unknown, c
		}
	}
	return out, cause
}

func (s Scope) installIn(in Installation) (Tri, GateCause) {
	if s.Install == "" || s.Install == in.InstallKey {
		return Yes, ""
	}
	return No, CauseOtherInstallation
}

func (s Scope) productIn(in Installation) (Tri, GateCause) {
	if s.Product.zero() || len(in.Product) == 0 {
		return Unknown, CauseProductUnproved
	}
	for _, p := range in.Product {
		if p.same(s.Product) {
			return Yes, ""
		}
	}
	return No, CauseProductUnproved
}

func (o OriginSet) contains(in Origin) (Tri, GateCause) {
	switch {
	case o.Any:
		return Yes, ""
	case in.Kind == OriginUnknown:
		return Unknown, CauseOriginOtherBuild
	case in.Kind == OriginUpstream && o.Upstream:
		return Yes, ""
	case in.Kind == OriginDistro:
		for _, b := range o.Builds {
			if b.Distro == in.Distro && b.Release == in.Release && b.Pocket == in.Pocket {
				return Yes, ""
			}
		}
	}
	return No, CauseOriginOtherBuild
}

// contains reads version v (release line line) against the set.
func (vs VersionSet) contains(v VersionValue, line string) (Tri, GateCause) {
	if len(vs.Lines) > 0 {
		if line == "" {
			return Unknown, CauseLineNotStated
		}
		if !slices.Contains(vs.Lines, line) {
			return No, CauseLineNotStated
		}
	}
	if vs.Every {
		return Yes, ""
	}
	if vs.Scheme != v.Scheme {
		return Unknown, CauseSchemeMismatch
	}
	if strings.TrimSpace(v.Raw) == "" {
		return Unknown, CauseVersionUnreadable
	}
	listed, unknown := false, false
	for _, r := range vs.Ranges {
		switch r.contains(vs.Scheme, v.Raw) {
		case Yes:
			listed = true
		case Unknown:
			unknown = true
		}
	}
	for _, x := range vs.Exact {
		c, ok := compareIn(vs.Scheme, v.Raw, x)
		switch {
		case !ok:
			unknown = true
		case c == 0:
			listed = true
		}
	}
	switch {
	case listed && !vs.AllExceptListed:
		return Yes, ""
	case listed:
		return No, CauseLineNotStated
	case unknown:
		return Unknown, CauseVersionUnreadable
	case vs.AllExceptListed:
		return Yes, ""
	}
	return No, CauseLineNotStated
}

func (r Span) contains(scheme, v string) Tri {
	unknown := false
	if r.From != "" {
		c, ok := compareIn(scheme, v, r.From)
		switch {
		case !ok:
			unknown = true
		case c < 0 || c == 0 && r.FromExcl:
			return No
		}
	}
	if r.To != "" {
		c, ok := compareIn(scheme, v, r.To)
		switch {
		case !ok:
			unknown = true
		case c > 0 || c == 0 && !r.ToIncl:
			return No
		}
	}
	if unknown {
		return Unknown
	}
	return Yes
}

// compareIn orders a and b in scheme; false when either cannot be read in it. The generic scheme reads build and revision tails too
// (compareBound): two builds of one release are not equal, and a tail it cannot order is unknown.
func compareIn(scheme, a, b string) (int, bool) {
	switch scheme {
	case SchemeGeneric:
		return compareBound(a, b)
	case SchemeDeb:
		c, err := debver.Compare(a, b)
		return c, err == nil
	case SchemeAPK:
		va, ok := parseAPK(a)
		if !ok {
			return 0, false
		}
		vb, ok := parseAPK(b)
		if !ok {
			return 0, false
		}
		return compareAPK(va, vb), true
	}
	return 0, false
}

func (p PlatformSet) contains(in Platform) (Tri, GateCause) {
	if p.Any {
		return Yes, ""
	}
	out := Yes
	for _, d := range [...]struct {
		list []string
		have string
	}{{p.OS, in.OS}, {p.Arch, in.Arch}, {p.Hardware, in.Hardware}} {
		if len(d.list) == 0 {
			continue
		}
		if d.have == "" {
			out = Unknown
			continue
		}
		if slices.ContainsFunc(d.list, func(x string) bool { return strings.EqualFold(x, d.have) }) == p.Except {
			return No, CausePlatformUnknown
		}
	}
	if out == Unknown {
		return Unknown, CausePlatformUnknown
	}
	if len(p.OS)+len(p.Arch)+len(p.Hardware) == 0 {
		return Unknown, CausePlatformUnknown // neither every platform nor any stated one: says nothing
	}
	return Yes, ""
}
