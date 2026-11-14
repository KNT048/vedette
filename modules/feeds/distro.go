package feeds

import (
	"archive/tar"
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/ulikunitz/xz"

	"github.com/knt048/vedette/core/debver"
)

// Distribution backport data (D-516). Ubuntu and Debian fix their packages without changing the upstream version, so a
// patched OpenSSH stays inside NVD's affected range. Three built-in feeds say, for the CVEs of the CISA list, which source
// package of which release is fixed in which distribution version, or not affected:
//   - ubuntu-osv: Canonical's osv-all.tar.xz, every Ubuntu release in one file; a "fixed" event is the first fixed version.
//   - ubuntu-vex: Canonical's vex-all.tar.xz; only its not_affected statements are kept (its "fixed" statements name the
//     archive's current version, not the first fixed one, so they would keep a patched device suspected).
//   - debian-tracker: the Debian Security Tracker JSON, every Debian release in one file: resolved with a fixed version,
//     or resolved with fixed version "0" (not affected).
//
// Each file covers every release, so a pull names none of the releases the customer runs. Open, needs-triage, deferred
// and ignored entries are not kept: they change nothing about a finding.
const (
	DistroUbuntu = "ubuntu"
	DistroDebian = "debian"

	DistroFixed       = "fixed"
	DistroNotAffected = "not_affected"

	ubuntuOSVFeedID     = "ubuntu-osv"
	ubuntuVEXFeedID     = "ubuntu-vex"
	debianTrackerFeedID = "debian-tracker"

	// distroMaxBytes bounds what a source sends, counted after the transport's gzip decoding: on 2026-11-14 the OSV
	// archive was 63 MB, the VEX archive 79 MB and the Debian JSON 90 MB (15 MB gzip).
	distroMaxBytes = 400_000_000
	// distroMaxUnpacked bounds what an xz archive unpacks to: 12.6 GB (OSV) and 29.9 GB (VEX) on 2026-11-14.
	distroMaxUnpacked = 128 << 30
	// distroMaxEntry bounds one CVE file of an archive (the largest VEX file was 17.4 MB on 2026-11-14).
	distroMaxEntry = 64 << 20
	// distroMaxDict bounds the LZMA2 dictionary an archive asks for (review L2 of #732): the decoder allocates it, and core runs
	// with a 2 GB memory limit. Canonical's archives are one block with a 64 MiB dictionary (xz --list, 2026-11-14).
	distroMaxDict = 64 << 20
	// distroMaxRowsPerCVE fails a hostile CVE entry closed (the Linux kernel CVEs have a few hundred source packages).
	distroMaxRowsPerCVE = 20_000
)

// DistroFix is what one distribution says about one CVE in one source package of one release.
type DistroFix struct {
	Distro  string // DistroUbuntu or DistroDebian
	Release string // "24.04", "12"
	Package string // the source package
	CVE     string
	Status  string // DistroFixed or DistroNotAffected
	Fixed   string // the first fixed version (DistroFixed), "" otherwise
	Pro     bool   // the fix is in Ubuntu Pro (ESM) only
}

// DistroResult is one parsed pull.
type DistroResult struct {
	Rows []DistroFix
	Stats
}

// Ubuntu names its releases by codename in VEX; OSV names them by number. A codename this table does not know is
// counted as a rejected row, so Settings → Feeds says so. ponytail: a table, a few lines a year; upgrade path: read the
// codenames from Canonical's releases list.
var ubuntuCodenames = map[string]string{
	"trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04",
	"oracular": "24.10", "plucky": "25.04", "questing": "25.10", "resolute": "26.04", "stonking": "26.10",
}

// debianReleases maps the tracker's codenames to release numbers; sid (unstable) has no number and is skipped.
var debianReleases = map[string]string{"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14", "duke": "15"}

var (
	// debPackageRE is a Debian source package name (Policy §5.6.1).
	debPackageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,99}$`)
	// ubuntuEcosystemRE is an OSV ecosystem of a plain Ubuntu release: "Ubuntu:24.04:LTS", "Ubuntu:26.10",
	// "Ubuntu:Pro:20.04:LTS". FIPS and other streams are left out.
	ubuntuEcosystemRE = regexp.MustCompile(`^Ubuntu:(Pro:)?([0-9]{2}\.[0-9]{2})(:LTS)?$`)
	osvEntryRE        = regexp.MustCompile(`^osv/cve/[0-9]{4}/UBUNTU-(CVE-[0-9]{4}-[0-9]{4,})\.json$`)
	vexEntryRE        = regexp.MustCompile(`^vex/cve/[0-9]{4}/(CVE-[0-9]{4}-[0-9]{4,})\.json$`)
)

// errNotDistroFile is the error of a body that is not the expected archive or JSON.
func errNotDistroFile(what string) error {
	return fail(ErrBadSample, "The answer is not %s.", what)
}

// errUnpackedTooLarge is an archive that unpacks past distroMaxUnpacked: its own sentinel, so the fetcher does not report it as
// a body over the wire cap (review L3 of #732).
var errUnpackedTooLarge = errors.New("feeds: the archive unpacks past the cap")

// bodyErr remembers the first error the body itself gave (a cut connection, a deadline, the wire cap), so a parser that fails
// because of it returns that error, not "the answer is not …" (review L3 of #732).
type bodyErr struct {
	r   io.Reader
	err error
}

func (b *bodyErr) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && b.err == nil {
		b.err = err
	}
	return n, err
}

// or is the body's own error when it gave one, else err.
func (b *bodyErr) or(err error) error {
	if b.err != nil {
		return b.err
	}
	return err
}

// unpackCap fails with errUnpackedTooLarge once more than left bytes were unpacked.
type unpackCap struct {
	r    io.Reader
	left int64
}

func (u *unpackCap) Read(p []byte) (int, error) {
	if u.left <= 0 {
		return 0, errUnpackedTooLarge
	}
	if int64(len(p)) > u.left {
		p = p[:u.left]
	}
	n, err := u.r.Read(p)
	u.left -= int64(n)
	return n, err
}

// xzFirstDict reads the LZMA2 dictionary size the first block of an xz stream asks for (the xz file format 1.1.0, sections
// 2.1.1 and 3.1, and the LZMA2 property byte). ok is false when the header cannot be read; a stream with no block asks for 0.
// ponytail: the first block only; Canonical's archives are one block, and a later block's header is read by the library.
func xzFirstDict(b []byte) (dict int64, ok bool) {
	if len(b) < 13 || string(b[:6]) != "\xfd7zXZ\x00" {
		return 0, false
	}
	if b[12] == 0 { // the index: no block at all
		return 0, true
	}
	size := (int(b[12]) + 1) * 4
	if len(b) < 12+size {
		return 0, false
	}
	h := b[12 : 12+size]
	flags := h[1]
	i := 2
	varint := func() (int, bool) { // header fields are small: more than four bytes (2^28) is not a header Vedette reads
		v := 0
		for shift := 0; i < len(h) && shift < 28; shift += 7 {
			c := h[i]
			i++
			v |= int(c&0x7f) << shift
			if c&0x80 == 0 {
				return v, true
			}
		}
		return 0, false
	}
	for _, bit := range []byte{0x40, 0x80} { // compressed and uncompressed sizes, when present
		if flags&bit != 0 {
			if _, ok := varint(); !ok {
				return 0, false
			}
		}
	}
	for range int(flags&0x03) + 1 {
		id, ok1 := varint()
		n, ok2 := varint()
		if !ok1 || !ok2 || i+n > len(h) {
			return 0, false
		}
		if id == 0x21 { // LZMA2: one property byte
			p := h[i]
			switch {
			case n != 1 || p > 40:
				return 0, false
			case p == 40:
				return 0xFFFFFFFF, true
			}
			return int64(2|p&1) << (p/2 + 11), true
		}
		i += n
	}
	return 0, false // no LZMA2 filter
}

// eachTarEntry unpacks an xz tar archive and calls fn for the regular files whose name matches re with a CVE of want
// (submatch 1), with the CVE and the file (at most distroMaxEntry bytes; a bigger one is rejected with its CVE).
func eachTarEntry(r io.Reader, re *regexp.Regexp, want map[string]bool, tl *tally, fn func(cve string, body io.Reader) error) error {
	body := &bodyErr{r: r}
	br := bufio.NewReaderSize(body, 1<<20)
	head, _ := br.Peek(12 + 1024) // the stream header and the first block header (at most 1 024 bytes)
	dict, ok := xzFirstDict(head)
	switch {
	case !ok:
		return body.or(errNotDistroFile("an xz archive"))
	case dict > distroMaxDict:
		return fail(ErrBadSample, "The archive asks for a %d MiB dictionary; Vedette unpacks at most %d MiB.", dict>>20, distroMaxDict>>20)
	}
	zr, err := xz.ReaderConfig{SingleStream: true}.NewReader(br)
	if err != nil {
		return body.or(errNotDistroFile("an xz archive"))
	}
	unpacked := &unpackCap{r: zr, left: distroMaxUnpacked}
	failed := func(err error, what string) error {
		if errors.Is(err, errUnpackedTooLarge) {
			return fail(errUnpackedTooLarge, "The archive unpacks to more than %d GiB; Vedette would skip it.", distroMaxUnpacked>>30)
		}
		return body.or(errNotDistroFile(what))
	}
	tr := tar.NewReader(unpacked)
	for row := 1; ; row++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			// tar stops at its end marker, or at any header boundary; reading the xz stream to its end checks its index
			// and footer, so an archive cut short is an error, never a smaller list
			if _, err := io.Copy(io.Discard, unpacked); err != nil {
				return failed(err, "a complete xz archive")
			}
			return body.or(nil)
		}
		if err != nil {
			return failed(err, "a complete tar archive")
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		m := re.FindStringSubmatch(h.Name)
		if m == nil || !want[m[1]] {
			continue
		}
		if h.Size > distroMaxEntry {
			tl.reject(row, "%s: larger than 64 MiB", m[1])
			continue
		}
		if err := fn(m[1], io.LimitReader(tr, distroMaxEntry)); err != nil {
			return err
		}
		if body.err != nil { // the file above was cut by the connection, not bad data: the whole pull fails
			return body.err
		}
	}
}

type osvRecord struct {
	ID       string `json:"id"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// ParseUbuntuOSV reads Canonical's osv-all.tar.xz and keeps, for the CVEs in want, the first fixed version of each
// source package of each Ubuntu release. A fix of a release only Ubuntu Pro has is kept with Pro set unless the
// release also has a public fix; of several fixed versions the highest is kept. A CVE file with a bad package name,
// version or too many rows is rejected whole (fail closed: findings never decide on half an entry).
func ParseUbuntuOSV(r io.Reader, want map[string]bool) (DistroResult, error) {
	tl := newTally()
	var out []DistroFix
	row := 0
	err := eachTarEntry(r, osvEntryRE, want, tl, func(cve string, body io.Reader) error {
		row++
		var rec osvRecord
		if err := json.NewDecoder(body).Decode(&rec); err != nil {
			tl.reject(row, "%s: not an OSV record", cve)
			return nil
		}
		type key struct{ release, pkg string }
		got := map[key]DistroFix{}
		for _, a := range rec.Affected {
			m := ubuntuEcosystemRE.FindStringSubmatch(a.Package.Ecosystem)
			if m == nil {
				continue
			}
			pro := m[1] != ""
			for _, rg := range a.Ranges {
				for _, e := range rg.Events {
					if e.Fixed == "" {
						continue
					}
					if !debPackageRE.MatchString(a.Package.Name) {
						tl.reject(row, "%s: package %s is not a Debian package name", cve, quoteVal(a.Package.Name))
						return nil
					}
					if !debver.Valid(e.Fixed) {
						tl.reject(row, "%s: version %s is not a Debian version", cve, quoteVal(e.Fixed))
						return nil
					}
					k := key{m[2], a.Package.Name}
					f := DistroFix{Distro: DistroUbuntu, Release: m[2], Package: a.Package.Name, CVE: cve, Status: DistroFixed, Fixed: e.Fixed, Pro: pro}
					if old, ok := got[k]; ok && !preferFix(f, old) {
						continue
					}
					got[k] = f
				}
			}
		}
		if len(got) > distroMaxRowsPerCVE {
			tl.reject(row, "%s: more than 20,000 packages", cve)
			return nil
		}
		for _, f := range got {
			out = append(out, f)
		}
		tl.Accepted++
		return nil
	})
	if err != nil {
		return DistroResult{}, err
	}
	return DistroResult{Rows: out, Stats: tl.stats()}, nil
}

// preferFix says whether f replaces old for the same release and package: a public fix over a Pro-only one, then the
// higher version (both are valid: checked before).
func preferFix(f, old DistroFix) bool {
	if f.Pro != old.Pro {
		return !f.Pro
	}
	c, _ := debver.Compare(f.Fixed, old.Fixed)
	return c > 0
}

type vexDoc struct {
	Statements []struct {
		Status   string `json:"status"`
		Products []struct {
			ID string `json:"@id"`
		} `json:"products"`
	} `json:"statements"`
}

// ParseUbuntuVEX reads Canonical's vex-all.tar.xz and keeps the not_affected statements of the CVEs in want: each
// source product ("pkg:deb/ubuntu/<source>@<version>?arch=source&distro=<codename>") of a plain release. Products of a
// pocket (esm-infra/focal, fips/jammy) and binary products are left out. A codename this Vedette does not know is
// rejected with its name; a malformed product rejects the CVE file whole.
func ParseUbuntuVEX(r io.Reader, want map[string]bool) (DistroResult, error) {
	tl := newTally()
	var out []DistroFix
	row := 0
	err := eachTarEntry(r, vexEntryRE, want, tl, func(cve string, body io.Reader) error {
		row++
		var doc vexDoc
		if err := json.NewDecoder(body).Decode(&doc); err != nil {
			tl.reject(row, "%s: not an OpenVEX document", cve)
			return nil
		}
		type key struct{ release, pkg string }
		got := map[key]bool{}
		var unknown string
		for _, st := range doc.Statements {
			if st.Status != "not_affected" {
				continue
			}
			for _, p := range st.Products {
				name, codename, ok, bad := sourcePurl(p.ID)
				if bad {
					tl.reject(row, "%s: product %s is not a Debian package", cve, quoteVal(p.ID))
					return nil
				}
				if !ok {
					continue
				}
				rel, known := ubuntuCodenames[codename]
				if !known {
					unknown = codename
					continue
				}
				got[key{rel, name}] = true
			}
		}
		if unknown != "" {
			tl.reject(row, "Ubuntu release %s is not known to this Vedette", quoteVal(unknown))
		}
		if len(got) > distroMaxRowsPerCVE {
			tl.reject(row, "%s: more than 20,000 packages", cve)
			return nil
		}
		for k := range got {
			out = append(out, DistroFix{Distro: DistroUbuntu, Release: k.release, Package: k.pkg, CVE: cve, Status: DistroNotAffected})
		}
		tl.Accepted++
		return nil
	})
	if err != nil {
		return DistroResult{}, err
	}
	return DistroResult{Rows: out, Stats: tl.stats()}, nil
}

// sourcePurl reads an Ubuntu source product. ok is false for a product that is not about a source package of a plain
// release (a binary, a pocket such as esm-infra/focal); bad is true for one that is not a Debian package at all.
func sourcePurl(id string) (name, codename string, ok, bad bool) {
	rest, found := strings.CutPrefix(id, "pkg:deb/ubuntu/")
	if !found {
		return "", "", false, true
	}
	path, query, _ := strings.Cut(rest, "?")
	name, _, _ = strings.Cut(path, "@")
	name, err := url.PathUnescape(name) // a purl percent-encodes its name (review L4 of #732)
	if err != nil || !debPackageRE.MatchString(name) {
		return "", "", false, true
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return "", "", false, true
	}
	codename = q.Get("distro")
	if q.Get("arch") != "source" || codename == "" || strings.Contains(codename, "/") {
		return "", "", false, false
	}
	return name, codename, true, false
}

type debianEntry struct {
	Releases map[string]struct {
		Status       string `json:"status"`
		FixedVersion string `json:"fixed_version"`
	} `json:"releases"`
}

// ParseDebianTracker reads the Debian Security Tracker JSON ({source: {CVE: {releases: {codename: {status,
// fixed_version}}}}}) as a stream and keeps, for the CVEs in want, each release's "resolved" status: fixed in its
// fixed_version, or not affected when that version is "0". sid has no release number and is skipped; a codename this
// Vedette does not know is rejected with its name. A bad package name or version rejects that package's CVE entry.
func ParseDebianTracker(r io.Reader, want map[string]bool) (DistroResult, error) {
	body := &bodyErr{r: r}
	res, err := parseDebian(json.NewDecoder(bufio.NewReaderSize(body, 1<<20)), want)
	if err != nil {
		return DistroResult{}, body.or(err)
	}
	return res, nil
}

// parseDebian is ParseDebianTracker on the decoder of the body.
func parseDebian(dec *json.Decoder, want map[string]bool) (DistroResult, error) {
	tl := newTally()
	var out []DistroFix
	if !jsonDelim(dec, '{') {
		return DistroResult{}, errNotDistroFile("the Debian Security Tracker JSON")
	}
	row := 0
	for dec.More() {
		pkg, ok := jsonKey(dec)
		if !ok || !jsonDelim(dec, '{') {
			return DistroResult{}, errNotDistroFile("the Debian Security Tracker JSON")
		}
		for dec.More() {
			cve, ok := jsonKey(dec)
			if !ok {
				return DistroResult{}, errNotDistroFile("the Debian Security Tracker JSON")
			}
			if !want[cve] {
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return DistroResult{}, errNotDistroFile("the Debian Security Tracker JSON")
				}
				continue
			}
			row++
			var e debianEntry
			if err := dec.Decode(&e); err != nil {
				return DistroResult{}, errNotDistroFile("the Debian Security Tracker JSON")
			}
			if !debPackageRE.MatchString(pkg) {
				tl.reject(row, "%s: package %s is not a Debian package name", cve, quoteVal(pkg))
				continue
			}
			var rows []DistroFix
			bad := false
			for codename, rel := range e.Releases {
				if rel.Status != "resolved" || codename == "sid" {
					continue
				}
				num, known := debianReleases[codename]
				if !known {
					tl.reject(row, "Debian release %s is not known to this Vedette", quoteVal(codename))
					continue
				}
				f := DistroFix{Distro: DistroDebian, Release: num, Package: pkg, CVE: cve, Status: DistroFixed, Fixed: rel.FixedVersion}
				switch {
				case rel.FixedVersion == "0":
					f.Status, f.Fixed = DistroNotAffected, ""
				case !debver.Valid(rel.FixedVersion):
					tl.reject(row, "%s: version %s is not a Debian version", cve, quoteVal(rel.FixedVersion))
					bad = true
				}
				rows = append(rows, f)
			}
			if bad {
				continue
			}
			out = append(out, rows...)
			tl.Accepted++
		}
		if !jsonDelim(dec, '}') {
			return DistroResult{}, errNotDistroFile("the Debian Security Tracker JSON")
		}
	}
	if !jsonDelim(dec, '}') {
		return DistroResult{}, errNotDistroFile("the Debian Security Tracker JSON")
	}
	return DistroResult{Rows: out, Stats: tl.stats()}, nil
}

// jsonDelim reads the next token and reports whether it is d.
func jsonDelim(dec *json.Decoder, d json.Delim) bool {
	t, err := dec.Token()
	return err == nil && t == d
}

// jsonKey reads an object key.
func jsonKey(dec *json.Decoder) (string, bool) {
	t, err := dec.Token()
	s, ok := t.(string)
	return s, err == nil && ok
}
