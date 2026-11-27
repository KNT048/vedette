package feeds

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/ulikunitz/xz"

	"github.com/knt048/vedette/core/apkver"
	"github.com/knt048/vedette/core/debver"
)

// Distribution backport data. Ubuntu and Debian fix their packages without changing the upstream version, so a
// patched OpenSSH stays inside NVD's affected range. Three built-in feeds say, for the CVEs of the CISA list, which source
// package of which release is fixed in which distribution version, or not affected; ubuntu-osv and debian-tracker also keep
// the fixed versions of the tier CVEs for the packages the devices run (DistroWant), for findings' "Updates to plan":
//   - ubuntu-osv: Canonical's osv-all.tar.xz, every Ubuntu release in one file; a "fixed" event is the first fixed version.
//   - ubuntu-vex: Canonical's vex-all.tar.xz; only its not_affected statements are kept (its "fixed" statements name the
//     archive's current version, not the first fixed one, so they would keep a patched device suspected).
//   - debian-tracker: the Debian Security Tracker JSON, every Debian release in one file: resolved with a fixed version,
//     or resolved with fixed version "0" (not affected).
//   - alpine-osv: OSV.dev's Alpine ecosystem (all.zip, one OSV record per CVE converted from Alpine's secdb), every Alpine
//     branch OSV lists in one file: a "fixed" event is the first fixed apk release of the source package on that branch, "0" not
//     affected. KEV CVEs only (no tier rows), and pulled only while a device states Alpine (the inventory gate without a first pull).
//
// Each file covers every release, so a pull names none of the releases the customer runs. Open, needs-triage, deferred
// and ignored entries are not kept: they change nothing about a finding.
const (
	DistroUbuntu = "ubuntu"
	DistroDebian = "debian"
	DistroAlpine = "alpine"

	DistroFixed       = "fixed"
	DistroNotAffected = "not_affected"
	// DistroOpen is the distribution's word "affected, no fix yet" (Debian's open entries, an Ubuntu release with no fixed event):
	// kept for every CVE of the CISA list (the matcher judges a package the distribution built by its word alone) and for the tier
	// CVEs of the devices' packages (DistroWant.Row), for "Updates to plan".
	DistroOpen = "open"

	ubuntuOSVFeedID     = "ubuntu-osv"
	ubuntuVEXFeedID     = "ubuntu-vex"
	debianTrackerFeedID = "debian-tracker"
	alpineOSVFeedID     = "alpine-osv"

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

	// The bounds of OSV.dev's Alpine all.zip, a few times what it held on 2026-11-17. The archive is
	// read whole into memory (a zip's directory is at its end): 9,244,018 bytes, 10,859 files, a central directory of 0.9 MB. Only the
	// records of KEV CVEs are unpacked: the largest 26,945 bytes, all of them 582,845 bytes (any record: 44,917 bytes).
	alpineMaxBytes    = 32 << 20
	alpineMaxFiles    = 50_000
	alpineMaxDir      = 8 << 20 // the central directory, read from the end record before the zip reader parses it
	alpineMaxEntry    = 1 << 20
	alpineMaxUnpacked = 64 << 20
	// alpineMaxRelease is the longest fixed release kept (feeds_distro_fix.fixed_version CHECK).
	alpineMaxRelease = 100
)

// DistroFix is what one distribution says about one CVE in one source package of one release.
type DistroFix struct {
	Distro  string // DistroUbuntu, DistroDebian or DistroAlpine
	Release string // "24.04", "12", "3.23" (an Alpine branch)
	Package string // the source package
	CVE     string
	Status  string // DistroFixed or DistroNotAffected
	Fixed   string // the first fixed version (DistroFixed), "" otherwise
	Pro     bool   // the fix is in Ubuntu Pro (ESM) only
}

// DistroWant says which rows a pull keeps: every row of a CVE of the CISA list, as before; of a tier CVE
// (nvd-recent's last 12 months) only the "fixed" rows of a source package some device runs, since the plan lists only
// packages below their fix and the parse of every package of every tier CVE held 434,162 rows (418k of them kernel flavours
// no device runs) and 366 MB of peak RSS for Ubuntu's file on 2026-11-15 (KEV only: 2,131 rows, 159 MB).
type DistroWant struct {
	KEV      map[string]bool // CVEs whose every row is kept
	Tier     map[string]bool // CVEs whose fixed rows of Packages are kept
	Packages map[string]bool // source packages as the security data names them (findings.DevicePackages)
}

// CVE says whether some row of the CVE may be kept: its entry is read.
func (w DistroWant) CVE(c string) bool { return w.KEV[c] || w.Tier[c] }

// Row says whether the row of the CVE for the source package with this status is kept: every row of a CVE of the CISA list (the
// matcher's: fixed, not affected, or open), and every row of a tier CVE for a package some device runs (the plan's).
func (w DistroWant) Row(cve, pkg, _ string) bool { // the status no longer decides: every row of a kept CVE is kept
	return w.KEV[cve] || w.Tier[cve] && w.Packages[pkg]
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
	// alpineEntryRE is a file of OSV.dev's Alpine all.zip: one record per CVE, "ALPINE-CVE-2026-123158.json".
	alpineEntryRE = regexp.MustCompile(`^ALPINE-(CVE-[0-9]{4}-[0-9]{4,})\.json$`)
	// alpineEcosystemRE is the OSV ecosystem of an Alpine branch: "Alpine:v3.23". OSV.dev lists no edge (2026-11-17).
	alpineEcosystemRE = regexp.MustCompile(`^Alpine:v([0-9]{1,2}\.[0-9]{1,3})$`)
	// apkPackageRE is an Alpine (source) package name.
	apkPackageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,99}$`)
	vexEntryRE   = regexp.MustCompile(`^vex/cve/[0-9]{4}/(CVE-[0-9]{4}-[0-9]{4,})\.json$`)
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

// eachTarEntry unpacks an xz tar archive and calls fn for the regular files whose name matches re with a CVE want accepts
// (submatch 1), with the CVE and the file (at most distroMaxEntry bytes; a bigger one is rejected with its CVE).
func eachTarEntry(r io.Reader, re *regexp.Regexp, want func(string) bool, tl *tally, fn func(cve string, body io.Reader) error) error {
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
		if m == nil || !want(m[1]) {
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

// eachZipEntry reads a zip archive whole (at most alpineMaxBytes; its directory is at its end) and calls fn once for each CVE that has
// exactly one file whose name matches re and that want accepts (submatch 1), with the CVE and the file (at most alpineMaxEntry bytes;
// a bigger one is rejected with its CVE). Two files of one CVE reject that CVE. The end record is read first, so
// a directory of more than alpineMaxFiles files or alpineMaxDir bytes is refused before the zip reader parses it (L2). An archive
// where no file name matches re fails (L10: a format change never stores nothing), as do a cut or damaged archive, a file whose
// checksum fails, or files that unpack past alpineMaxUnpacked together: the whole pull fails, never a smaller list.
func eachZipEntry(r io.Reader, re *regexp.Regexp, want func(string) bool, tl *tally, fn func(cve string, body io.Reader) error) error {
	body := &bodyErr{r: r}
	data, err := io.ReadAll(io.LimitReader(body, alpineMaxBytes+1))
	switch {
	case err != nil:
		return body.or(err)
	case len(data) > alpineMaxBytes:
		return fail(ErrTooLarge, "The archive is larger than %d MiB; Vedette would skip it.", alpineMaxBytes>>20)
	}
	files, dir, ok := zipEnd(data)
	switch {
	case !ok:
		return body.or(errNotDistroFile("a zip archive"))
	case files > alpineMaxFiles || dir > alpineMaxDir:
		return fail(ErrBadSample, "The archive lists %d files in %d bytes; Vedette reads at most %d files in %d MiB.", files, dir, alpineMaxFiles, alpineMaxDir>>20)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return body.or(errNotDistroFile("a zip archive"))
	}
	named, count := 0, map[string]int{}
	for _, f := range zr.File {
		if m := re.FindStringSubmatch(f.Name); m != nil && !f.FileInfo().IsDir() {
			named++
			count[m[1]]++
		}
	}
	if named == 0 {
		return fail(ErrBadSample, "No file of the archive is an OSV record of a CVE (ALPINE-CVE-….json); OSV.dev may have changed its format.")
	}
	var unpacked int64
	for row, f := range zr.File {
		m := re.FindStringSubmatch(f.Name)
		if f.FileInfo().IsDir() || m == nil || !want(m[1]) {
			continue
		}
		switch n := count[m[1]]; {
		case n == 0: // the CVE's second file, already rejected with the first
			continue
		case n > 1:
			tl.reject(row+1, "%s: more than one file of the same CVE", m[1])
			count[m[1]] = 0
			continue
		}
		if f.UncompressedSize64 > alpineMaxEntry {
			tl.reject(row+1, "%s: larger than 1 MiB", m[1])
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return errNotDistroFile("a complete zip archive")
		}
		b, err := io.ReadAll(io.LimitReader(rc, alpineMaxEntry+1))
		_ = rc.Close()
		if err != nil || len(b) > alpineMaxEntry { // the zip reader checks the size and checksum at the end of the file
			return errNotDistroFile("a complete zip archive")
		}
		if unpacked += int64(len(b)); unpacked > alpineMaxUnpacked {
			return fail(errUnpackedTooLarge, "The archive's records unpack to more than %d MiB; Vedette would skip it.", alpineMaxUnpacked>>20)
		}
		if err := fn(m[1], bytes.NewReader(b)); err != nil {
			return err
		}
	}
	return nil
}

// zipEnd reads a zip archive's end of central directory record (APPNOTE 4.3.16): the number of files and the size of the central
// directory. ok is false when there is none, or the archive is zip64 (OSV.dev's is not; a zip64 count would need the zip64 record).
func zipEnd(data []byte) (files, dir int, ok bool) {
	const endLen, maxComment = 22, 0xFFFF
	for i := len(data) - endLen; i >= 0 && i >= len(data)-endLen-maxComment; i-- {
		if data[i] != 'P' || string(data[i:i+4]) != "PK\x05\x06" {
			continue
		}
		e := data[i:]
		files = int(e[10]) | int(e[11])<<8
		dir = int(e[12]) | int(e[13])<<8 | int(e[14])<<16 | int(e[15])<<24
		if files == 0xFFFF || dir == 0xFFFFFFFF {
			return 0, 0, false
		}
		return files, dir, true
	}
	return 0, 0, false
}

type osvRecord struct {
	ID        string `json:"id"`
	Withdrawn string `json:"withdrawn"` // a withdrawn record decides nothing
	Affected  []struct {
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

// ParseUbuntuOSV reads Canonical's osv-all.tar.xz and keeps, for the CVEs in want (DistroWant.Row), the first fixed version
// of each source package of each Ubuntu release. A fix of a release only Ubuntu Pro has is kept with Pro set unless the
// release also has a public fix; of several fixed versions the highest is kept. A CVE file with a bad package name,
// version or too many rows is rejected whole (fail closed: findings never decide on half an entry).
func ParseUbuntuOSV(r io.Reader, want DistroWant) (DistroResult, error) {
	tl := newTally()
	var out []DistroFix
	row := 0
	err := eachTarEntry(r, osvEntryRE, want.CVE, tl, func(cve string, body io.Reader) error {
		row++
		var rec osvRecord
		if err := json.NewDecoder(body).Decode(&rec); err != nil {
			tl.reject(row, "%s: not an OSV record", cve)
			return nil
		}
		type key struct{ release, pkg string }
		got := map[key]DistroFix{}
		var open []key // a public release's package with no fixed event: Ubuntu has no fix yet
		for _, a := range rec.Affected {
			m := ubuntuEcosystemRE.FindStringSubmatch(a.Package.Ecosystem)
			if m == nil {
				continue
			}
			pro := m[1] != ""
			fixed := false
			for _, rg := range a.Ranges {
				for _, e := range rg.Events {
					fixed = fixed || e.Fixed != ""
				}
			}
			if !fixed && !pro && debPackageRE.MatchString(a.Package.Name) && want.Row(cve, a.Package.Name, DistroOpen) {
				open = append(open, key{m[2], a.Package.Name})
			}
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
					if !want.Row(cve, a.Package.Name, DistroFixed) {
						continue
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
		for _, k := range open { // a fix for the same release and package elsewhere in the record wins
			if _, ok := got[k]; !ok {
				got[k] = DistroFix{Distro: DistroUbuntu, Release: k.release, Package: k.pkg, CVE: cve, Status: DistroOpen}
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

// ParseAlpineOSV reads OSV.dev's Alpine all.zip and keeps, for the CVEs of want (DistroWant.Row: every row of a CVE of the CISA list,
// and of a tier CVE the rows of the packages the Alpine devices run), the first fixed release of each source package of each Alpine
// branch ("Alpine:v3.23" → release "3.23"): a "fixed" event, the highest of several; "0" is Alpine's "not affected" (secdb's
// convention). secdb lists fixed releases only: a CVE it does not list for a package has no fix from Alpine yet. The record must be about its file's CVE; a record with a bad package name, no affected package
// of an Alpine branch or too many rows is rejected whole, and a withdrawn record keeps nothing. A release apkver cannot read ("1.9.5p2-r0", in old branches of two KEV CVEs on 2026-11-17) drops that branch's
// row only, counted with its value (also one longer than 100 characters or with spaces): a branch without a row never proves "not
// affected" in findings, so the other branches stay usable.
func ParseAlpineOSV(r io.Reader, want DistroWant) (DistroResult, error) {
	tl := newTally()
	var out []DistroFix
	row := 0
	err := eachZipEntry(r, alpineEntryRE, want.CVE, tl, func(cve string, body io.Reader) error {
		row++
		var rec osvRecord
		if err := json.NewDecoder(body).Decode(&rec); err != nil || rec.ID != "ALPINE-"+cve {
			tl.reject(row, "%s: not an OSV record of this CVE", cve)
			return nil
		}
		if rec.Withdrawn != "" { // OSV.dev withdrew it: no claim about any branch
			tl.Accepted++
			return nil
		}
		type key struct{ release, pkg string }
		got := map[key]DistroFix{}
		branches := 0
		for _, a := range rec.Affected {
			m := alpineEcosystemRE.FindStringSubmatch(a.Package.Ecosystem)
			if m == nil {
				continue
			}
			branches++
			if !apkPackageRE.MatchString(a.Package.Name) {
				tl.reject(row, "%s: package %s is not an Alpine package name", cve, quoteVal(a.Package.Name))
				return nil
			}
			for _, rg := range a.Ranges {
				for _, e := range rg.Events {
					f := DistroFix{Distro: DistroAlpine, Release: m[1], Package: a.Package.Name, CVE: cve, Status: DistroFixed, Fixed: e.Fixed}
					switch {
					case e.Fixed == "":
						continue
					case e.Fixed == "0":
						f.Status, f.Fixed = DistroNotAffected, ""
					case len(e.Fixed) > alpineMaxRelease || strings.TrimSpace(e.Fixed) != e.Fixed || !apkver.Valid(e.Fixed):
						tl.reject(row, "%s: release %s is not an Alpine package release", cve, quoteVal(e.Fixed))
						continue
					}
					if !want.Row(cve, a.Package.Name, f.Status) {
						continue
					}
					k := key{m[1], a.Package.Name}
					if old, ok := got[k]; ok && !preferAlpine(f, old) {
						continue
					}
					got[k] = f
				}
			}
		}
		switch {
		case branches == 0 && len(rec.Affected) > 0: // a renamed ecosystem fails loudly (all rejected), never stores nothing
			tl.reject(row, "%s: no affected package of an Alpine branch (ecosystem %s)", cve, quoteVal(rec.Affected[0].Package.Ecosystem))
			return nil
		case len(got) > distroMaxRowsPerCVE:
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

// preferAlpine says whether f replaces old for the same branch and package: a fixed release over "not affected" (as findings reads
// Ubuntu's two files), then the higher release in apk order. secdb lists some CVEs under two releases of one branch (13 KEV
// rows on 2026-11-17, docker 29.4.2-r0 and 29.4.3-r0 for CVE-2026-31431): the higher one is the release that has the whole fix.
func preferAlpine(f, old DistroFix) bool {
	if f.Status != old.Status {
		return f.Status == DistroFixed
	}
	a, _ := apkver.Parse(f.Fixed)
	b, _ := apkver.Parse(old.Fixed)
	return apkver.Compare(a, b) > 0
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
func ParseUbuntuVEX(r io.Reader, want DistroWant) (DistroResult, error) {
	tl := newTally()
	var out []DistroFix
	row := 0
	err := eachTarEntry(r, vexEntryRE, want.CVE, tl, func(cve string, body io.Reader) error {
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
				if want.Row(cve, name, DistroNotAffected) {
					got[key{rel, name}] = true
				}
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

type debianRelease struct {
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	Urgency      string `json:"urgency"`
	// NoDSA and NoDSAReason are set when Debian will not publish a security update for the entry ("minor issue", "ignored",
	// "postponed", "end-of-life"); the tracker writes them as strings, a boolean is read too
	NoDSA       json.RawMessage `json:"nodsa"`
	NoDSAReason json.RawMessage `json:"nodsa_reason"`
}

type debianEntry struct {
	Releases map[string]debianRelease `json:"releases"`
}

// noSecurityUpdate says whether Debian has decided not to publish a security update for the entry: urgency unimportant or
// end-of-life, or a nodsa / nodsa_reason mark.
func (r debianRelease) noSecurityUpdate() bool {
	set := func(m json.RawMessage) bool {
		t := strings.TrimSpace(string(m))
		return t != "" && t != "null" && t != "false" && t != `""`
	}
	return r.Urgency == "unimportant" || r.Urgency == "end-of-life" || set(r.NoDSA) || set(r.NoDSAReason)
}

// ParseDebianTracker reads the Debian Security Tracker JSON ({source: {CVE: {releases: {codename: {status,
// fixed_version}}}}}) as a stream and keeps, for the CVEs in want, each release's "resolved" status: fixed in its
// fixed_version, or not affected when that version is "0". sid has no release number and is skipped; a codename this
// Vedette does not know is rejected with its name. A bad package name or version rejects that package's CVE entry.
func ParseDebianTracker(r io.Reader, want DistroWant) (DistroResult, error) {
	body := &bodyErr{r: r}
	res, err := parseDebian(json.NewDecoder(bufio.NewReaderSize(body, 1<<20)), want)
	if err != nil {
		return DistroResult{}, body.or(err)
	}
	return res, nil
}

// parseDebian is ParseDebianTracker on the decoder of the body.
func parseDebian(dec *json.Decoder, want DistroWant) (DistroResult, error) {
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
			if !want.CVE(cve) {
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
				// open: affected, no fix yet; one Debian will not fix in a security update (unimportant, end-of-life, nodsa, ignored) is left out
				open := rel.Status == "open" && !rel.noSecurityUpdate()
				if rel.Status != "resolved" && !open || codename == "sid" {
					continue
				}
				num, known := debianReleases[codename]
				if !known {
					tl.reject(row, "Debian release %s is not known to this Vedette", quoteVal(codename))
					continue
				}
				f := DistroFix{Distro: DistroDebian, Release: num, Package: pkg, CVE: cve, Status: DistroFixed, Fixed: rel.FixedVersion}
				switch {
				case open:
					f.Status, f.Fixed = DistroOpen, ""
				case rel.FixedVersion == "0":
					f.Status, f.Fixed = DistroNotAffected, ""
				case !debver.Valid(rel.FixedVersion):
					tl.reject(row, "%s: version %s is not a Debian version", cve, quoteVal(rel.FixedVersion))
					bad = true
				}
				if want.Row(cve, pkg, f.Status) {
					rows = append(rows, f)
				}
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
