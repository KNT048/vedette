package feeds

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path"
	"strings"
)

// The CVE Program's bulk files. Every day at midnight UTC it publishes the whole list as one archive (a zip holding one zip, cves.zip,
// of one JSON file per CVE: 429,247 records, 740 MB inside a 669 MB download, measured 2026-11-20), and every hour an archive of the
// records changed since midnight (a few MB). The inner zip is read as a stream, entry by entry, so the archive is never unpacked on
// disk. Both are untrusted input: entry counts, name lengths and sizes are bounded, every entry's CRC is checked, and anything that is
// not a plain stored or deflated file fails the read.
const (
	// archiveMaxEntries bounds the entries of one archive (the whole list had 429,907 with its directories in 2026).
	archiveMaxEntries = 3_000_000
	// archiveMaxName bounds an entry's name ("cves/2026/133xxx/CVE-2026-133612.json" is 37 bytes).
	archiveMaxName = 512
	// archiveMaxExtra bounds an entry's extra field.
	archiveMaxExtra = 4096
	// archiveMaxInner bounds the inner zip of the daily archive (740 MB in 2026).
	archiveMaxInner = 8 << 30
	// deltaMaxBytes bounds one hourly archive of changed records (12.7 MB on a busy day in 2026).
	deltaMaxBytes = 256 << 20
)

// archiveEntry is one file of an archive: its name and the CVE ID it names ("" for a directory or another file).
type archiveEntry struct {
	Name string
	CVE  string
	Size uint64 // uncompressed
}

// recordCVE is the CVE ID a record file's name gives ("cves/2024/3xxx/CVE-2024-3400.json" or "deltaCves/CVE-2024-3400.json"), "" for
// any other name.
func recordCVE(name string) string {
	base := path.Base(name)
	cve, ok := strings.CutSuffix(base, ".json")
	if !ok || !cveRE.MatchString(cve) || len(cve) > 32 {
		return ""
	}
	return cve
}

// errArchive is a malformed archive.
var errArchive = errors.New("feeds: the CVE archive is not a zip Vedette can read")

func archiveFail(format string, a ...any) error {
	return &Error{Err: errArchive, Detail: "The CVE Program's archive could not be read: " + fmt.Sprintf(format, a...) + "."}
}

// walkDailyArchive reads the daily archive whole from r (a file of size n): the one zip inside it, entry by entry (walkZipStream).
func walkDailyArchive(r io.ReaderAt, n int64, fn func(e archiveEntry, body func() ([]byte, error)) error) error {
	outer, err := zip.NewReader(r, n)
	if err != nil {
		return archiveFail("%v", err)
	}
	var inner *zip.File
	for _, f := range outer.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".zip") {
			if inner != nil {
				return archiveFail("it holds more than one archive")
			}
			inner = f
		}
	}
	if inner == nil {
		return archiveFail("it holds no archive of records")
	}
	if inner.UncompressedSize64 > archiveMaxInner {
		return archiveFail("its archive of records is larger than %d GB", archiveMaxInner>>30)
	}
	rc, err := inner.Open()
	if err != nil {
		return archiveFail("%v", err)
	}
	defer func() { _ = rc.Close() }()
	if err := walkZipStream(io.LimitReader(rc, archiveMaxInner+1), fn); err != nil {
		return err
	}
	// what is left of the inner zip (its central directory) is read so the outer entry's CRC is checked
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return archiveFail("%v", err)
	}
	return nil
}

// walkDeltaArchive reads an hourly archive of changed records (a plain zip, read whole: deltaMaxBytes).
func walkDeltaArchive(data []byte, fn func(e archiveEntry, body func() ([]byte, error)) error) error {
	if len(data) == 0 {
		return nil
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if errors.Is(err, zip.ErrFormat) && len(data) <= 22 { // the archive of the hour after midnight is an empty zip
		return nil
	}
	if err != nil {
		return archiveFail("%v", err)
	}
	if len(z.File) > archiveMaxEntries {
		return archiveFail("it has more than %d entries", archiveMaxEntries)
	}
	for _, f := range z.File {
		cve := recordCVE(f.Name)
		if cve == "" || f.FileInfo().IsDir() {
			continue
		}
		e := archiveEntry{Name: f.Name, CVE: cve, Size: f.UncompressedSize64}
		body := func() ([]byte, error) {
			if f.UncompressedSize64 > RecordMaxBytes {
				return nil, fail(ErrTooLarge, "The CVE record is larger than %d MB.", RecordMaxBytes>>20)
			}
			rc, err := f.Open()
			if err != nil {
				return nil, archiveFail("%v", err)
			}
			defer func() { _ = rc.Close() }()
			b, err := io.ReadAll(io.LimitReader(rc, RecordMaxBytes+1))
			if err != nil || len(b) > RecordMaxBytes {
				return nil, archiveFail("entry %s: %v", quoteVal(f.Name), err)
			}
			return b, nil
		}
		if err := fn(e, body); err != nil {
			return err
		}
	}
	return nil
}

// The zip signatures read in a stream.
const (
	sigLocal   = 0x04034b50
	sigCentral = 0x02014b50
	sigEnd     = 0x06054b50
	sigEnd64   = 0x06064b50
)

// walkZipStream reads a zip from its first byte to its central directory without seeking: each local file header, then its data.
// fn gets each record entry (recordCVE) with body, which inflates and returns it (at most RecordMaxBytes, its CRC checked); an entry
// fn does not read is skipped without inflating. Entries with a data descriptor (sizes after the data), encryption or another method
// than stored or deflated fail the walk.
func walkZipStream(r io.Reader, fn func(e archiveEntry, body func() ([]byte, error)) error) error {
	br := bufio.NewReaderSize(r, 256<<10)
	var hdr [30]byte
	for n := 0; ; n++ {
		if n > archiveMaxEntries {
			return archiveFail("it has more than %d entries", archiveMaxEntries)
		}
		if _, err := io.ReadFull(br, hdr[:4]); err != nil {
			return archiveFail("it ends before its directory")
		}
		switch binary.LittleEndian.Uint32(hdr[:4]) {
		case sigCentral, sigEnd, sigEnd64:
			return nil // the directory: every file was read
		case sigLocal:
		default:
			return archiveFail("an entry does not start with a file header")
		}
		if _, err := io.ReadFull(br, hdr[4:30]); err != nil {
			return archiveFail("an entry header is cut")
		}
		flags := binary.LittleEndian.Uint16(hdr[6:8])
		method := binary.LittleEndian.Uint16(hdr[8:10])
		crc := binary.LittleEndian.Uint32(hdr[14:18])
		csize := uint64(binary.LittleEndian.Uint32(hdr[18:22]))
		usize := uint64(binary.LittleEndian.Uint32(hdr[22:26]))
		nameLen := int(binary.LittleEndian.Uint16(hdr[26:28]))
		extraLen := int(binary.LittleEndian.Uint16(hdr[28:30]))
		if flags&0x1 != 0 || flags&0x8 != 0 || method != zip.Store && method != zip.Deflate || nameLen > archiveMaxName || extraLen > archiveMaxExtra {
			return archiveFail("an entry is encrypted, has its sizes after its data, or uses another compression")
		}
		buf := make([]byte, nameLen+extraLen)
		if _, err := io.ReadFull(br, buf); err != nil {
			return archiveFail("an entry header is cut")
		}
		name := string(buf[:nameLen])
		if csize == 0xFFFFFFFF || usize == 0xFFFFFFFF { // zip64: the sizes are in the extra field
			var ok bool
			if usize, csize, ok = zip64Sizes(buf[nameLen:], usize, csize); !ok {
				return archiveFail("entry %s has no readable sizes", quoteVal(name))
			}
		}
		if method == zip.Store && csize != usize {
			return archiveFail("entry %s has two sizes", quoteVal(name))
		}
		data := io.LimitReader(br, int64(csize))
		e := archiveEntry{Name: name, CVE: recordCVE(name), Size: usize}
		if e.CVE != "" {
			body := func() ([]byte, error) {
				if usize > RecordMaxBytes {
					return nil, fail(ErrTooLarge, "The CVE record is larger than %d MB.", RecordMaxBytes>>20)
				}
				var src io.Reader = data
				if method == zip.Deflate {
					fr := flate.NewReader(data)
					defer func() { _ = fr.Close() }()
					src = fr
				}
				b, err := io.ReadAll(io.LimitReader(src, int64(usize)+1))
				if err != nil || uint64(len(b)) != usize || crc32.ChecksumIEEE(b) != crc {
					return nil, archiveFail("entry %s is damaged", quoteVal(name))
				}
				return b, nil
			}
			if err := fn(e, body); err != nil {
				return err
			}
		}
		if _, err := io.Copy(io.Discard, data); err != nil { // what fn did not read (or the deflate stream's tail)
			return archiveFail("entry %s is cut", quoteVal(name))
		}
		if rest, ok := data.(*io.LimitedReader); ok && rest.N != 0 {
			return archiveFail("entry %s is cut", quoteVal(name))
		}
	}
}

// zip64Sizes reads the sizes of a zip64 extra field (header 0x0001): the uncompressed size first, then the compressed one, each present
// only when the header's own field is 0xFFFFFFFF.
func zip64Sizes(extra []byte, usize, csize uint64) (u, c uint64, ok bool) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra[:2])
		size := int(binary.LittleEndian.Uint16(extra[2:4]))
		if len(extra) < 4+size {
			return 0, 0, false
		}
		field := extra[4 : 4+size]
		extra = extra[4+size:]
		if id != 0x0001 {
			continue
		}
		if usize == 0xFFFFFFFF {
			if len(field) < 8 {
				return 0, 0, false
			}
			usize, field = binary.LittleEndian.Uint64(field[:8]), field[8:]
		}
		if csize == 0xFFFFFFFF {
			if len(field) < 8 {
				return 0, 0, false
			}
			csize = binary.LittleEndian.Uint64(field[:8])
		}
		return usize, csize, true
	}
	return 0, 0, false
}
