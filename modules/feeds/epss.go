package feeds

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Limits for the EPSS bulk file. It is about 3 MB gzipped and 10+ MB as text,
// and has ~260k rows, so INV-2's 50,000-row cap does not fit; these are the
// zip-bomb and memory guards instead.
const (
	MaxEPSSDecompressed = 64 << 20
	MaxEPSSRows         = 1_000_000
	maxEPSSLine         = 64 << 10
)

// EPSSScore is one row of the FIRST EPSS file.
type EPSSScore struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// EPSSData is a parsed EPSS file. Scores holds only the rows `keep` selected;
// Accepted counts every valid row.
type EPSSData struct {
	ModelVersion string // from the "#model_version:..." comment, "" when odd
	ScoreDate    string // YYYY-MM-DD from "score_date:...", "" when odd
	Scores       []EPSSScore
	Stats
}

// capReader fails with ErrTooLarge once more than max bytes were read, so a
// decompression bomb or an endless body stops at a hard ceiling.
type capReader struct {
	r    io.Reader
	left int64
}

func newCapReader(r io.Reader, limit int64) *capReader { return &capReader{r: r, left: limit} }

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, ErrTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return 0, ErrTooLarge
	}
	return n, err
}

var (
	epssCVE   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	epssNum   = regexp.MustCompile(`^[0-9]*\.?[0-9]+([eE][+-]?[0-9]+)?$`)
	modelRE   = regexp.MustCompile(`^[0-9A-Za-z._-]{1,40}$`)
	epssWords = "cve,epss,percentile"
)

func unitFloat(s string) (float64, bool) {
	if !epssNum.MatchString(s) {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || f > 1 {
		return 0, false
	}
	return f, true
}

// ParseEPSS reads the FIRST EPSS CSV, gzip-compressed (as published) or plain.
// The decompressed size is capped at MaxEPSSDecompressed (ErrTooLarge). The
// "#model_version" comment line is read for metadata; the header must be
// "cve,epss,percentile". Bad rows are rejected and counted. Any stream error
// (truncated gzip, bad checksum, a line over 64 KB) fails the whole parse so
// the caller keeps its previous scores. keep may be nil to keep every row.
func ParseEPSS(data []byte, keep func(cve string) bool) (EPSSData, error) {
	if len(data) > MaxBodyBytes {
		return EPSSData{}, fail(ErrTooLarge, "The EPSS file is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	var src io.Reader = bytes.NewReader(data)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(src)
		if err != nil {
			return EPSSData{}, fail(ErrBadSample, "The EPSS file is not valid gzip.")
		}
		defer func() { _ = gz.Close() }()
		src = gz
	}
	sc := bufio.NewScanner(newCapReader(src, MaxEPSSDecompressed))
	sc.Buffer(make([]byte, 0, 4096), maxEPSSLine)
	out := EPSSData{Scores: []EPSSScore{}}
	tl := newTally()
	headerSeen := false
	row := 0
	for sc.Scan() {
		line := jsTrim(strings.ToValidUTF8(sc.Text(), "�"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if !headerSeen {
				epssMeta(line, &out)
			}
			continue
		}
		if !headerSeen {
			if !strings.EqualFold(line, epssWords) {
				return EPSSData{}, fail(ErrBadSample, "This is not an EPSS file: the header must be %s.", epssWords)
			}
			headerSeen = true
			continue
		}
		if row == MaxEPSSRows {
			tl.Truncated = true
			break
		}
		row++
		cols := strings.Split(line, ",")
		if len(cols) != 3 {
			tl.reject(row, "row: expected 3 columns")
			continue
		}
		cve := strings.ToUpper(cols[0])
		score, ok1 := unitFloat(cols[1])
		pct, ok2 := unitFloat(cols[2])
		switch {
		case !epssCVE.MatchString(cve):
			tl.reject(row, `cve: "`+jsSlice(cols[0], 30)+`" is not a CVE ID`)
		case !ok1:
			tl.reject(row, `epss: "`+jsSlice(cols[1], 20)+`" is not a number from 0 to 1`)
		case !ok2:
			tl.reject(row, `percentile: "`+jsSlice(cols[2], 20)+`" is not a number from 0 to 1`)
		default:
			tl.Accepted++
			if keep == nil || keep(cve) {
				out.Scores = append(out.Scores, EPSSScore{cve, score, pct})
			}
		}
	}
	if err := sc.Err(); err != nil {
		switch {
		case errors.Is(err, ErrTooLarge):
			return EPSSData{}, fail(ErrTooLarge, "The EPSS file expands to more than %d MB; Vedette would skip it.", MaxEPSSDecompressed>>20)
		case errors.Is(err, bufio.ErrTooLong):
			return EPSSData{}, fail(ErrBadSample, "The EPSS file has a line that is far too long.")
		}
		return EPSSData{}, fail(ErrBadSample, "The EPSS file is damaged or cut off.")
	}
	if !headerSeen {
		return EPSSData{}, fail(ErrBadSample, "This is not an EPSS file: the header is missing.")
	}
	out.Stats = tl.stats()
	return out, nil
}

// epssMeta reads "#model_version:v2025.03.14,score_date:2025-03-14T12:55:00Z".
func epssMeta(line string, out *EPSSData) {
	for _, part := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model_version":
			if v = strings.TrimSpace(v); modelRE.MatchString(v) {
				out.ModelVersion = v
			}
		case "score_date":
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
				out.ScoreDate = t.UTC().Format("2006-01-02")
			}
		}
	}
}
