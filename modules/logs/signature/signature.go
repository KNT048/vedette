// Package signature turns a received log line into the short, stable text that the digest counts ("signature") and,
// where the device's format is known, the address it was aimed at. A device kind with a profile (a JSON file in
// modules/logs/data/profiles) is read with the rule of that file; every other kind, and every line a profile does not
// recognise, is mined by the generic template miner (Mine). It has no database and no network, like modules/logs/listen, so
// it can move to the sensor unchanged.
//
// Lines are untrusted (INV-1, SYS-6). Of is total and bounded whatever it is given: the result is valid UTF-8 without control
// characters, a signature is at most MaxSignatureBytes bytes, an address at most MaxDestBytes. Profiles are data and are
// untrusted too: Load refuses unknown fields, oversized files and rules whose own samples do not give the answer they claim,
// and a bad profile is an error at load, never a rule that half works.
package signature

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/modules/logs/listen"
)

// Limits (ponytail: starting points, one constant each).
const (
	MaxSignatureBytes = 240
	MaxDestBytes      = 64
	MaxProfileBytes   = 64 << 10 // one profile file
	MaxProfiles       = 32
	MaxFields         = 12
	MaxPatterns       = 8
	MaxPatternBytes   = 256
	MaxTitles         = 256
	MaxVocab          = 512
	MaxSamples        = 8
	// GenericProfile is the Result.Profile of a line read by the template miner.
	GenericProfile = "generic"

	maxScan  = 4096 // bytes of a line that a rule looks at (lines are stored at 2 KiB; this is the bound for a caller that passes more)
	maxValue = 48   // bytes of a plain key=value value in a signature
	maxPairs = 256  // key=value pairs looked at in one line
)

// Rule types.
const (
	TypeKV       = "kv"       // key=value pairs: the signature is the chosen keys, in order
	TypeEventID  = "event_id" // an event number found by a pattern, named by a table (Windows Security)
	TypeTemplate = "template" // a leading tag (such as RouterOS topics) and the mined message
)

// File is one profile as it is written in a JSON file.
type File struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Kinds   []string `json:"kinds"`
	Rule    Rule     `json:"rule"`
	Samples []Sample `json:"samples"`
}

// Rule is the signature rule of a profile. Which fields apply depends on Type; the others must be empty.
type Rule struct {
	Type string `json:"type"`
	// kv
	Fields []string `json:"fields,omitempty"` // keys that make the signature, in order; the line matches when the first is present
	Mined  []string `json:"mined,omitempty"`  // keys (among Fields) whose value is mined instead of kept as it is
	// Vocab lists, for a key of Fields, the only values the signature takes: a value that is not listed is left out of the signature (for
	// the first field, which decides whether the line is in the format, the line is not read by the profile). A rule whose every field
	// has a vocabulary and none is mined has a signature that shipped data bounds: Result.Bounded.
	Vocab map[string][]string `json:"vocab,omitempty"`
	// Shapes gives, for the first field, an RE2 pattern for a value that is not in Vocab but is well formed (a ten-digit FortiGate log id):
	// the line is still read by the profile, the signature keeps that value, and it is not Bounded (it counts in the quota of the miner).
	Shapes   map[string]string `json:"shapes,omitempty"`
	SrcField string            `json:"src_field,omitempty"` // key that holds the source address
	DstField string            `json:"dst_field,omitempty"` // key that holds the destination address
	// RemoteFields are the keys that hold the address of the remote peer the line is about (the client of a login, the source of a
	// blocked connection), in order of preference: the first that holds a countable address wins (D-210). Not the sender of the log.
	RemoteFields []string `json:"remote_fields,omitempty"`
	// event_id
	Patterns []string          `json:"patterns,omitempty"` // each with a named group "id"; tried in order
	Titles   map[string]string `json:"titles,omitempty"`   // id -> what the event is: the vocabulary, an id that is not here is not read
	// template
	Prefix    string   `json:"prefix,omitempty"`     // matches at the start, with a named group "head"
	HeadVocab []string `json:"head_vocab,omitempty"` // the words the head (split at commas) is made of; a head with another word is not read
	// template and event_id
	SrcPattern string `json:"src_pattern,omitempty"` // named group "src"
	DstPattern string `json:"dst_pattern,omitempty"` // named group "dst"
	// RemotePatterns (any type) find the remote peer's address by a pattern with a named group "addr"; tried in order after RemoteFields.
	// A line the profile does not settle goes to the generic reader (ParseAddr over the usual daemon layouts).
	RemotePatterns []string `json:"remote_patterns,omitempty"`
}

// Sample is a documented line and what the rule must make of it; Load runs every sample.
type Sample struct {
	Line      string `json:"line"`
	Signature string `json:"signature"`
	Src       string `json:"src,omitempty"`
	Dest      string `json:"dest,omitempty"`
	Remote    string `json:"remote,omitempty"` // the remote peer's address the rule must find (empty: none)
}

type profile struct {
	File
	patterns  []*regexp.Regexp
	prefix    *regexp.Regexp
	src, dst  *regexp.Regexp
	remote    []*regexp.Regexp
	mined     map[string]bool
	wanted    map[string]bool
	vocab     map[string]map[string]bool
	shape     *regexp.Regexp // of the first field
	headVocab map[string]bool
	bounded   bool
}

// Set is the loaded profiles, by device kind.
type Set struct {
	profiles []*profile
	byKind   map[string]*profile
}

// Result is what Of makes of a line.
type Result struct {
	Signature string // never empty
	Src, Dest string // a plain address or name, or empty
	// Remote is the address of the remote peer the line is about (D-210): never the device that sent the log. Unmapped, no zone,
	// Countable; the zero Addr when the line has none or the text is not an address.
	Remote  netip.Addr
	Profile string // the profile id, or GenericProfile
	// Bounded says that the signature comes from a vocabulary that shipped data bounds (a known log id, a known event id): the number
	// of signatures a device can make is small whatever it sends. Every other result (the miner, a profile whose text is free) is
	// counted in the quota of the miner.
	Bounded bool
}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Load reads every *.json file of dir in fsys. It is an error when there is none, when more than MaxProfiles, or when any file
// is bigger than MaxProfileBytes, has a field the schema does not know, breaks a limit, repeats an id or a kind of another file,
// or has a sample that the rule does not turn into the signature the sample says.
func Load(fsys fs.FS, dir string) (*Set, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("signature: reading profiles: %w", err)
	}
	set := &Set{byKind: map[string]*profile{}}
	ids := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if len(set.profiles) >= MaxProfiles {
			return nil, fmt.Errorf("signature: more than %d profiles", MaxProfiles)
		}
		p, err := loadOne(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("signature: profile %s: %w", e.Name(), err)
		}
		if other, dup := ids[p.ID]; dup {
			return nil, fmt.Errorf("signature: profile %s has the id %q of %s", e.Name(), p.ID, other)
		}
		ids[p.ID] = e.Name()
		for _, k := range p.Kinds {
			if other, dup := set.byKind[k]; dup {
				return nil, fmt.Errorf("signature: profile %s: kind %q already has the profile %s", e.Name(), k, other.ID)
			}
			set.byKind[k] = p
		}
		set.profiles = append(set.profiles, p)
	}
	if len(set.profiles) == 0 {
		return nil, errors.New("signature: no profile found")
	}
	// The samples run against the whole set: a kind that is not its own would be read by the generic miner.
	for _, p := range set.profiles {
		for i, s := range p.Samples {
			r := set.Of(p.Kinds[0], s.Line)
			remote := ""
			if r.Remote.IsValid() {
				remote = r.Remote.String()
			}
			if r.Profile != p.ID || r.Signature != s.Signature || r.Src != s.Src || r.Dest != s.Dest || remote != s.Remote {
				return nil, fmt.Errorf("signature: profile %s sample %d: the rule gives profile %q signature %q src %q dest %q remote %q, the sample says signature %q src %q dest %q remote %q",
					p.ID, i+1, r.Profile, r.Signature, r.Src, r.Dest, remote, s.Signature, s.Src, s.Dest, s.Remote)
			}
		}
	}
	return set, nil
}

func loadOne(fsys fs.FS, name string) (*profile, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxProfileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxProfileBytes {
		return nil, fmt.Errorf("larger than %d bytes", MaxProfileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var file File
	if err := dec.Decode(&file); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the profile")
	}
	return compile(file)
}

func compile(f File) (*profile, error) {
	if !idRE.MatchString(f.ID) {
		return nil, fmt.Errorf("id %q is not a lower-case name", f.ID)
	}
	if len(f.Title) == 0 || len(f.Title) > 120 {
		return nil, errors.New("title must be 1 to 120 bytes")
	}
	if len(f.Kinds) == 0 || len(f.Kinds) > 8 {
		return nil, errors.New("kinds must list 1 to 8 device kinds")
	}
	for _, k := range f.Kinds {
		if !idRE.MatchString(k) {
			return nil, fmt.Errorf("kind %q is not a lower-case name", k)
		}
	}
	if len(f.Samples) == 0 || len(f.Samples) > MaxSamples {
		return nil, fmt.Errorf("a profile needs 1 to %d samples: a rule that is not shown to work is not shipped", MaxSamples)
	}
	for _, s := range f.Samples {
		if len(s.Line) == 0 || len(s.Line) > 2048 || s.Signature == "" || len(s.Signature) > MaxSignatureBytes {
			return nil, errors.New("a sample needs a line (at most 2048 bytes) and a signature")
		}
	}
	p := &profile{File: f, mined: map[string]bool{}, wanted: map[string]bool{}}
	r := f.Rule
	var err error
	switch r.Type {
	case TypeKV:
		if len(r.Fields) == 0 || len(r.Fields) > MaxFields {
			return nil, fmt.Errorf("a kv rule needs 1 to %d fields", MaxFields)
		}
		if len(r.Patterns)+len(r.Titles)+len(r.HeadVocab) != 0 || r.Prefix != "" || r.SrcPattern != "" || r.DstPattern != "" {
			return nil, errors.New("a kv rule takes only fields, mined, vocab, src_field, dst_field, remote_fields and remote_patterns")
		}
		for _, k := range r.Fields {
			if !validKey(k) {
				return nil, fmt.Errorf("field %q is not a key name", k)
			}
			p.wanted[k] = true
		}
		for _, k := range r.Mined {
			if !slices.Contains(r.Fields, k) {
				return nil, fmt.Errorf("mined field %q is not in fields", k)
			}
			p.mined[k] = true
		}
		p.vocab = map[string]map[string]bool{}
		for k, values := range r.Vocab {
			if !slices.Contains(r.Fields, k) || len(values) == 0 || len(values) > MaxVocab {
				return nil, fmt.Errorf("vocab of %q: a field of the rule and 1 to %d values", k, MaxVocab)
			}
			p.vocab[k] = map[string]bool{}
			for _, v := range values {
				if v == "" || len(v) > maxValue || clean(v) != v {
					return nil, fmt.Errorf("vocab of %q: %q is not a plain value", k, v)
				}
				p.vocab[k][v] = true
			}
		}
		for k, src := range r.Shapes {
			if k != r.Fields[0] || p.vocab[k] == nil {
				return nil, fmt.Errorf("shapes: only the first field, which has a vocab, can have one (%q)", k)
			}
			re, err := regexp.Compile(src)
			if err != nil || len(src) > MaxPatternBytes {
				return nil, fmt.Errorf("shape of %q: a pattern of at most %d bytes: %w", k, MaxPatternBytes, err)
			}
			p.shape = re
		}
		p.bounded = len(r.Mined) == 0
		for _, k := range r.Fields {
			p.bounded = p.bounded && p.vocab[k] != nil
		}
		if len(r.RemoteFields) > MaxFields {
			return nil, fmt.Errorf("remote_fields takes at most %d keys", MaxFields)
		}
		for _, k := range append([]string{r.SrcField, r.DstField}, r.RemoteFields...) {
			if k != "" {
				if !validKey(k) {
					return nil, fmt.Errorf("field %q is not a key name", k)
				}
				p.wanted[k] = true
			}
		}
	case TypeEventID:
		if len(r.Patterns) == 0 || len(r.Patterns) > MaxPatterns {
			return nil, fmt.Errorf("an event_id rule needs 1 to %d patterns", MaxPatterns)
		}
		if len(r.Fields)+len(r.Mined)+len(r.Vocab)+len(r.HeadVocab)+len(r.RemoteFields) != 0 || r.SrcField != "" || r.DstField != "" || r.Prefix != "" {
			return nil, errors.New("an event_id rule takes only patterns, titles, src_pattern, dst_pattern and remote_patterns")
		}
		if len(r.Titles) == 0 || len(r.Titles) > MaxTitles {
			return nil, fmt.Errorf("an event_id rule needs 1 to %d titles: they are its vocabulary", MaxTitles)
		}
		p.bounded = true
		for id, title := range r.Titles {
			if !validID(id) || title == "" || len(title) > 80 {
				return nil, fmt.Errorf("title of %q: an id is 1 to 6 digits and a title 1 to 80 bytes", id)
			}
		}
		for _, src := range r.Patterns {
			re, err := compileGroup(src, "id")
			if err != nil {
				return nil, err
			}
			p.patterns = append(p.patterns, re)
		}
	case TypeTemplate:
		if len(r.Fields)+len(r.Mined)+len(r.Patterns)+len(r.Titles)+len(r.Vocab)+len(r.RemoteFields) != 0 || r.SrcField != "" || r.DstField != "" {
			return nil, errors.New("a template rule takes only prefix, head_vocab, src_pattern, dst_pattern and remote_patterns")
		}
		if len(r.HeadVocab) > MaxVocab {
			return nil, fmt.Errorf("head_vocab has more than %d words", MaxVocab)
		}
		if len(r.HeadVocab) > 0 {
			p.headVocab = map[string]bool{}
			for _, v := range r.HeadVocab {
				if !validKey(v) {
					return nil, fmt.Errorf("head_vocab: %q is not a word", v)
				}
				p.headVocab[v] = true
			}
		}
		if p.prefix, err = compileGroup(r.Prefix, "head"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown rule type %q", r.Type)
	}
	if len(r.RemotePatterns) > MaxPatterns {
		return nil, fmt.Errorf("remote_patterns takes at most %d patterns", MaxPatterns)
	}
	for _, src := range r.RemotePatterns {
		re, err := compileGroup(src, "addr")
		if err != nil {
			return nil, err
		}
		p.remote = append(p.remote, re)
	}
	if r.SrcPattern != "" {
		if p.src, err = compileGroup(r.SrcPattern, "src"); err != nil {
			return nil, err
		}
	}
	if r.DstPattern != "" {
		if p.dst, err = compileGroup(r.DstPattern, "dst"); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func compileGroup(src, group string) (*regexp.Regexp, error) {
	if src == "" || len(src) > MaxPatternBytes {
		return nil, fmt.Errorf("a pattern is 1 to %d bytes", MaxPatternBytes)
	}
	re, err := regexp.Compile(src) // RE2: linear time, so a pattern cannot make a line expensive
	if err != nil {
		return nil, fmt.Errorf("pattern %q: %w", src, err)
	}
	if re.SubexpIndex(group) < 0 {
		return nil, fmt.Errorf("pattern %q has no named group %q", src, group)
	}
	return re, nil
}

func validKey(k string) bool {
	if k == "" || len(k) > 32 {
		return false
	}
	for i := 0; i < len(k); i++ {
		if !isAtomByte(k[i]) || k[i] == ':' {
			return false
		}
	}
	return true
}

func validID(s string) bool {
	if s == "" || len(s) > 6 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// HasProfile says whether a kind is read by a profile of its own (not by the generic miner).
func (s *Set) HasProfile(kind string) bool { return s.byKind[kind] != nil }

// Kinds lists the device kinds that have a profile, sorted.
func (s *Set) Kinds() []string {
	out := make([]string, 0, len(s.byKind))
	for k := range s.byKind {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Of returns the signature of a line from a device of the given kind. It never fails.
func (s *Set) Of(kind, line string) Result {
	line = strings.ToValidUTF8(clip(line, maxScan), "?")
	msg := listen.ParseSyslog(line).Msg
	if p := s.byKind[kind]; p != nil {
		if r, ok := p.read(msg); ok {
			if !r.Remote.IsValid() {
				r.Remote = genericRemote(msg) // the profile does not name it: the layouts that daemons share
			}
			return r
		}
	}
	return Result{Signature: Mine(msg), Profile: GenericProfile, Remote: genericRemote(msg)}
}

// read applies the rule; ok is false when the line is not in the format of the profile.
func (p *profile) read(msg string) (Result, bool) {
	var r Result
	switch p.Rule.Type {
	case TypeKV:
		kv := kvFind(msg, p.wanted)
		if _, has := kv[p.Rule.Fields[0]]; !has {
			return r, false
		}
		var parts []string
		bounded := p.bounded
		for i, k := range p.Rule.Fields {
			v, has := kv[k]
			if !has {
				continue
			}
			if voc := p.vocab[k]; voc != nil && !voc[v] {
				if i == 0 {
					if p.shape == nil || !p.shape.MatchString(v) {
						return r, false // the key of the format is not one the data knows: not this profile's line
					}
					bounded = false // well formed but unknown: read, kept, counted in the quota of the miner
				} else {
					continue
				}
			}
			if p.mined[k] {
				v = Mine(v)
			} else {
				v = clean(cut(v, maxValue))
			}
			parts = append(parts, k+"="+v)
		}
		r.Signature = strings.Join(parts, " ")
		r.Src, r.Dest = addr(kv[p.Rule.SrcField]), addr(kv[p.Rule.DstField])
		for _, k := range p.Rule.RemoteFields {
			if a, ok := ParseAddr(kv[k]); ok && Countable(a) {
				r.Remote = a
				break
			}
		}
		r.Bounded = bounded
	case TypeEventID:
		id, title := "", ""
		for _, re := range p.patterns {
			if m := re.FindStringSubmatch(msg); m != nil {
				if v := m[re.SubexpIndex("id")]; validID(v) {
					v = strings.TrimLeft(v, "0")
					if t, known := p.Rule.Titles[v]; known {
						id, title = v, t
						break
					}
				}
			}
		}
		if id == "" {
			return r, false // not an event id the table knows: the miner reads the line
		}
		r.Signature = id + ": " + title
		r.Bounded = true
	case TypeTemplate:
		m := p.prefix.FindStringSubmatchIndex(msg)
		if m == nil || m[0] != 0 {
			return r, false
		}
		i := p.prefix.SubexpIndex("head")
		if m[2*i] < 0 {
			return r, false
		}
		head := msg[m[2*i]:m[2*i+1]]
		if p.headVocab != nil {
			for _, w := range strings.Split(head, ",") {
				if !p.headVocab[w] {
					return r, false
				}
			}
		}
		r.Signature = clean(cut(head, 64)) + ": " + Mine(msg[m[1]:])
	}
	if p.src != nil {
		r.Src = group(p.src, msg, "src")
	}
	if p.dst != nil {
		r.Dest = group(p.dst, msg, "dst")
	}
	r.Signature = clean(cut(r.Signature, MaxSignatureBytes))
	if r.Signature == "" {
		return Result{}, false
	}
	for _, re := range p.remote {
		if r.Remote.IsValid() {
			break
		}
		if m := re.FindStringSubmatch(msg); m != nil {
			if a, ok := ParseAddr(m[re.SubexpIndex("addr")]); ok && Countable(a) {
				r.Remote = a
			}
		}
	}
	r.Profile = p.ID
	return r, true
}

func group(re *regexp.Regexp, msg, name string) string {
	if m := re.FindStringSubmatch(msg); m != nil {
		return addr(m[re.SubexpIndex(name)])
	}
	return ""
}

// addr returns v when it is a plain address or name (letters, digits and . : _ - up to MaxDestBytes), else "": what a device
// writes into an address field is not stored unless it can only be an address.
func addr(v string) string {
	if v == "" || len(v) > MaxDestBytes {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if !isAtomByte(v[i]) {
			return ""
		}
	}
	return v
}

// clean makes s valid UTF-8 without control characters and trims it.
func clean(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// kvFind reads key=value pairs ("key=value" and key="quoted value", the first of a key wins) and returns the wanted ones.
func kvFind(s string, want map[string]bool) map[string]string {
	out := map[string]string{}
	pairs := 0
	for i := 0; i < len(s) && pairs < maxPairs; {
		if s[i] == ' ' {
			i++
			continue
		}
		j := i
		for j < len(s) && isKeyByte(s[j]) {
			j++
		}
		if j == i || j >= len(s) || s[j] != '=' {
			for j < len(s) && s[j] != ' ' { // not a pair: skip the word
				j++
			}
			if j == i {
				j++
			}
			i = j
			continue
		}
		pairs++
		key := s[i:j]
		j++
		var val string
		if j < len(s) && s[j] == '"' {
			k := j + 1
			for k < len(s) && s[k] != '"' {
				if s[k] == '\\' {
					k++
				}
				k++
			}
			if k > len(s) {
				k = len(s)
			}
			val = s[j+1 : k]
			j = k + 1
		} else {
			k := j
			for k < len(s) && s[k] != ' ' {
				k++
			}
			val, j = s[j:k], k
		}
		if want[key] {
			if _, dup := out[key]; !dup {
				out[key] = val
			}
		}
		i = j
	}
	return out
}

func isKeyByte(c byte) bool { return isAtomByte(c) && c != ':' }
