package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Untrusted text (INV-21). Vedette sits on the customer's network, so much of what a job reads is written by whoever can name a device,
// send a log line, touch a trap or publish a web page. Every such text reaches a prompt the same way, and only this way:
//
//   - Untrusted builds the one kind of value that may carry it (DataBlock), labelled by where it came from (a closed list of sources),
//     with invisible and control characters removed and its size capped, before any hook reads it;
//   - Build puts each block between per-call markers the model is told are data (PromptBuilder.Build), tool results the same
//     (WrapToolResult);
//   - the instructions of a call (JobSpec.Task, JobSpec.Question) are of type Instruction, which a string variable cannot be assigned
//     to: they are constants, or built by instructionf from values the box validated (a CVE id, a count, a word of its own). The
//     guard test TestUntrustedTextNeverBecomesAnInstruction fails on any other conversion to Instruction and on any DataBlock literal
//     outside this file.
//
// What a model answers is decoded strictly (decodeAnswer) and what it may do is fixed per job (jobPowers).

// Source says where untrusted text came from. The list is closed: a block of any other source is refused by Build.
type Source string

// The sources of untrusted text.
const (
	SourceFeed     Source = "feed"     // CVE records, exploited-list entries, CVE briefs: written by CNAs, vendors and feeds
	SourceWeb      Source = "web"      // web pages the box fetched itself: vendor advisories, references, NVD, GitHub, security blogs
	SourceDevice   Source = "device"   // what devices say about themselves: names (DHCP, mDNS, hostnames), vendor, model, OS, banners, ports
	SourceSoftware Source = "software" // installed programs as agents and scans list them: publisher, name, version
	SourceLog      Source = "log"      // kinds of log line and their counts (syslog, firewall logs): never a log line itself
	SourceDocument Source = "document" // documents an administrator added to the knowledge base, and text the box lists for a job
	SourceMemory   Source = "memory"   // notes an administrator keeps for the AI (INV-8)
	SourceTool     Source = "tool"     // the result of a tool the model called
	SourceCustomer Source = "customer" // what a person typed into the box (the organisation's sector, the actions of a catalog)
	SourceBox      Source = "box"      // the box's own records, which may quote any of the above (a host it could not read)
)

// Sources lists every source, in the order the attack test walks them.
func Sources() []Source {
	return []Source{SourceFeed, SourceWeb, SourceDevice, SourceSoftware, SourceLog, SourceDocument, SourceMemory, SourceTool, SourceCustomer, SourceBox}
}

func (s Source) valid() bool {
	for _, k := range Sources() {
		if s == k {
			return true
		}
	}
	return false
}

// maxBlockBytes caps one block: the largest a job sends is a knowledge passage set or a page of a reference (a few KiB each).
const maxBlockBytes = 128 << 10

// Untrusted is the only way to carry untrusted text into a prompt: the text, cleaned (normalizeUntrusted) and capped, labelled with its
// source and a short description of what it is. An unknown source is kept as given and refused by Build, never sent.
func Untrusted(src Source, label, text string) DataBlock {
	return DataBlock{Kind: src, Source: label, Text: normalizeUntrusted(text)}
}

// publicUntrusted is Untrusted for public text the box fetched itself for a call of public text only (DataBlock.public).
func publicUntrusted(src Source, label, text string) DataBlock {
	b := Untrusted(src, label, text)
	b.public = true
	return b
}

// normalizeUntrusted is the form in which untrusted text is checked by the hooks and sent: valid UTF-8; line breaks (CR LF, CR, U+2028,
// U+2029) as "\n"; tabs kept; every other control character and every invisible format character removed (bidi overrides and
// isolates, zero-width spaces and joiners, Unicode tag characters, variation selectors), so what a person and a pattern read is what the
// model reads; cut to maxBlockBytes on a character boundary.
func normalizeUntrusted(s string) string { return clipBytes(cleanUntrusted(s), maxBlockBytes) }

// cleanUntrusted is normalizeUntrusted without the cap, for text whose size a later check judges (a tool result over the hooks' limit
// is refused, not cut).
func cleanUntrusted(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == '\r' || r == ' ' || r == ' ' || r == '\u0085':
			b.WriteByte('\n')
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || invisible(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Instruction is text the box itself writes as the instructions of a call: a job's task or the question it asks. Constants convert to it
// implicitly; anything else needs instructionf (values the box validated) or personQuestion (what a signed-in person typed).
type Instruction string

// safeArg is a value the box validated that may go into an Instruction.
type safeArg interface{ instructionText() string }

// cveArg is a CVE id that matched cveRE.
type cveArg string

func (c cveArg) instructionText() string { return string(c) }

// asCVE validates a CVE id for an instruction: upper case, CVE-YYYY-NNNN+.
func asCVE(s string) (cveArg, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !cveRE.MatchString(s) {
		return "", false
	}
	return cveArg(s), true
}

// mustCVE is asCVE for an id the caller has validated already; one that does not match becomes "CVE-0000-0000", never the text.
func mustCVE(s string) cveArg {
	if c, ok := asCVE(s); ok {
		return c
	}
	return "CVE-0000-0000"
}

// countArg is a number the box counted.
type countArg int

func (n countArg) instructionText() string { return strconv.Itoa(int(n)) }

// boxWord is one of the box's own words for a decision (the affected status it decided). Only the words listed here exist.
type boxWord string

const (
	wordYes     boxWord = "yes"
	wordNo      boxWord = "no"
	wordUnknown boxWord = "unknown"
)

func (w boxWord) instructionText() string {
	switch w {
	case wordYes, wordNo, wordUnknown:
		return string(w)
	}
	return string(wordUnknown)
}

// instructionf fills the %s verbs of a constant format with validated values only.
func instructionf(format Instruction, args ...safeArg) Instruction {
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a.instructionText()
	}
	return Instruction(fmt.Sprintf(string(format), vals...)) //nolint:govet // the format is an Instruction constant
}

// blockPtr returns a pointer to a copy of b (a source whose block may be left out).
func blockPtr(b DataBlock) *DataBlock { return &b }

// personQuestion is what a signed-in person typed as their own question (Ask): the one instruction a person writes. The caller has
// cleaned it and run it through the hooks.
func personQuestion(q string) Instruction { return Instruction(q) }

// maskedInstruction is an instruction as the before-AI hooks gave it back (masked where they mask): the same text, less.
func maskedInstruction(q string) Instruction { return Instruction(q) }

// decodeAnswer reads a model's structured answer strictly: exactly one JSON object, no field the type does not name (a field a page
// talked the model into adding is refused, never ignored), nothing after it; then check validates the values (closed enums, length caps,
// indexes in range). Any failure is ErrBadOutput: the answer is discarded, never repaired.
func decodeAnswer[T any](text string, check func(*T) error) (T, error) {
	var v T
	dec := json.NewDecoder(bytes.NewReader([]byte(strings.TrimSpace(text))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("%w: %s", ErrBadOutput, clipRunes(err.Error(), 200))
	}
	if dec.More() {
		return v, fmt.Errorf("%w: text after the answer", ErrBadOutput)
	}
	if check != nil {
		if err := check(&v); err != nil {
			return v, fmt.Errorf("%w: %s", ErrBadOutput, clipRunes(err.Error(), 200))
		}
	}
	return v, nil
}

// capRunes is the length check of one answer field: at most n characters.
func capRunes(field, v string, n int) error {
	if utf8.RuneCountInString(v) > n {
		return fmt.Errorf("%s is longer than %d characters", field, n)
	}
	return nil
}

// oneOf is the enum check of one answer field.
func oneOf(field, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%s %q is not one of the allowed values", field, clipRunes(v, 40))
}

var (
	mdImage = regexp.MustCompile(`!\[[^\]\n]*\]\([^)\n]*\)`)
	mdLink  = regexp.MustCompile(`\[([^\]\n]*)\]\([^)\n]*\)`)
	mdRef   = regexp.MustCompile(`(?m)^\s*\[[^\]\n]+\]:\s*\S+.*$`)
)

// plainText is free text of a model as the box keeps it: no markdown image (shown anywhere that renders markdown, it would be fetched
// with data in its address), a markdown link reduced to its words, and no web address. The links of an answer are always the box's
// own (its citations).
func plainText(s string) string {
	s = mdImage.ReplaceAllString(s, "")
	s = mdRef.ReplaceAllString(s, "")
	s = mdLink.ReplaceAllString(s, "$1")
	return withoutAddresses(s)
}
