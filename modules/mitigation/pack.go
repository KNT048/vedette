package mitigation

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
)

// Limits of untrusted pack content (the update is signed, but a parser still fails closed).
const (
	maxDocBytes = 256 << 10
	maxDocs     = 10_000
	maxTextLen  = 20_000
)

// Update is the mitigation content of one signed update: pack documents (JSON) and the signature
// material core/updates holds. The Verifier decides what the signature covers.
type Update struct {
	Version   string // the update's version, kept as pack_version
	Docs      []Doc
	Signature []byte
}

// Doc is one pack file.
type Doc struct {
	Name string
	Data []byte
}

// Rejection says why one document was not loaded.
type Rejection struct {
	Name   string
	Reason string
}

// InstallResult is what Install did.
type InstallResult struct {
	Loaded   int
	Rejected []Rejection
}

// ErrNoVerifier means no signature verifier is configured, so every update is refused (fail closed, FORBID-3).
var ErrNoVerifier = errors.New("no update signature verifier configured")

// ErrUnsigned means the update's signature is not valid.
var ErrUnsigned = errors.New("update signature is not valid")

// ErrNoValidPack means the update holds no valid pack (no documents, or every one was rejected). It is
// refused rather than wiping the packs that are loaded.
var ErrNoValidPack = errors.New("update has no valid pack")

// ErrReplay means the update is not newer than the installed one, or its version cannot be ordered.
var ErrReplay = errors.New("update version is not newer than the installed one")

// packDoc is the pack file format: the pack of contract.ts plus status and the optional recheck and
// compromise blocks. Unknown fields are refused.
type packDoc struct {
	Status      string                    `json:"status"`
	CVE         string                    `json:"cve"`
	ConfirmedBy string                    `json:"confirmed_by"`
	ConfirmedAt time.Time                 `json:"confirmed_at"`
	DraftedWith string                    `json:"drafted_with"`
	Sources     []findings.Source         `json:"sources"`
	Patch       findings.Patch            `json:"patch"`
	Workaround  findings.Workaround       `json:"workaround"`
	Firewall    []findings.FirewallGuide  `json:"firewall"`
	Checklist   []string                  `json:"checklist"`
	Recheck     *findings.Recheck         `json:"recheck"`
	Compromise  *findings.CompromiseCheck `json:"compromise"`
}

// packBody is what mit_pack.body holds: the pack without its identity and compromise columns.
type packBody struct {
	Sources    []findings.Source        `json:"sources"`
	Patch      findings.Patch           `json:"patch"`
	Workaround findings.Workaround      `json:"workaround"`
	Firewall   []findings.FirewallGuide `json:"firewall"`
	Checklist  []string                 `json:"checklist"`
	Recheck    *findings.Recheck        `json:"recheck,omitempty"`
}

// Loader loads confirmed packs from signed updates into mit_pack (INV-2).
type Loader struct {
	db       *store.DB
	audit    *audit.Log
	verifier Verifier
	log      *slog.Logger
	now      func() time.Time
}

// NewLoader returns the loader. A nil verifier is allowed and refuses everything.
func NewLoader(db *store.DB, a *audit.Log, v Verifier, log *slog.Logger, clock func() time.Time) *Loader {
	if clock == nil {
		clock = time.Now
	}
	return &Loader{db: db, audit: a, verifier: v, log: log, now: clock}
}

// Install replaces the loaded packs with the valid ones of the update, in one transaction.
// An update with no valid pack (ErrNoValidPack) and one whose version is not newer than the installed
// one (ErrReplay) are refused and change nothing; a refused update does not use up its version.
//
// The signature is checked first: without a verifier, or when it fails, nothing is read and nothing
// changes. Then each document is held to INV-2: status confirmed, confirmed_by, confirmed_at,
// drafted_with and sources present. A document that fails is rejected on its own (listed in the result)
// and does not stop the others. A pack missing from the new update is withdrawn.
func (l *Loader) Install(ctx context.Context, u Update) (InstallResult, error) {
	if l.verifier == nil {
		return InstallResult{}, fmt.Errorf("mitigation: installing packs: %w", ErrNoVerifier)
	}
	if err := l.verifier.Verify(ctx, u); err != nil {
		return InstallResult{}, fmt.Errorf("mitigation: installing packs: %w: %w", ErrUnsigned, err)
	}
	if n := utf8.RuneCountInString(u.Version); n < 1 || n > 64 || strings.ContainsRune(u.Version, 0) {
		return InstallResult{}, fmt.Errorf("mitigation: installing packs: update version must be 1 to 64 characters")
	}
	if _, ok := findings.CompareVersions(u.Version, u.Version); !ok {
		return InstallResult{}, fmt.Errorf("mitigation: installing packs: update version %q cannot be ordered: %w", u.Version, ErrReplay)
	}
	if len(u.Docs) > maxDocs {
		return InstallResult{}, fmt.Errorf("mitigation: installing packs: more than %d documents", maxDocs)
	}
	var res InstallResult
	seen := map[string]bool{}
	var packs []packDoc
	for _, d := range u.Docs {
		p, err := parsePack(d.Data)
		if err == nil && seen[p.CVE] {
			err = fmt.Errorf("a pack for %s is already in this update", p.CVE)
		}
		if err != nil {
			res.Rejected = append(res.Rejected, Rejection{Name: d.Name, Reason: err.Error()})
			continue
		}
		seen[p.CVE] = true
		packs = append(packs, p)
	}
	if len(packs) == 0 {
		// Nothing valid to load: an update that would only wipe the packs is refused, with the reasons.
		return res, fmt.Errorf("mitigation: installing packs: %w", ErrNoValidPack)
	}
	err := l.db.Write(ctx, func(tx *sql.Tx) error {
		if err := l.checkVersion(ctx, tx, u.Version); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM mit_pack`); err != nil {
			return fmt.Errorf("mitigation: clearing packs: %w", err)
		}
		for _, p := range packs {
			body, err := json.Marshal(packBody{Sources: p.Sources, Patch: p.Patch, Workaround: p.Workaround, Firewall: p.Firewall, Checklist: p.Checklist, Recheck: p.Recheck})
			if err != nil {
				return fmt.Errorf("mitigation: encoding pack %s: %w", p.CVE, err)
			}
			var comp any
			if p.Compromise != nil {
				b, err := json.Marshal(p.Compromise)
				if err != nil {
					return fmt.Errorf("mitigation: encoding pack %s: %w", p.CVE, err)
				}
				comp = string(b)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO mit_pack (cve, body, compromise, confirmed_by, confirmed_at, drafted_with, pack_version) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				p.CVE, string(body), comp, p.ConfirmedBy, store.FormatTS(p.ConfirmedAt), p.DraftedWith, u.Version); err != nil {
				return fmt.Errorf("mitigation: storing pack %s: %w", p.CVE, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mit_pack_state (id, version, installed_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET version = excluded.version, installed_at = excluded.installed_at`,
			u.Version, store.FormatTS(l.now())); err != nil {
			return fmt.Errorf("mitigation: recording the update version: %w", err)
		}
		return l.audit.Append(ctx, tx, audit.Entry{User: findings.SystemUser, Action: "mitigation.packs_loaded", Target: u.Version,
			Detail: fmt.Sprintf("%d packs loaded, %d rejected", len(packs), len(res.Rejected))})
	})
	if err != nil {
		return InstallResult{}, err
	}
	res.Loaded = len(packs)
	for _, r := range res.Rejected {
		l.log.WarnContext(ctx, "pack rejected", "doc", r.Name, "reason", r.Reason)
	}
	return res, nil
}

// CheckPack reports whether the box would load this pack document (the release tool runs it before signing, D-345).
func CheckPack(data []byte) error {
	_, err := parsePack(data)
	return err
}

// parsePack reads and validates one pack document. It is fail-closed: unknown fields, trailing data,
// oversize input and any missing proof of confirmation are errors.
func parsePack(data []byte) (packDoc, error) {
	var p packDoc
	if len(data) > maxDocBytes {
		return p, fmt.Errorf("document is larger than %d bytes", maxDocBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return packDoc{}, fmt.Errorf("not a valid pack document: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return packDoc{}, errors.New("not a valid pack document: data after the pack")
	}
	if err := p.validate(); err != nil {
		return packDoc{}, err
	}
	return p, nil
}

func (p *packDoc) validate() error {
	if p.Status != "confirmed" {
		return fmt.Errorf("status is %q, only confirmed packs are loaded", p.Status)
	}
	if !findings.ValidCVE(p.CVE) {
		return errors.New("cve is not a CVE id")
	}
	if err := text("confirmed_by", p.ConfirmedBy, 320); err != nil {
		return err
	}
	if p.ConfirmedAt.IsZero() {
		return errors.New("confirmed_at is missing")
	}
	if err := text("drafted_with", p.DraftedWith, 200); err != nil {
		return err
	}
	if len(p.Sources) == 0 {
		return errors.New("sources is empty")
	}
	for _, s := range p.Sources {
		if err := text("source title", s.Title, 300); err != nil {
			return err
		}
		if !httpURL(s.URL) {
			return fmt.Errorf("source %q has no http(s) url", s.Title)
		}
	}
	if err := text("patch summary", p.Patch.Summary, maxTextLen); err != nil {
		return err
	}
	if err := text("workaround summary", p.Workaround.Summary, maxTextLen); err != nil {
		return err
	}
	if p.Patch.URL != "" && !httpURL(p.Patch.URL) {
		return errors.New("patch url is not an http(s) url")
	}
	vendors := map[string]bool{}
	for i := range p.Firewall {
		f := &p.Firewall[i]
		switch f.Vendor {
		case "fortigate", "mikrotik", "generic":
		default:
			return fmt.Errorf("firewall vendor %q is not supported", f.Vendor)
		}
		if vendors[f.Vendor] {
			return fmt.Errorf("firewall vendor %q appears twice", f.Vendor)
		}
		vendors[f.Vendor] = true
		f.Detected = false // the inventory decides, never the file
	}
	if p.Compromise != nil {
		for _, in := range p.Compromise.Indicators {
			switch in.Kind {
			case "file", "web", "log", "process":
			default:
				return fmt.Errorf("indicator kind %q is not supported", in.Kind)
			}
		}
	}
	return nil
}

func text(field, s string, maxLen int) error {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return fmt.Errorf("%s is missing", field)
	case !utf8.ValidString(s) || strings.ContainsRune(s, 0):
		return fmt.Errorf("%s is not valid text", field)
	case utf8.RuneCountInString(s) > maxLen:
		return fmt.Errorf("%s is longer than %d characters", field, maxLen)
	}
	return nil
}

func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// checkVersion refuses an update whose version is not newer than the installed one. An installed
// version that cannot be compared refuses everything (fail closed) instead of letting a replay through.
func (l *Loader) checkVersion(ctx context.Context, tx *sql.Tx, version string) error {
	var last string
	err := tx.QueryRowContext(ctx, `SELECT version FROM mit_pack_state WHERE id = 1`).Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("mitigation: reading the installed version: %w", err)
	}
	if order, ok := findings.CompareVersions(version, last); !ok || order <= 0 {
		return fmt.Errorf("mitigation: installing packs: version %q is not newer than %q: %w", version, last, ErrReplay)
	}
	return nil
}
