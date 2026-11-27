package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
)

// The testing terms of a verified target: one acceptance per target, by an administrator with two-step sign-in, makes every scan of
// that target a deep scan (ScanMode.Full) and lets a scan a person starts run the disruptive checks too (ScanMode.Disruptive); the
// scans the box runs by itself on the schedule never do (boxMode). Without an acceptance a target keeps the basic scope of the Scan
// now sentence: passive web scan, read-only nuclei, no Greenbone. It can be withdrawn at any time; a new TermsVersion asks again,
// except that an acceptance of a version in keptTermsVersions stays valid with its own stored text and disruptive flag. The texts
// are the only copy: the API sends them with the target in it and the page shows what it got; the mock's copy (contract.ts
// TERMS_TEMPLATE, TERMS_TEMPLATE_DOMAIN) is held equal by a test, and each version's text is pinned.
const (
	TermsVersion = "2026-11-26"
	// termsTemplate is an IP target's text, termsTemplateDomain a domain's: the "yours alone"
	// sentence becomes what reaches every address a name under the domain resolves to and who answers for a provider's permission.
	// Both share the head and the tail, so the list of tools is the same. They say what the deep scan sends as the deep nmap and
	// nuclei steps and OpenVAS's deep config run it: checks that confirm a flaw by sending the exploit request in a harmless form,
	// OpenVAS checks that may write a harmless test file or record, known authentication bypasses and the public anonymous login;
	// then the disruptive checks as PRIVACY flow 9 lists them. TERMS.md says the same.
	// 2026-11-14d: revised texts (an acceptance of a 2026-11-14c text is asked again).
	// 2026-11-14e: the web line says what TERMS.md says, word for word (follows links, may submit forms), while
	// the active ZAP scan is not built; the domain's list names "the web scan (ZAP)".
	// 2026-11-18: the disclaimer names the Vedette authors instead of a person (an acceptance of an older text is asked again).
	// 2026-11-18b: the box also scans the target on its schedule, never with the disruptive checks, until the schedule is off (INV-36).
	// 2026-11-26: the disruptive checks are one paragraph of the terms instead of a separate tick, so one acceptance covers them;
	// a domain's run sends them only to an address that is a proven public IP of this box (deepGate); an acceptance of 2026-11-18b
	// stays valid (keptTermsVersions).
	termsTemplate       = termsHead + termsOwnIP + termsTail
	termsTemplateDomain = termsHead + termsDomain + termsTail
	termsHead           = "I confirm that my company owns {value} and that I am authorized to test it in depth. Once I accept, every scan of {value} is a deep scan, and Vedette's tools may send it:\n" +
		"All ports: every TCP port, and the service and version behind each one.\n" +
		"Vulnerability checks: tests for known vulnerabilities, including checks that confirm a flaw by sending the exploit request itself in a harmless form (for example reading a file or running a harmless command). Some checks, OpenVAS's in particular, may write a harmless test file or record to confirm a flaw and then try to remove it.\n" +
		"Web scanning: a scan of the web pages that follows links and may submit forms.\n" +
		"Authentication checks: whether login pages, admin interfaces and services let anyone in without a password, through a known authentication bypass or with weak settings, including the public anonymous login a service may offer (for example anonymous FTP).\n" +
		termsDisruptive + "\n"
	// termsDisruptive is the paragraph of the disruptive checks (until 2026-11-18b the sentence of a separate tick).
	termsDisruptive = "Disruptive checks: denial of service, password guessing, sign-in attempts with default or well-known passwords, and exploit checks that send more than a harmless read, such as nuclei's POST exploit requests that may create or change data and nmap's SQL injection probes. These can crash a service, lock accounts, change data or take a device offline. They run only in a scan a person starts with Scan now, never in the scans Vedette runs by itself on the schedule."
	termsOwnIP      = "Accept only if {value} is yours alone: not an address shared through your Internet provider (carrier-grade NAT), a hosting provider's NAT or proxy, or a CDN or hosted service that serves your names. Their servers are not yours to test. "
	// termsDomain: the third party in front of the names
	// and the IP-level tools by name, then TERMS.md's own sentences on what verifying a name proves, third-party hosting,
	// CDN and proxies, the customer's responsibility, and that Vedette does not check who owns the addresses, so the two never disagree.
	termsDomain = "Every name under {value} that resolves to a public address is scanned at this depth, whatever serves it: your own server, a hosting provider or a CDN. " +
		"If a provider serves a name, its testing policy applies to you (for example, Cloudflare and AWS forbid denial-of-service tests). " +
		"The disruptive checks run only on an address of {value} that is a proven public IP of this box; every other address (a hosting provider, a CDN, a proxy, or the address of a name that points outside {value}) gets the deep scan without them. " +
		"Vedette's tools reach each address a name under {value} resolves to, including a third-party hosting provider, CDN or proxy in front of your names: the scan of all ports, OpenVAS, nuclei and the web scan (ZAP). " +
		"Verifying a name proves you control its DNS, not that you own the machines behind it or may test them. " +
		"With shared or cloud hosting, a CDN or a proxy, that address can also serve other people's systems: you are responsible for having the provider's permission. " +
		"Vedette does not check who owns those addresses. " +
		"A name that points (CNAME) to a name outside {value} is scanned at whatever address the owner of that other name sets. "
	termsTail = "Vedette also scans {value} by itself on the schedule set on its page (weekly unless changed), never with the disruptive checks, until that schedule is turned off. The deep scan can load or slow the services on {value} and may create, change or delete data. Run scans when you can accept that, and keep a backup. " +
		"An administrator can withdraw this acceptance at any time. Vedette is provided as is under the Apache-2.0 license; the Vedette authors are not responsible for how you use it."
)

// keptTermsVersions are the older versions whose acceptances still count after an update: the stored row keeps its version, its text
// and its disruptive flag (2026-11-18b: the deep scan, and the disruptive checks only when its tick was on). An acceptance of any
// other older version counts as not accepted until the current terms are accepted.
var keptTermsVersions = []string{"2026-11-18b"}

// Terms is who accepted the testing terms of a target, when, and the exact text of the version they saw. UserID and Method
// (how two-step was met) are kept in the row and the audit line, not in the API.
type Terms struct {
	Version    string `json:"version"`
	By         string `json:"by"`
	At         string `json:"at"`
	Text       string `json:"text"`
	Disruptive bool   `json:"disruptive"` // the disruptive checks too: always on an acceptance of TermsVersion; an older one keeps its tick
	UserID     string `json:"-"`
	Method     string `json:"-"`
}

// current says the acceptance is of the terms in force: TermsVersion or a version kept valid after an update; one of any other older
// version counts as not accepted.
func (t *Terms) current() bool {
	return t != nil && (t.Version == TermsVersion || slices.Contains(keptTermsVersions, t.Version))
}

// ScanMode is what a scan of a target may do, read by every scanner seam from ScanTarget: Full once the target's testing
// terms in force are accepted (else the basic scope), Disruptive when that acceptance includes the disruptive checks and the run's
// rules allow them. The groups say which parts may run: DoS, Logins and Change are the disruptive groups (Disruptive is
// DoS || Logins || Change), WebActive and OpenVAS parts of the deep scan; the target's deep-scan settings clear them (narrow), and
// Off records the groups the settings cleared where the rules allowed them, for the run page. Every bit only removes: a mode built
// without the groups allows none of them.
type ScanMode struct {
	Full       bool
	Disruptive bool
	DoS        bool
	Logins     bool
	Change     bool
	WebActive  bool
	OpenVAS    bool
	Off        Groups
}

func (t Target) mode() ScanMode {
	full := t.Terms.current()
	d := full && t.Terms.Disruptive
	return ScanMode{Full: full, Disruptive: d, DoS: d, Logins: d, Change: d, WebActive: full, OpenVAS: full}
}

// norm keeps the bits consistent: no group without its level, and Disruptive only with a disruptive group.
func (m ScanMode) norm() ScanMode {
	m.Disruptive = m.Full && m.Disruptive && (m.DoS || m.Logins || m.Change)
	if !m.Disruptive {
		m.DoS, m.Logins, m.Change = false, false, false
	}
	m.WebActive, m.OpenVAS = m.WebActive && m.Full, m.OpenVAS && m.Full
	return m
}

// withoutDisruptive is m without any disruptive group (a scheduled scan, an address that is not the box's own).
func (m ScanMode) withoutDisruptive() ScanMode {
	m.Disruptive, m.DoS, m.Logins, m.Change = false, false, false, false
	return m
}

// And is what both modes allow, bit by bit: a re-read of the mode is never more than the run started with.
func (m ScanMode) And(b ScanMode) ScanMode {
	return ScanMode{Full: m.Full && b.Full, Disruptive: m.Disruptive && b.Disruptive, DoS: m.DoS && b.DoS, Logins: m.Logins && b.Logins,
		Change: m.Change && b.Change, WebActive: m.WebActive && b.WebActive, OpenVAS: m.OpenVAS && b.OpenVAS, Off: m.Off | b.Off}.norm()
}

// WebDisruptive says the active web scan may run disruptive rules: the host splits them into denial-of-service rules and rules that
// may change data, and runs those of the groups allowed (the other class goes to the host turned off); ZAP has no password guessing.
func (m ScanMode) WebDisruptive() bool { m = m.norm(); return m.WebActive && (m.DoS || m.Change) }

// ModeNow is the scan mode of target id right before a deep job leaves core (for the scanner
// adapters in cmd/vedette): exposure's gate again with actor, then the terms as stored now. A target the gate
// refuses, or whose terms were withdrawn or are of an older version meanwhile, is the zero ScanMode; a scan the box runs by
// itself never gets Disruptive. The ScanTarget.Mode of the run is minutes old by then, like the gate of the run.
func (s *Service) ModeNow(ctx context.Context, actor, id string) (ScanMode, error) {
	t, reason, err := s.gate(ctx, actor, id)
	if err != nil || reason != "" {
		return ScanMode{}, err
	}
	return s.runMode(ctx, actor, t), nil
}

// TermsNotice is the terms as the page shows them (contract.ts TermsNotice): the version and the text with the target in it (one
// paragraph per line, the disruptive checks among them).
type TermsNotice struct {
	Version string `json:"version"`
	Text    string `json:"text"`
}

// termsFor is the current terms for one target: a domain's text or an IP's; a domain or an IP has no braces, so the value
// cannot substitute again.
func termsFor(k Kind, value string) TermsNotice {
	tmpl := termsTemplate
	if k == KindDomain {
		tmpl = termsTemplateDomain
	}
	return TermsNotice{Version: TermsVersion, Text: strings.ReplaceAll(tmpl, "{value}", value)}
}

// noticeOf and termsOf are the sentences of one target. A public IP a person typed in is not proved to be the company's, only
// controlled (a token file, a reverse DNS name), so the person says "I own it or am authorised to have it tested".
func noticeOf(t Target) Notice {
	n := noticeFor(t.Value)
	if t.Typed {
		n.Text = strings.Replace(n.Text, "that my company owns "+t.Value+" and that I am authorized to scan it", "that I own "+t.Value+" or am authorised to have it tested", 1)
	}
	return n
}

func termsOf(t Target) TermsNotice {
	n := termsFor(t.Kind, t.Value)
	if t.Typed {
		n.Text = strings.Replace(n.Text, "that my company owns "+t.Value+" and that I am authorized to test it in depth", "that I own "+t.Value+" or am authorised to have it tested in depth", 1)
	}
	return n
}

// typedWarning is the shared-address warning of a typed IP: a token file proves control of a web port, and the address may be shared
// hosting, a CDN or a provider's NAT, whose other tenants are not the person's to test.
const typedWarning = "The proof shows control of this address's web service only. If it is shared hosting, a CDN, a hosting provider's NAT or an address your provider shares with other customers, the other tenants are not yours to test: accept the testing terms, which include the disruptive checks, only if the address is yours alone and you can afford to break the system behind it."

// cgnat is the shared address space of carrier-grade NAT (RFC 6598).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// sharedAddress is the warning of the terms step of an IP target when the box's default gateway is in 100.64.0.0/10:
// the box then reaches the Internet through carrier-grade NAT, so its public IP is the provider's, shared with other customers,
// and its open ports are the provider's. Accepting the testing terms is refused while it shows (they include the disruptive checks). ponytail: only the box's own gateway is
// known here (a home router whose WAN side is CGNAT is not seen); upgrade: the host reports the router's WAN address (UPnP or the
// second hop of a traceroute). "" when not known to be shared (no Gateway wired, or the lookup failed).
func (s *Service) sharedAddress(ctx context.Context, t Target) string {
	if t.Typed { // not the address the box goes out through: its own warning, always shown
		return typedWarning
	}
	if t.Kind != KindIP {
		return ""
	}
	g, shared, err := s.sharedGateway(ctx)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: reading the gateway for the testing terms", "err", err)
		return ""
	}
	if !shared {
		return ""
	}
	return fmt.Sprintf("This box reaches the Internet through carrier-grade NAT (its gateway %s is in 100.64.0.0/10), so %s is probably shared with your provider's other customers and its open ports are the provider's. "+
		"The testing terms cannot be accepted for it: they include the disruptive checks, which would reach the provider's equipment.", g, t.Value)
}

// sharedGateway reads the box's default gateway and says whether it is in 100.64.0.0/10 (carrier-grade NAT). No Gateway wired: not
// shared, no error.
func (s *Service) sharedGateway(ctx context.Context) (netip.Addr, bool, error) {
	if s.cfg.Gateway == nil {
		return netip.Addr{}, false, nil
	}
	g, err := s.cfg.Gateway.Gateway(ctx)
	if err != nil {
		return netip.Addr{}, false, err
	}
	return g.IP, g.IP.IsValid() && cgnat.Contains(g.IP.Unmap()), nil
}

// runMode is the mode a scan of target t runs at when actor starts it now: what the terms allow (t.mode()), never the disruptive
// checks in a scan the box runs by itself (boxMode), and never the disruptive checks on the box's own IP (not a typed one) while the
// box's gateway is in 100.64.0.0/10 or cannot be read: the address is then probably the provider's, shared with its other customers.
// The acceptance is refused in that case (sharedAddress); this covers an acceptance stored before the gateway moved there. Fail
// closed at scan time: the deep scan runs as accepted, without the disruptive checks.
//
// Last, the target's deep-scan settings narrow what is left (narrow): they only remove groups, so every rule above still holds.
func (s *Service) runMode(ctx context.Context, actor string, t Target) ScanMode {
	m := boxMode(actor, t.mode())
	if !m.Disruptive || t.Kind != KindIP || t.Typed {
		return narrow(m, t.Deep)
	}
	g, shared, err := s.sharedGateway(ctx)
	switch {
	case err != nil:
		s.cfg.Log.WarnContext(ctx, "exposure: the gateway could not be read, so this scan runs without the disruptive checks", "target", t.Value, "err", err)
		m = m.withoutDisruptive()
	case shared:
		s.cfg.Log.WarnContext(ctx, "exposure: the gateway is in 100.64.0.0/10, so this scan runs without the disruptive checks", "target", t.Value, "gateway", g.String())
		m = m.withoutDisruptive()
	}
	return narrow(m, t.Deep)
}

func errTermsChanged() *APIError {
	return apiErr(409, "notice_changed", "The testing terms changed since this page loaded. Read them again, then accept them again.")
}

// AcceptTerms is PUT /exposure/targets/{id}/terms and PUT /exposure/tree/{id}/terms (admin with two-step sign-in): the one acceptance
// of the testing terms, the deep scan and the disruptive checks together. Every refusal is logged at WARN with its code and the
// target id (no e-mail address, no token), so a refused acceptance leaves a trace for the person who reads the box's log.
func (s *Service) AcceptTerms(ctx context.Context, who Actor, id, version string) (TargetView, error) {
	v, err := s.acceptTerms(ctx, who, id, version)
	if ae := (*APIError)(nil); errors.As(err, &ae) {
		s.cfg.Log.WarnContext(ctx, "exposure: testing terms refused", "code", ae.Code, "status", ae.HTTP, "target", clipText(id, 80), "user", who.ID)
	}
	return v, err
}

// acceptTerms: the target must be verified and its proof not expired, the request must carry the version the page showed, and an IP
// of the box's own (not typed in) must not sit behind carrier-grade NAT (sharedAddress). The box's own IP it does not go out through
// now keeps its proof for ValidDays from its last sighting (INV-4) and is scanned in that time, so its terms can be accepted in that
// time too, disruptive checks included: the carrier-grade NAT check reads the box's own gateway, the same for every line of a router.
// It stores who, when, the version, the disruptive flag (always on) and the exact text with an exposure.terms_accept audit row, in
// one transaction. The terms include the ownership and authorization sentence, so a target without a commitment of the current Scan
// now sentence gets that one too (its own exposure.commitment row). Accepting the current terms again changes nothing; accepting
// them over an acceptance of an older version replaces it (and adds the disruptive checks when it had none).
func (s *Service) acceptTerms(ctx context.Context, who Actor, id, version string) (TargetView, error) {
	if !who.Admin {
		return TargetView{}, apiErr(403, "forbidden", "Only an administrator can accept the testing terms.")
	}
	if s.cfg.TwoStep == nil {
		return TargetView{}, errNeedTwoStep()
	}
	method, err := s.cfg.TwoStep(ctx, who.ID)
	if err != nil {
		return TargetView{}, fmt.Errorf("checking two-step sign-in: %w", err)
	}
	if method == "" {
		return TargetView{}, errNeedTwoStep()
	}
	if version != TermsVersion {
		return TargetView{}, errTermsChanged()
	}
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return TargetView{}, err
	}
	if err := termsStatus(t, s.clock()); err != nil { // before the gateway: an unverified or expired target says so first
		return TargetView{}, err
	}
	if w := s.sharedAddress(ctx, t); w != "" && !t.Typed { // a typed IP shows its own warning and is accepted on purpose
		return TargetView{}, apiErr(409, "shared_address", "%s", w)
	}
	err = s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		now := s.clock()
		if err := termsStatus(t, now); err != nil { // again inside the write: the proof may have lapsed meanwhile
			return err
		}
		if t.Terms != nil && t.Terms.Version == TermsVersion && t.Terms.Disruptive {
			return nil
		}
		if !t.Commitment.current() {
			n := noticeOf(t)
			if err := setCommitment(ctx, tx, id, who.Email, now, n, who.ID, method); err != nil {
				return err
			}
			if err := s.audit(ctx, tx, who.Email, "exposure.commitment", t.Value, "confirmed by accepting the testing terms (user "+who.ID+", two-step: "+method+", notice "+n.Version+"): "+n.Text); err != nil {
				return err
			}
		}
		n := termsOf(t)
		what := "accepted"
		if t.Terms != nil {
			what = "accepted again (replaces terms " + t.Terms.Version + ", accepted by " + t.Terms.By + " at " + t.Terms.At + ", disruptive checks: " + yesNo(t.Terms.Disruptive) + ")"
		}
		if err := setTerms(ctx, tx, id, &Terms{Version: n.Version, By: who.Email, At: store.FormatTS(now), Text: n.Text, Disruptive: true, UserID: who.ID, Method: method}); err != nil {
			return err
		}
		return s.audit(ctx, tx, who.Email, "exposure.terms_accept", t.Value, auditClip(what+" (disruptive checks: yes, user "+who.ID+", two-step: "+method+", terms "+n.Version+"): "+n.Text))
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: accepting the testing terms: %w", err)
	}
	return s.Target(ctx, id)
}

// termsStatus refuses the terms of a target that is not verified or whose proof expired.
func termsStatus(t Target, now time.Time) error {
	switch t.status(now) {
	case statusUnverified:
		return apiErr(409, "not_verified", "Verify ownership first; only then can the testing terms be accepted.")
	case statusExpired:
		return apiErr(409, "expired", "Verification of %s has expired. Verify it again first.", t.Value)
	}
	return nil
}

// auditDetailMax is core/audit's limit on a detail, in characters.
const auditDetailMax = 2000

// termsClipNote ends an audit detail whose terms text was cut (a domain's text with a long name can pass auditDetailMax). The whole text stays in the target's row (terms_text) and each version's text is pinned in code.
const termsClipNote = " … (cut here; the whole text is stored with the acceptance and pinned to its version)"

// auditClip keeps an audit detail within auditDetailMax characters, cutting its end and saying so.
func auditClip(d string) string {
	if utf8.RuneCountInString(d) <= auditDetailMax {
		return d
	}
	return clipText(d, auditDetailMax-utf8.RuneCountInString(termsClipNote)) + termsClipNote
}

// above says whether mode m may do more than mode b.
func (m ScanMode) above(b ScanMode) bool {
	return (m.Full && !b.Full) || (m.Disruptive && !b.Disruptive)
}

// stopRunAbove stops the scan of target id that runs now when its mode is above m: withdrawing the terms must reach a
// scan that runs now, the case where the service is being hurt. A queued scan has no mode yet: it reads the terms when it starts. Every step reads the run's context: the OpenVAS step stops
// gvmd's task (stop_task) and keeps the rows the earlier steps wrote, as a Stop does. Only a run really stopped gets its own audit
// row, on the action of the terms change.
func (s *Service) stopRunAbove(ctx context.Context, id, value string, m ScanMode, user, action, why string) {
	s.runMu.Lock()
	runID := ""
	for rid, x := range s.execs {
		if x.targetID == id && x.mode.above(m) {
			runID = rid
		}
	}
	s.runMu.Unlock()
	if runID == "" || s.cfg.Runs == nil {
		return
	}
	s.setStopCause(runID, &stoppedBy{by: user + " (" + why + ")", why: why, reason: StopTerms, person: user})
	if err := s.cfg.Runs.Stop(ctx, runID, user, why); err != nil {
		s.cfg.Log.WarnContext(ctx, "exposure: stopping the scan after a terms change", "target", value, "error", err)
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	if err := s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		return s.audit(wctx, tx, user, action, value, stoppedNote+" ("+why+")")
	}); err != nil {
		s.cfg.Log.ErrorContext(wctx, "exposure: auditing the stop of a scan by a terms change failed", "target", value, "error", err)
	}
}

// stoppedNote is the audit row written when a terms change really stopped the running scan.
const stoppedNote = "the scan of this target that was running was stopped"

// RevokeTerms is DELETE /exposure/targets/{id}/terms (admin): always possible; the next scan runs in the basic scope again, and
// a scan of this target that runs now at full depth is stopped.
func (s *Service) RevokeTerms(ctx context.Context, user, id string) (TargetView, error) {
	value := ""
	err := s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		t, err := loadTarget(ctx, tx, id)
		if err != nil {
			return err
		}
		if t.Terms == nil {
			return nil
		}
		if err := setTerms(ctx, tx, id, nil); err != nil {
			return err
		}
		value = t.Value
		return s.audit(ctx, tx, user, "exposure.terms_revoke", t.Value, "withdrawn (terms "+t.Terms.Version+", disruptive checks: "+yesNo(t.Terms.Disruptive)+", accepted by "+t.Terms.By+" at "+t.Terms.At+")")
	})
	if err != nil {
		return TargetView{}, fmt.Errorf("exposure: withdrawing the testing terms: %w", err)
	}
	if value != "" {
		s.stopRunAbove(ctx, id, value, ScanMode{}, user, "exposure.terms_revoke", "the testing terms of this target were withdrawn")
	}
	return s.Target(ctx, id)
}

// setTerms stores an acceptance, or clears it (nil).
func setTerms(ctx context.Context, tx *sql.Tx, id string, t *Terms) error {
	if t == nil {
		return dropConsent(ctx, tx, id, consentTerms)
	}
	at, err := parseTS(t.At)
	if err != nil {
		return fmt.Errorf("recording the testing terms of %s: %w", id, err)
	}
	return putConsent(ctx, tx, id, consentTerms, consentRow{Version: t.Version, Text: t.Text, By: t.By, UserID: t.UserID, Method: t.Method, Disruptive: t.Disruptive, At: at})
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
