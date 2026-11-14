package exposure

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// What the Internet sees (D-558, INV-21): on an administrator's click, the box asks Shodan InternetDB what it has seen on one of
// its own verified public IPs, and the page shows that next to Vedette's own scan, which runs from inside the network (NAT
// loopback). Shodan's terms: "Free for non-commercial use: you can use it at a company, you can't use it to build commercial
// products that you charge money for" (blog.shodan.io/introducing-the-internetdb-api). Vedette is free; each box asks for its own IP.

// InternetDBURL is Shodan InternetDB: no key, one GET per IP. It is fixed in code, never typed in.
const InternetDBURL = "https://internetdb.shodan.io"

const (
	outsideMaxBody  = 64 << 10         // an answer longer than this is refused (INV-10)
	outsideTimeout  = 10 * time.Second // the whole request
	outsideMaxItems = 200              // entries kept per list of an answer
	// OutsideEvery is the least time between two requests to Shodan from the box (any IP, any person): a repeated click is
	// answered 429 rather than sent again.
	OutsideEvery = time.Minute
)

// The answers of a check that got nothing usable from Shodan. Nothing is stored for them; the request is audited.
var (
	ErrOutsideDown = apiErr(502, "unreachable", "Shodan InternetDB (internetdb.shodan.io) did not answer, so nothing was saved. Check that this box can make outgoing HTTPS connections, then try again in a few minutes.")
	ErrOutsideBad  = apiErr(502, "unreachable", "Shodan InternetDB sent an answer Vedette cannot read, so nothing was saved. Try again later.")
	ErrOutsideIP   = apiErr(400, "bad_value", "Only a public IP of this box can be checked with Shodan, not a domain.")
	ErrOutsideV4   = apiErr(400, "bad_value", "Only a public IPv4 address of this box can be checked with Shodan.")
	// ErrOutsideLimited: InternetDB answered 429 (it limits requests per asking IP, for example a shared office or carrier address).
	ErrOutsideLimited = apiErr(502, "unreachable", "Shodan is limiting requests from this box's IP right now, so nothing was saved. Try again later.")
	ErrOutsideOff     = apiErr(501, "not_implemented", "Checking with Shodan is not set up on this box.")
)

// outsideRefusal is the answer when a target may not be sent to Shodan (INV-21): the same conditions as a scan, in the words of
// this check.
func (s *Service) outsideRefusal(t Target, r BlockedReason, now time.Time) error {
	switch r {
	case BlockedUnverified:
		return apiErr(409, "not_verified", "%s has no ownership proof, so it cannot be checked with Shodan. Finish verification first.", t.Value)
	case BlockedExpired:
		return apiErr(409, "expired", "Verification of %s expired on %s, so it cannot be checked with Shodan. Verify it again first.", t.Value, s.dayText(t.expiresAt(now)))
	}
	return apiErr(409, "ip_not_current", "This box no longer reaches the Internet through %s; it was last seen %s. It is not sent to Shodan until the box uses it again.", t.Value, s.momentText(t.VerifiedAt))
}

func outsideTooSoon() *APIError {
	return apiErr(429, "rate_limited", "The box asked Shodan less than a minute ago. Try again in a minute: it asks at most once a minute.")
}

// InternetDB asks Shodan InternetDB about one IP. It follows no redirect, caps the answer at 64 KiB, has a deadline and keeps the
// environment's proxy settings (the IP is in the path, so a proxy does not change the answer; unlike the "what is my IP" services).
type InternetDB struct {
	base   string
	client *http.Client
}

// NewInternetDB returns the client of base ("": InternetDBURL; tests pass an httptest TLS server). transport may be nil (a clone of
// the default transport).
func NewInternetDB(base string, transport *http.Transport) (*InternetDB, error) {
	if base == "" {
		base = InternetDBURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" {
		return nil, errors.New("exposure: creating the InternetDB client: the address must be https://host without a path")
	}
	if transport == nil {
		dt, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("exposure: creating the InternetDB client: no default transport")
		}
		transport = dt
	}
	return &InternetDB{
		base: strings.TrimRight(u.String(), "/"),
		client: &http.Client{
			Transport:     transport.Clone(),
			Timeout:       outsideTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// OutsideAnswer is what Shodan said about one IP, limited and checked (parseOutside).
type OutsideAnswer struct {
	Found     bool     `json:"-"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	CPEs      []string `json:"cpes"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

// Lookup sends the one request: GET <base>/<ip>. 404 is "no record" (Found false), not an error. Any other failure is
// ErrOutsideDown (no answer, another status) or ErrOutsideBad (an answer that does not parse).
func (d *InternetDB) Lookup(ctx context.Context, ip netip.Addr) (OutsideAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/"+ip.String(), nil)
	if err != nil {
		return OutsideAnswer{}, fmt.Errorf("exposure: asking Shodan: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return OutsideAnswer{}, fmt.Errorf("exposure: asking Shodan: %w: %w", ErrOutsideDown, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, outsideMaxBody+1))
	switch {
	case err != nil:
		return OutsideAnswer{}, fmt.Errorf("exposure: reading Shodan's answer: %w: %w", ErrOutsideDown, err)
	case resp.StatusCode == http.StatusNotFound:
		// Only InternetDB's own "no record" ({"detail": "..."}) means no record: a 404 page of a proxy or an edge is not Shodan's answer.
		if !isNoRecord(body) {
			return OutsideAnswer{}, fmt.Errorf("exposure: a 404 that is not InternetDB's: %w", ErrOutsideBad)
		}
		return OutsideAnswer{Found: false, Ports: []int{}, Hostnames: []string{}, CPEs: []string{}, Tags: []string{}, Vulns: []string{}}, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return OutsideAnswer{}, fmt.Errorf("exposure: Shodan answered 429: %w", ErrOutsideLimited)
	case resp.StatusCode != http.StatusOK:
		return OutsideAnswer{}, fmt.Errorf("exposure: Shodan answered %d: %w", resp.StatusCode, ErrOutsideDown)
	case len(body) > outsideMaxBody:
		return OutsideAnswer{}, fmt.Errorf("exposure: Shodan's answer is over %d bytes: %w", outsideMaxBody, ErrOutsideBad)
	}
	a, err := parseOutside(body, ip)
	if err != nil {
		return OutsideAnswer{}, fmt.Errorf("exposure: %w: %w", ErrOutsideBad, err)
	}
	return a, nil
}

// isNoRecord: InternetDB's 404 body, one JSON object with a string detail (`{"detail":"No information available"}`).
func isNoRecord(body []byte) bool {
	var v struct {
		Detail *string `json:"detail"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&v); err != nil || v.Detail == nil {
		return false
	}
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

var (
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9])?$`)
	tagRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9 _-]{0,31}$`)
	cveRE      = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)
)

// parseOutside reads InternetDB's JSON (untrusted, INV-10): one object whose ip is the address asked and whose lists have the
// right types, else an error (fail closed). Unknown fields are ignored (Shodan may add some). An entry that does not fit
// (a port outside 1..65535, a name with other characters, a CPE that is not cpe:/ printable ASCII, a vulnerability that is not a
// CVE ID) is dropped, not cut; duplicates go, lists are sorted and kept to 200 entries.
func parseOutside(body []byte, ip netip.Addr) (OutsideAnswer, error) {
	var raw struct {
		IP        string   `json:"ip"`
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		CPEs      []string `json:"cpes"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&raw); err != nil {
		return OutsideAnswer{}, fmt.Errorf("not the JSON object of InternetDB: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return OutsideAnswer{}, errors.New("data after the JSON object")
	}
	if got, err := netip.ParseAddr(raw.IP); err != nil || got != ip {
		return OutsideAnswer{}, errors.New("the answer is about another address")
	}
	a := OutsideAnswer{Found: true, Ports: []int{}}
	for _, p := range raw.Ports {
		if p >= 1 && p <= 65535 {
			a.Ports = append(a.Ports, p)
		}
	}
	slices.Sort(a.Ports)
	a.Ports = slices.Compact(a.Ports)
	if len(a.Ports) > outsideMaxItems {
		a.Ports = a.Ports[:outsideMaxItems]
	}
	a.Hostnames = keep(raw.Hostnames, func(s string) bool { return len(s) <= 253 && hostnameRE.MatchString(s) })
	a.CPEs = keep(raw.CPEs, func(s string) bool { return len(s) <= 200 && strings.HasPrefix(s, "cpe:/") && printableASCII(s) })
	a.Tags = keep(raw.Tags, tagRE.MatchString)
	a.Vulns = keep(raw.Vulns, cveRE.MatchString)
	return a, nil
}

// keep returns the entries ok accepts, sorted, without duplicates, at most outsideMaxItems; never nil.
func keep(in []string, ok func(string) bool) []string {
	out := []string{}
	for _, s := range in {
		if ok(s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > outsideMaxItems {
		out = out[:outsideMaxItems]
	}
	return out
}

func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// OutsideView is the API shape of what the Internet sees (contract.ts OutsideView): Shodan's last answer about a target's IP, and
// the open ports of Vedette's own newest scan of it, read now.
type OutsideView struct {
	IP        string `json:"ip"`
	CheckedAt string `json:"checked_at"`
	CheckedBy string `json:"checked_by"`
	Found     bool   `json:"found"`
	OutsideAnswer
	ScanPorts []int   `json:"scan_ports"` // nil: never scanned
	ScanAt    *string `json:"scan_at"`
}

// Outside returns the last Shodan answer about a target (GET …/outside), nil when nobody has asked. It sends nothing.
func (s *Service) Outside(ctx context.Context, id string) (*OutsideView, error) {
	db := s.cfg.DB.Reader()
	if _, err := loadTarget(ctx, db, id); err != nil {
		return nil, fmt.Errorf("exposure: reading the outside view: %w", err)
	}
	v, err := s.outsideView(ctx, db, id)
	if err != nil {
		return nil, fmt.Errorf("exposure: reading the outside view: %w", err)
	}
	return v, nil
}

func (s *Service) outsideView(ctx context.Context, q querier, id string) (*OutsideView, error) {
	var v OutsideView
	var found int
	var answer string
	err := q.QueryRowContext(ctx, `SELECT ip, checked_at, checked_by, found, answer FROM exp_outside WHERE target_id = ?`, id).
		Scan(&v.IP, &v.CheckedAt, &v.CheckedBy, &found, &answer)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // nil is the API's null: nobody has asked yet
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(answer), &v.OutsideAnswer); err != nil {
		return nil, fmt.Errorf("stored answer of %s: %w", id, err)
	}
	v.Found = found == 1
	v.Ports, v.Hostnames, v.CPEs, v.Tags, v.Vulns = nz(v.Ports), nz(v.Hostnames), nz(v.CPEs), nz(v.Tags), nz(v.Vulns)
	// Our own side, read now: the open ports of the newest scan of this IP.
	var at, ports string
	err = q.QueryRowContext(ctx, `SELECT scanned_at, ports FROM exp_snapshot WHERE target_id = ? ORDER BY date DESC LIMIT 1`, id).Scan(&at, &ports)
	if errors.Is(err, sql.ErrNoRows) {
		return &v, nil
	}
	if err != nil {
		return nil, err
	}
	var rows []PortRow
	if err := json.Unmarshal([]byte(ports), &rows); err != nil {
		return nil, fmt.Errorf("snapshot ports of %s: %w", id, err)
	}
	v.ScanPorts, v.ScanAt = []int{}, &at
	for _, r := range rows {
		if r.IP == v.IP {
			v.ScanPorts = append(v.ScanPorts, r.Port)
		}
	}
	slices.Sort(v.ScanPorts)
	v.ScanPorts = slices.Compact(v.ScanPorts)
	return &v, nil
}

// CheckOutside asks Shodan about a target's IP (POST …/outside, admin; INV-21). Only an IP of the box that is verified, not
// expired and still the one the box goes out through (INV-13: the same check as before a scan, which may run one full check as
// user) is sent; anything else is refused before any request. At most one request every OutsideEvery on the box. Every request
// sent is audited (exposure.outside_view), and an answer replaces the target's last one in the same transaction.
func (s *Service) CheckOutside(ctx context.Context, user, id string) (OutsideView, error) {
	if s.cfg.Outside == nil {
		return OutsideView{}, ErrOutsideOff
	}
	t, err := loadTarget(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return OutsideView{}, fmt.Errorf("exposure: checking with Shodan: %w", err)
	}
	if t.Kind != KindIP {
		return OutsideView{}, ErrOutsideIP
	}
	ip, err := netip.ParseAddr(t.Value)
	if err != nil || !ip.Is4() {
		return OutsideView{}, ErrOutsideV4
	}
	if r := t.blocked(s.clock()); r == BlockedUnverified || r == BlockedExpired {
		return OutsideView{}, s.outsideRefusal(t, r, s.clock())
	}
	current, err := s.stillCurrent(ctx, user, t)
	if err != nil {
		return OutsideView{}, fmt.Errorf("exposure: checking with Shodan: %w", err)
	}
	if !current {
		if t, err = loadTarget(ctx, s.cfg.DB.Reader(), id); err != nil {
			return OutsideView{}, fmt.Errorf("exposure: checking with Shodan: %w", err)
		}
		return OutsideView{}, s.outsideRefusal(t, BlockedNotCurrent, s.clock())
	}
	if !s.takeOutsideTurn() {
		return OutsideView{}, outsideTooSoon()
	}
	// From here the request goes to Shodan: it, the audit row and the answer must not depend on the person's browser staying on
	// the page (INV-21), like the save of a finished scan.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), outsideTimeout+saveTimeout)
	defer cancel()
	ans, lerr := s.cfg.Outside.Lookup(sctx, ip)
	err = s.write(sctx, func(tx *sql.Tx, _ func(string, any)) error {
		if lerr != nil {
			return s.audit(sctx, tx, user, "exposure.outside_view", t.Value, "sent to internetdb.shodan.io; failed: "+outsideFailure(lerr))
		}
		if _, err := loadTarget(sctx, tx, id); err != nil { // deleted meanwhile: nothing to keep the answer with
			if aerr := s.audit(sctx, tx, user, "exposure.outside_view", t.Value, "sent to internetdb.shodan.io; the target was deleted meanwhile, answer not kept"); aerr != nil {
				return aerr
			}
			return nil
		}
		doc, err := json.Marshal(ans)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(sctx, `INSERT INTO exp_outside (target_id, ip, checked_at, checked_by, found, answer) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (target_id) DO UPDATE SET ip = excluded.ip, checked_at = excluded.checked_at, checked_by = excluded.checked_by, found = excluded.found, answer = excluded.answer`,
			id, t.Value, store.FormatTS(s.clock()), user, boolInt(ans.Found), string(doc)); err != nil {
			return fmt.Errorf("storing Shodan's answer: %w", err)
		}
		detail := "sent to internetdb.shodan.io; Shodan has no record of it"
		if ans.Found {
			detail = fmt.Sprintf("sent to internetdb.shodan.io; Shodan lists %d ports and %d CVEs", len(ans.Ports), len(ans.Vulns))
		}
		return s.audit(sctx, tx, user, "exposure.outside_view", t.Value, detail)
	})
	if lerr != nil {
		if err != nil {
			s.cfg.Log.ErrorContext(sctx, "auditing a Shodan request failed", "error", err)
		}
		var ae *APIError
		if errors.As(lerr, &ae) {
			return OutsideView{}, ae
		}
		s.cfg.Log.WarnContext(sctx, "asking Shodan failed", "error", lerr)
		return OutsideView{}, ErrOutsideDown
	}
	if err != nil {
		return OutsideView{}, fmt.Errorf("exposure: checking with Shodan: %w", err)
	}
	v, err := s.outsideView(sctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return OutsideView{}, fmt.Errorf("exposure: reading the outside view: %w", err)
	}
	if v == nil {
		return OutsideView{}, fmt.Errorf("exposure: checking with Shodan: %w", ErrNotFound)
	}
	return *v, nil
}

// takeOutsideTurn reports whether a request may go to Shodan now, and if so counts it (kept in memory: a restart forgets it).
func (s *Service) takeOutsideTurn() bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	now := s.now()
	if !s.lastOutside.IsZero() && now.Sub(s.lastOutside) < OutsideEvery && !s.lastOutside.After(now.Add(clockSlack)) {
		return false
	}
	s.lastOutside = now
	return true
}

// outsideFailure is the audit text of a failed request: the code of the answer, never Shodan's own text.
func outsideFailure(err error) string {
	switch {
	case errors.Is(err, ErrOutsideBad):
		return "the answer could not be read"
	case errors.Is(err, ErrOutsideLimited):
		return "Shodan is limiting requests (429)"
	case errors.Is(err, ErrOutsideDown):
		return "no usable answer"
	}
	return "error"
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
