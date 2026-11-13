package honeypot

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/knt048/vedette/core/logexport"
	"github.com/knt048/vedette/core/store"
)

// maxHitsListed caps GET /honeypot/hits.
const maxHitsListed = 1000

// maxEvents caps the lines of the honeypot kept with a hit.
const maxEvents = 20

type storedHit struct {
	Hit
	tokenID string
	events  []HitEvent
	connKey string
}

const hitCols = `id, ts, kind, service, label, port, src_ip, is_test, excerpt, trap_ip, trap_hostname, token_id, events`

func scanHit(sc interface{ Scan(...any) error }) (storedHit, error) {
	var h storedHit
	var svc, tok sql.NullString
	var port sql.NullInt64
	var ev string
	if err := sc.Scan(&h.ID, &h.TS, &h.Kind, &svc, &h.Label, &port, &h.SrcIP, &h.IsTest, &h.Excerpt, &h.TrapIP, &h.TrapHostname, &tok, &ev); err != nil {
		return storedHit{}, err
	}
	if svc.Valid {
		s := ServiceName(svc.String)
		h.Service = &s
	}
	if port.Valid {
		p := int(port.Int64)
		h.Port = &p
	}
	h.tokenID = tok.String
	h.events = []HitEvent{}
	if err := json.Unmarshal([]byte(ev), &h.events); err != nil || h.events == nil {
		h.events = []HitEvent{}
	}
	return h, nil
}

// view resolves the source device by IP now (INV-8). A test hit comes from the box itself: it names no device.
func (w *world) view(h storedHit) Hit {
	out := h.Hit
	out.SrcAssetID, out.SrcName = nil, nil
	if !h.IsTest {
		if d := w.byIP(h.SrcIP); d != nil {
			out.SrcAssetID, out.SrcName = ptr(d.ID), ptr(d.Name)
		}
	}
	return out
}

// Hits lists the hits, newest first; with an asset, those whose source address the device has now. The response, ai and
// logs modules read the same list through their ports (IMPACT); each row carries is_test so a test can be told apart.
func (s *Service) Hits(ctx context.Context, f HitFilter) ([]Hit, error) {
	w, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	q, args := `SELECT `+hitCols+` FROM hp_hits`, []any{}
	if f.Asset != "" {
		var ip string
		for _, d := range w.devices {
			if d.ID == f.Asset && !d.IsBox && d.IP.IsValid() {
				ip = d.IP.String()
			}
		}
		if ip == "" {
			return []Hit{}, nil
		}
		q += ` WHERE src_ip = ? AND is_test = 0`
		args = append(args, ip)
	}
	rows, err := s.db.Reader().QueryContext(ctx, q+` ORDER BY ts DESC, id DESC LIMIT ?`, append(args, maxHitsListed)...)
	if err != nil {
		return nil, fmt.Errorf("honeypot: read hits: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Hit{}
	for rows.Next() {
		h, err := scanHit(rows)
		if err != nil {
			return nil, fmt.Errorf("honeypot: read hits: %w", err)
		}
		out = append(out, w.view(h))
	}
	return out, rows.Err()
}

// HitDetail is GET /honeypot/hits/{id}: the hit with the lines of the honeypot kept with it and, when the logs module is
// there, the lines of other sources in the hour around it (INV-9). Without the logs module the list has only our own.
func (s *Service) HitDetail(ctx context.Context, id string) (HitDetail, error) {
	w, err := s.load(ctx)
	if err != nil {
		return HitDetail{}, err
	}
	h, err := scanHit(s.db.Reader().QueryRowContext(ctx, `SELECT `+hitCols+` FROM hp_hits WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return HitDetail{}, notFound("No such trap hit. The list may have been cleaned up.")
	}
	if err != nil {
		return HitDetail{}, fmt.Errorf("honeypot: read hit: %w", err)
	}
	out := HitDetail{Hit: w.view(h), Events: h.events, WindowMinutes: WindowMinutes}
	if !h.IsTest {
		if d := w.byIP(h.SrcIP); d != nil {
			out.Asset = &DetailAsset{ID: d.ID, Kind: d.Kind, IP: d.IP.String(), Approved: d.Approved}
		}
		if s.cfg.Logs != nil {
			at, err := time.Parse(time.RFC3339, h.TS)
			src, _ := netip.ParseAddr(h.SrcIP)
			if err == nil {
				lines, err := s.cfg.Logs.Around(ctx, at, WindowMinutes*time.Minute/2, src)
				if err != nil {
					s.cfg.Log.WarnContext(ctx, "honeypot: log lines around a hit are not available", "error", err)
				}
				for _, l := range lines {
					if l.Source == "honeypot" { // ours are kept with the hit already
						continue
					}
					out.Events = append(out.Events, HitEvent{TS: store.FormatTS(l.TS), Source: l.Source, Text: clean(l.Text, 300)})
				}
			}
		}
	}
	sort.SliceStable(out.Events, func(i, j int) bool { return out.Events[i].TS < out.Events[j].TS })
	return out, nil
}

// SourceConnected reports whether src completed a connection to a trap service (a real service hit: the listener logs a connection only
// after the handshake) within window of at. A scan hit can be made from attempts that completed nothing, so its source may be forged;
// response offers to block the source of a scan only when this holds (D-509). Read only.
func (s *Service) SourceConnected(ctx context.Context, src string, at time.Time, window time.Duration) (bool, error) {
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM hp_hits WHERE src_ip = ? AND is_test = 0 AND kind = 'service' AND ts BETWEEN ? AND ?`,
		src, store.FormatTS(at.Add(-window)), store.FormatTS(at.Add(window))).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("honeypot: read the hits of a source: %w", err)
	}
	return n > 0, nil
}

func (s *Service) insertHit(ctx context.Context, tx *sql.Tx, h storedHit) error {
	var svc, port, tok, conn any
	if h.Service != nil {
		svc = string(*h.Service)
	}
	if h.Port != nil {
		port = *h.Port
	}
	if h.tokenID != "" {
		tok = h.tokenID
	}
	if h.connKey != "" {
		conn = h.connKey
	}
	ev, err := json.Marshal(h.events)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO hp_hits (`+hitCols+`, conn_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.TS, string(h.Kind), svc, h.Label, port, h.SrcIP, h.IsTest, h.Excerpt, h.TrapIP, h.TrapHostname, tok, string(ev), conn)
	if err != nil {
		return fmt.Errorf("honeypot: store hit: %w", err)
	}
	return nil
}

// recordTest stores a test hit (INV-4): from the box itself, marked is_test, counted nowhere, published nowhere.
func (s *Service) recordTest(ctx context.Context, actor, action, target string, h storedHit) (Hit, error) {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		if err := s.insertHit(ctx, tx, h); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, action, target, "")
	})
	if err != nil {
		return Hit{}, err
	}
	out := h.Hit
	out.SrcAssetID, out.SrcName = nil, nil
	return out, nil
}

func (s *Service) testHit(box Box, kind HitKind, svc *ServiceName, port *int, label, excerpt, trapIP, trapHost, eventText string) storedHit {
	src := "0.0.0.0"
	if box.IP.IsValid() {
		src = box.IP.String()
	}
	ts := store.FormatTS(s.now())
	return storedHit{
		Hit:    Hit{ID: store.NewID("hit"), TS: ts, Kind: kind, Service: svc, Label: label, Port: port, SrcIP: src, IsTest: true, Excerpt: excerpt, TrapIP: trapIP, TrapHostname: trapHost},
		events: []HitEvent{{TS: ts, Source: "vedette", Text: eventText, Mark: true}},
	}
}

// TestHit is POST /honeypot/test-hit (PRE-1, INV-4).
func (s *Service) TestHit(ctx context.Context, actor string, svc ServiceName) (Hit, error) {
	if !svc.Valid() {
		return Hit{}, bad("bad_service", "Choose a service: SMB, RDP, SSH, MSSQL or HTTP.")
	}
	w, err := s.load(ctx)
	if err != nil {
		return Hit{}, err
	}
	// The first Trap IP that is on with this service (D-466); one whose address the box would not hand to the host cannot listen.
	var on []trapIPRow
	for _, d := range w.trapIPs {
		if d.Enabled && d.has(svc) {
			on = append(on, d)
		}
	}
	if len(on) == 0 {
		return Hit{}, conflictErr("trap_off", fmt.Sprintf("No Trap IP that is on has %s. Add %s to a Trap IP, or turn one on, before testing.", svc.Label(), svc.Label()))
	}
	i := slices.IndexFunc(on, func(d trapIPRow) bool { return w.ipProblem(d.ip) == "" })
	if i < 0 {
		return Hit{}, conflictErr("ip_in_use", fmt.Sprintf("Every Trap IP with %s clashes with a device or is outside the box's network, so the trap cannot listen. Change the address before testing.", svc.Label()))
	}
	t := on[i]
	p := svc.Port()
	h := s.testHit(w.box, KindService, &svc, &p, svc.Label(),
		fmt.Sprintf("[test] The Vedette box connected to %s port %d on %s itself to check the trap", svc.Label(), p, t.Name), t.IP, t.Name,
		fmt.Sprintf(`Test started by a user selecting "Test trap" for %s. Not an attacker.`, svc.Label()))
	return s.recordTest(ctx, actor, "honeypot.test_hit", svc.Label(), h)
}

// TestScan is POST /honeypot/test-scan.
func (s *Service) TestScan(ctx context.Context, actor string) (Hit, error) {
	w, err := s.load(ctx)
	if err != nil {
		return Hit{}, err
	}
	var ips []string
	for _, d := range w.trapIPs {
		if d.Enabled {
			ips = append(ips, d.IP)
		}
	}
	if len(ips) < 2 {
		return Hit{}, conflictErr("need_decoys", "Scan detection needs at least two Trap IPs that are on. Add a Trap IP first.")
	}
	n := len(ips)
	h := s.testHit(w.box, KindScan, nil, nil, fmt.Sprintf("Port scan across %d decoy IPs", n),
		fmt.Sprintf("[test] The Vedette box simulated a sweep across %d decoy IPs", n), joinMax(ips, 400), "Decoy sweep",
		`Test started by a user selecting "Test scan". Not an attacker.`)
	return s.recordTest(ctx, actor, "honeypot.test_scan", fmt.Sprintf("%d decoys", n), h)
}

// TestToken is POST /honeypot/tokens/{id}/test.
func (s *Service) TestToken(ctx context.Context, actor, id string) (Hit, error) {
	t, err := s.token(ctx, id)
	if err != nil {
		return Hit{}, err
	}
	box, err := s.cfg.Inventory.Box(ctx)
	if err != nil {
		return Hit{}, fmt.Errorf("honeypot: read box: %w", err)
	}
	label := tokenLabel(t.Type) + " " + t.Name
	h := s.testHit(box, KindToken, nil, nil, label, "[test] The Vedette box triggered "+label+" to check it", t.Value, label,
		fmt.Sprintf(`Test started by a user selecting "Test token" for %s. Not an attacker.`, t.Name))
	h.tokenID = t.ID
	return s.recordTest(ctx, actor, "honeypot.test_token", t.Value, h)
}

func tokenLabel(t TokenType) string {
	switch t {
	case TokenFile:
		return "File token"
	case TokenCredential:
		return "Credential token"
	case TokenURL:
		return "URL token"
	}
	return "DNS token"
}

func joinMax(parts []string, n int) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			p = ", " + p
		}
		if len(out)+len(p) > n {
			break
		}
		out += p
	}
	return out
}

// ExportHits is the "honeypot" source of GET /core/logs/export (core INV-13): the hits from through to, oldest first, as JSON
// lines with the columns of hp_hits (events as JSON, conn_count; not conn_key, which only dedupes). The source device is not looked up:
// a download carries what was stored (INV-8). A zero time is open.
func (s *Service) ExportHits(ctx context.Context, from, to time.Time, w io.Writer) error {
	lo, hi := "", ""
	if !from.IsZero() {
		lo = store.FormatTS(from)
	}
	if !to.IsZero() {
		hi = store.FormatTS(to)
	}
	return logexport.Rows{SQL: `SELECT ` + hitCols + `, conn_count FROM hp_hits WHERE (? = '' OR ts >= ?) AND (? = '' OR ts <= ?) ORDER BY ts, id`,
		Args: []any{lo, lo, hi, hi}, JSON: []string{"events"}}.Write(ctx, s.db.Reader(), w)
}
