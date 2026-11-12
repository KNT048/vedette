package honeypot

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

const secretPurpose = "hp_token.password"

// maxHostIPs is the limit of the host (host-api 6.6): it holds at most this many decoy addresses, the secondary IP
// among them, so the decoys can be 31 when the secondary IP is set.
const maxHostIPs = 32

func bad(code, msg string) error         { return apierr.New(400, code, msg) }
func conflictErr(code, msg string) error { return apierr.New(409, code, msg) }
func notFound(msg string) error          { return apierr.New(404, apierr.CodeNotFound, msg) }

// who says which IP is being checked; the messages differ (they are the ones of the mock).
type who int

const (
	secondary who = iota
	decoyIP
)

// checkIP applies INV-5 and FORBID-1 to an IP the owner typed: IPv4 without leading zeros, inside the network of the
// box, not its network or broadcast address, not the box, not a device of the inventory.
func checkIP(w *world, raw string, k who) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" && k == secondary {
		return netip.Addr{}, bad("bad_ip", "Enter a secondary IP for the decoy, for example 192.168.10.240. Pick an address no device uses.")
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() || ip.IsUnspecified() {
		if k == secondary {
			return netip.Addr{}, bad("bad_ip", "The secondary IP is not valid. Use the form 192.168.10.240, each number 0 to 255, no leading zeros.")
		}
		return netip.Addr{}, bad("bad_ip", "The decoy IP is not valid. Pick a spare address such as 192.168.10.243.")
	}
	name := "decoy"
	if k == secondary {
		name = "secondary"
	}
	if !w.lan.IsValid() {
		purpose := "the decoys go on"
		if k == secondary {
			purpose = "the box is on"
		}
		return netip.Addr{}, bad("no_lan", "Add your LAN range first (Devices, Scope and sensors), so Vedette knows which network "+purpose+".")
	}
	if !usable(w.lan, ip) {
		return netip.Addr{}, bad("ip_outside_lan", fmt.Sprintf("The %s IP must be inside the box's network (%s), not the network or broadcast address.", name, w.lan))
	}
	if ip == w.box.IP {
		return netip.Addr{}, bad("ip_is_box", "This is the Vedette box's own IP. Pick an unused IP.")
	}
	if d := w.deviceAt(ip); d != nil {
		return netip.Addr{}, conflictErr("ip_in_use", fmt.Sprintf("IP %s belongs to device %s in the inventory. Pick an unused IP.", ip, d.Name))
	}
	return ip, nil
}

func hostnameTaken(w *world, name string) (string, bool) {
	for _, d := range w.devices {
		if d.Hostname != "" && strings.EqualFold(d.Hostname, name) {
			return d.IP.String(), true
		}
	}
	return "", false
}

// SetConfig is PUT /honeypot/config (INV-5, INV-13).
func (s *Service) SetConfig(ctx context.Context, actor, ipRaw, hostname string) (Overview, error) {
	w, err := s.load(ctx)
	if err != nil {
		return Overview{}, err
	}
	// An empty IP removes the decoy IP, only while every trap is off: nothing then listens on it, and the box never turns
	// traps off behind the owner's back (a resource in use cannot be released: AWS Elastic IP, Azure public IP; the Canary
	// console asks to disable a Canary before deleting it). Without an IP set there is nothing to clear.
	clearing := strings.TrimSpace(ipRaw) == "" && w.secIP.IsValid()
	var ip netip.Addr
	if clearing {
		for _, svc := range Services {
			if w.traps[svc].enabled {
				return Overview{}, conflictErr("traps_on", "Turn all traps off before removing the decoy IP.")
			}
		}
	} else if ip, err = checkIP(w, ipRaw, secondary); err != nil {
		return Overview{}, err
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return Overview{}, bad("bad_hostname", "Enter a fake hostname, for example FILESRV-OLD. Pick a name that looks like an old file server in your company.")
	}
	if !validHostname(hostname) {
		return Overview{}, bad("bad_hostname", "The fake hostname may only contain letters, digits and hyphens, up to 15 characters (NetBIOS limit), not all digits, and must not start or end with a hyphen. Example FILESRV-OLD.")
	}
	if at, ok := hostnameTaken(w, hostname); ok {
		return Overview{}, conflictErr("hostname_in_use", fmt.Sprintf("The name %s belongs to device %s in the inventory. Pick another name.", hostname, at))
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		if clearing {
			var cur configRow
			if err := loadJSON(ctx, tx, "config", &cur); err != nil {
				return err
			}
			var on int // checked again where the write is: a trap turned on since the read above must not keep a removed IP
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hp_trap WHERE enabled = 1`).Scan(&on); err != nil {
				return fmt.Errorf("honeypot: check traps: %w", err)
			}
			if on > 0 {
				return conflictErr("traps_on", "Turn all traps off before removing the decoy IP.")
			}
			if err := s.saveJSON(ctx, tx, "config", configRow{Hostname: hostname}, actor); err != nil {
				return err
			}
			return s.auditTx(ctx, tx, actor, "honeypot.config", cur.SecondaryIP, "decoy IP removed, hostname "+hostname)
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM hp_decoys WHERE ip = ?`, ip.String()).Scan(&n); err != nil {
			return fmt.Errorf("honeypot: check decoys: %w", err)
		}
		if n > 0 {
			return conflictErr("ip_in_use", fmt.Sprintf("IP %s is already used by a decoy.", ip))
		}
		var cur configRow
		if err := loadJSON(ctx, tx, "config", &cur); err != nil {
			return err
		}
		if !cur.has() { // the secondary IP is new: it takes one of the host's addresses
			if err := checkHostLimit(ctx, tx, 1); err != nil {
				return err
			}
		}
		if err := s.saveJSON(ctx, tx, "config", configRow{SecondaryIP: ip.String(), Hostname: hostname}, actor); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, actor, "honeypot.config", ip.String(), "decoy hostname "+hostname)
	})
	if err != nil {
		return Overview{}, err
	}
	s.Kick()
	return s.Overview(ctx)
}

// SetTrap is PATCH /honeypot/traps/{service} (INV-6, INV-13).
func (s *Service) SetTrap(ctx context.Context, actor string, svc ServiceName, enabled bool) (Overview, error) {
	if !svc.Valid() {
		return Overview{}, notFound("No trap for this service.")
	}
	w, err := s.load(ctx)
	if err != nil {
		return Overview{}, err
	}
	if enabled {
		if !w.secIP.IsValid() {
			return Overview{}, conflictErr("no_secondary_ip", "Set a secondary IP for the traps before turning one on.")
		}
		if d := w.deviceAt(w.secIP); d != nil {
			return Overview{}, conflictErr("ip_in_use", fmt.Sprintf("The secondary IP %s clashes with device %s. Change the secondary IP before turning a trap on.", w.secIP, d.Name))
		}
		// The box may have taken the address, or the LAN range changed, since the IP was accepted (INV-5, FORBID-1).
		if _, err := checkIP(w, w.secIP.String(), secondary); err != nil {
			return Overview{}, err
		}
	}
	action := "honeypot.trap_disable"
	if enabled {
		action = "honeypot.trap_enable"
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		if enabled {
			var cur configRow // checked where the write is: the decoy IP may have been removed since the read above (INV-6, INV-21)
			if err := loadJSON(ctx, tx, "config", &cur); err != nil {
				return err
			}
			if !cur.has() {
				return conflictErr("no_secondary_ip", "Set a secondary IP for the traps before turning one on.")
			}
			_, err := tx.ExecContext(ctx, `UPDATE hp_trap SET enabled = 1, since = coalesce(since, ?) WHERE service = ?`, store.FormatTS(s.now()), string(svc))
			if err != nil {
				return fmt.Errorf("honeypot: turn trap on: %w", err)
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE hp_trap SET enabled = 0, since = NULL WHERE service = ?`, string(svc)); err != nil {
			return fmt.Errorf("honeypot: turn trap off: %w", err)
		}
		return s.auditTx(ctx, tx, actor, action, svc.Label(), "")
	})
	if err != nil {
		return Overview{}, err
	}
	s.Kick()
	return s.Overview(ctx)
}

// ---- decoys ----

// Decoys is GET /honeypot/decoys.
func (s *Service) Decoys(ctx context.Context) (DecoysResponse, error) {
	w, err := s.load(ctx)
	if err != nil {
		return DecoysResponse{}, err
	}
	out := DecoysResponse{Items: make([]Decoy, 0, len(w.decoys)), Suggestions: suggestions(w.devices), SpareIPs: spareIPs(w), SpareChecked: w.discovered()}
	hv := s.hostView()
	for _, d := range w.decoys {
		out.Items = append(out.Items, w.withState(d, hv))
	}
	return out, nil
}

// AddDecoy is POST /honeypot/decoys (INV-5, INV-13).
func (s *Service) AddDecoy(ctx context.Context, actor string, in DecoyInput) (Decoy, error) {
	if !validPersonality(in.Personality) {
		return Decoy{}, bad("bad_personality", "Choose what the decoy should look like.")
	}
	w, err := s.load(ctx)
	if err != nil {
		return Decoy{}, err
	}
	ip, err := checkIP(w, in.IP, decoyIP)
	if err != nil {
		return Decoy{}, err
	}
	name := strings.TrimSpace(in.Name)
	if !validHostname(name) {
		return Decoy{}, bad("bad_hostname", "The decoy name may only contain letters, digits and hyphens, up to 15 characters, not all digits, and must not start or end with a hyphen. Example PRN-FLOOR2.")
	}
	_, taken := hostnameTaken(w, name)
	for _, d := range w.decoys {
		taken = taken || strings.EqualFold(d.Name, name)
	}
	if taken {
		return Decoy{}, conflictErr("hostname_in_use", fmt.Sprintf("The name %s is already used by a device or another decoy.", name))
	}
	d := Decoy{ID: store.NewID("dec"), Personality: in.Personality, Name: name, IP: ip.String(), Enabled: true, CreatedAt: store.FormatTS(s.now()), Services: personalityServices(in.Personality)}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		// The checks that depend on the stored state run in the transaction that writes, so two requests cannot both pass.
		var cur configRow
		if err := loadJSON(ctx, tx, "config", &cur); err != nil {
			return err
		}
		if cur.SecondaryIP == ip.String() {
			return conflictErr("ip_in_use", fmt.Sprintf("IP %s is already used by another decoy.", ip))
		}
		if err := checkHostLimit(ctx, tx, 1); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO hp_decoys (id, personality, name, ip, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)`,
			d.ID, string(d.Personality), d.Name, d.IP, d.CreatedAt); err != nil {
			if store.IsUniqueViolation(err) {
				return conflictErr("ip_in_use", fmt.Sprintf("IP %s is already used by another decoy.", ip))
			}
			return fmt.Errorf("honeypot: add decoy: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "honeypot.decoy_add", d.IP, string(d.Personality)+" "+d.Name)
	})
	if err != nil {
		return Decoy{}, err
	}
	s.Kick()
	return w.withState(decoyRow{Decoy: d, ip: ip}, s.hostView()), nil
}

// checkHostLimit refuses when adding add more addresses (secondary IP and decoys together) would pass what the host
// holds (host-api 6.6: 32). It reads the stored state through q, a transaction when called before a write.
func checkHostLimit(ctx context.Context, q querier, add int) error {
	var cfg configRow
	if err := loadJSON(ctx, q, "config", &cfg); err != nil {
		return err
	}
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM hp_decoys`).Scan(&n); err != nil {
		return fmt.Errorf("honeypot: count decoys: %w", err)
	}
	if cfg.has() {
		n++
	}
	if n+add > maxHostIPs {
		return conflictErr("limit_reached", fmt.Sprintf("The box can hold %d addresses for traps, the secondary IP included. Delete a decoy before adding another.", maxHostIPs))
	}
	return nil
}

// withState puts what the host says on a decoy: listening only when the container runs with a trap on and the host holds the
// address, not because the switch is on. Reasons are plain sentences for the screen.
func (w *world) withState(d decoyRow, hv hostView) Decoy {
	out := d.Decoy
	set := func(state, reason string) Decoy {
		out.State = state
		if reason != "" {
			out.Reason = ptr(reason)
		}
		return out
	}
	if m := hv.macs[d.ip]; m != "" && hv.placed[d.ip] {
		out.MAC = ptr(m)
	}
	anyTrap := false
	for _, t := range w.traps {
		anyTrap = anyTrap || t.enabled
	}
	secWhy, secFault := hv.conflicts[w.secIP], hv.hostFailed[w.secIP]
	secProblem := w.secIP.IsValid() && w.ipProblem(w.secIP) != ""
	switch why, hostFault := hv.conflicts[d.ip], hv.hostFailed[d.ip]; {
	case !d.Enabled:
		if hv.pending && hv.placed[d.ip] {
			return set(StateStopping, "")
		}
		return set(StateOff, "")
	case !anyTrap:
		if hv.pending && hv.placed[d.ip] { // the last trap was just turned off: the host still holds the address
			return set(StateStopping, "")
		}
		return set(StateOff, "No trap is on, so nothing listens on this address.")
	case !w.secIP.IsValid():
		return set(StateOff, "No decoy IP is set, so no trap listens.")
	case secProblem || (secWhy != "" && !secFault):
		return set(StateConflict, "The decoy IP cannot be used, so no trap listens: "+cmp.Or(w.ipProblem(w.secIP), secWhy))
	case secWhy != "":
		return set(StateFailed, "The box could not set up the decoy IP: "+secWhy)
	case w.ipProblem(d.ip) != "":
		return set(StateConflict, w.ipProblem(d.ip))
	case why != "" && hostFault:
		return set(StateFailed, why)
	case why != "":
		return set(StateConflict, why)
	case hv.available && hv.running && hv.placed[d.ip]:
		return set(StateListening, "")
	case hv.pending:
		return set(StateStarting, "")
	default:
		return set(StateFailed, reasonOrDefault(hv.reason))
	}
}

// SetDecoyEnabled is PATCH /honeypot/decoys/{id}.
func (s *Service) SetDecoyEnabled(ctx context.Context, actor, id string, enabled bool) (Decoy, error) {
	action := "honeypot.decoy_disable"
	if enabled {
		action = "honeypot.decoy_enable"
	}
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var ip string
		err := tx.QueryRowContext(ctx, `UPDATE hp_decoys SET enabled = ? WHERE id = ? RETURNING ip`, enabled, id).Scan(&ip)
		if errors.Is(err, sql.ErrNoRows) {
			return notFound("No such decoy.")
		}
		if err != nil {
			return fmt.Errorf("honeypot: update decoy: %w", err)
		}
		return s.auditTx(ctx, tx, actor, action, ip, "")
	})
	if err != nil {
		return Decoy{}, err
	}
	s.Kick()
	rows, err := loadDecoys(ctx, s.db.Reader())
	if err != nil {
		return Decoy{}, err
	}
	w, err := s.load(ctx)
	if err != nil {
		return Decoy{}, err
	}
	for _, d := range rows {
		if d.ID == id {
			return w.withState(d, s.hostView()), nil
		}
	}
	return Decoy{}, notFound("No such decoy.")
}

// DeleteDecoy is DELETE /honeypot/decoys/{id}: the IP stops listening (POST-5), old hits stay.
func (s *Service) DeleteDecoy(ctx context.Context, actor, id string) error {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var ip, name string
		err := tx.QueryRowContext(ctx, `DELETE FROM hp_decoys WHERE id = ? RETURNING ip, name`, id).Scan(&ip, &name)
		if errors.Is(err, sql.ErrNoRows) {
			return notFound("No such decoy.")
		}
		if err != nil {
			return fmt.Errorf("honeypot: delete decoy: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "honeypot.decoy_delete", ip, name)
	})
	if err == nil {
		s.Kick()
	}
	return err
}

// ---- tokens ----

func randText(n int, alphabet string) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("honeypot: random: %w", err)
	}
	out := make([]byte, n)
	for i, x := range b {
		out[i] = alphabet[int(x)%len(alphabet)]
	}
	return string(out), nil
}

const (
	letters = "abcdefghijklmnopqrstuvwxyz"
	lower   = "abcdefghijklmnopqrstuvwxyz0123456789"
	upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

type tokenRow struct {
	Token
	secretID string
}

func (s *Service) loadTokens(ctx context.Context, q querier) ([]tokenRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT t.id, t.type, t.name, t.value, t.secret_id, t.plant_at, t.created_at,
		(SELECT max(ts) FROM hp_hits h WHERE h.token_id = t.id),
		(SELECT count(*) FROM hp_hits h WHERE h.token_id = t.id AND h.is_test = 0)
		FROM hp_tokens t ORDER BY t.created_at DESC, t.id`)
	if err != nil {
		return nil, fmt.Errorf("honeypot: read tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []tokenRow
	for rows.Next() {
		var t tokenRow
		var sec, last sql.NullString
		if err := rows.Scan(&t.ID, &t.Type, &t.Name, &t.Value, &sec, &t.PlantAt, &t.CreatedAt, &last, &t.Triggers); err != nil {
			return nil, fmt.Errorf("honeypot: read tokens: %w", err)
		}
		t.secretID = sec.String
		if last.Valid {
			t.LastTriggeredAt = ptr(last.String)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Tokens is GET /honeypot/tokens; the bait password of a credential token is opened here (INV-10).
func (s *Service) Tokens(ctx context.Context) ([]Token, error) {
	rows, err := s.loadTokens(ctx, s.db.Reader())
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(rows))
	for _, r := range rows {
		t := r.Token
		if r.secretID != "" {
			pw, err := s.cfg.Secrets.Open(ctx, s.db.Reader(), r.secretID, secretPurpose)
			if err != nil { // one stored secret that cannot be opened (wrong key, damaged row) must not hide the other tokens
				s.cfg.Log.ErrorContext(ctx, "honeypot: open bait password", "token", r.ID, "error", err)
			} else {
				t.Password = ptr(string(pw))
			}
		}
		out = append(out, t)
	}
	return out, nil
}

// MaskTokens returns l with every bait password hidden except its last 4 characters (D-189, L14): what a viewer sees.
// A password shorter than 8 characters shows no tail at all (the rule of secrets.Value.Last4). The input is not changed.
func MaskTokens(l []Token) []Token {
	out := make([]Token, len(l))
	for i, t := range l {
		out[i] = t
		if t.Password != nil {
			out[i].Password = ptr(maskPassword(*t.Password))
		}
	}
	return out
}

func maskPassword(pw string) string {
	r := []rune(pw)
	if len(r) < 8 {
		return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
	}
	return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" + string(r[len(r)-4:])
}

func (s *Service) token(ctx context.Context, id string) (Token, error) {
	all, err := s.Tokens(ctx)
	if err != nil {
		return Token{}, err
	}
	for _, t := range all {
		if t.ID == id {
			return t, nil
		}
	}
	return Token{}, notFound("No such token.")
}

// AddToken is POST /honeypot/tokens (INV-10, POST-4, INV-13).
func (s *Service) AddToken(ctx context.Context, actor string, in TokenInput) (Token, error) {
	switch in.Type {
	case TokenFile, TokenCredential, TokenURL, TokenDNS:
	default:
		return Token{}, bad("bad_type", "Choose a token type: decoy file, fake credentials, URL or DNS name.")
	}
	name := strings.TrimSpace(in.Name)
	plant := strings.TrimSpace(in.PlantAt)
	if r := []rune(plant); len(r) > 120 {
		plant = strings.TrimSpace(string(r[:120]))
	}
	if !tokenNameRE.MatchString(name) {
		return Token{}, bad("bad_name", "The name may only contain letters without accents, digits, spaces, hyphens, dots or underscores, start with a letter or digit, and be at most 64 characters. Example: Payroll-2026-Q4.")
	}
	if plant == "" {
		return Token{}, bad("bad_plant_at", `Say where you will plant it, for example \\SRV-FILE\HR or "Password manager". This reminds you where to look when it fires.`)
	}
	if in.Type == TokenFile && in.Ext != "docx" && in.Ext != "xlsx" {
		return Token{}, bad("bad_ext", "Choose the file type: .docx or .xlsx.")
	}
	rnd, err := randText(10, lower)
	if err != nil {
		return Token{}, err
	}
	var value, password string
	switch in.Type {
	case TokenFile:
		value = strings.Join(strings.Fields(name), "-") + "." + in.Ext
	case TokenCredential:
		// The bait account is a generated, plausible service account (svc_ plus six letters), never the display name of the
		// token and never a common one like admin: ordinary brute force does not fire it, only a stolen list does (D-90 (3)).
		acct, err := randText(6, letters)
		if err != nil {
			return Token{}, err
		}
		value = "svc_" + acct
		a, err1 := randText(4, lower)
		b, err2 := randText(6, upper)
		if err := errors.Join(err1, err2); err != nil {
			return Token{}, err
		}
		password = "Bk!" + a + "-" + b + "x9"
	case TokenURL:
		box, err := s.cfg.Inventory.Box(ctx)
		if err != nil {
			return Token{}, fmt.Errorf("honeypot: read box: %w", err)
		}
		value = "https://" + box.Name + ":8443/t/" + rnd
	case TokenDNS:
		sl := slug(name)
		if sl == "" {
			sl = "token"
		}
		value = sl[:min(20, len(sl))] + "-" + rnd[:4] + ".vedette.internal"
	}
	t := Token{ID: store.NewID("tok"), Type: in.Type, Name: name, Value: value, PlantAt: plant, CreatedAt: store.FormatTS(s.now())}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		var secretID any
		if in.Type == TokenCredential {
			id, _, err := s.cfg.Secrets.Seal(ctx, tx, secretPurpose, []byte(password), false)
			if err != nil {
				return fmt.Errorf("honeypot: seal bait password: %w", err)
			}
			secretID = id
			t.Password = ptr(password)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO hp_tokens (id, type, name, value, secret_id, plant_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			t.ID, string(t.Type), t.Name, t.Value, secretID, t.PlantAt, t.CreatedAt); err != nil {
			if store.IsUniqueViolation(err) {
				return conflictErr("duplicate", "A token of this type with this name already exists.")
			}
			return fmt.Errorf("honeypot: add token: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "honeypot.token_add", t.Value, string(t.Type))
	})
	if err != nil {
		return Token{}, err
	}
	if t.Type == TokenFile {
		s.Kick() // the share needs the new file name
	}
	return t, nil
}

// DeleteToken is DELETE /honeypot/tokens/{id}: the planted copy stops alerting (INV-10, POST-5), old hits stay.
func (s *Service) DeleteToken(ctx context.Context, actor, id string) error {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var value, typ string
		var sec sql.NullString
		err := tx.QueryRowContext(ctx, `DELETE FROM hp_tokens WHERE id = ? RETURNING value, type, secret_id`, id).Scan(&value, &typ, &sec)
		if errors.Is(err, sql.ErrNoRows) {
			return notFound("No such token.")
		}
		if err != nil {
			return fmt.Errorf("honeypot: delete token: %w", err)
		}
		if sec.Valid {
			if err := s.cfg.Secrets.Delete(ctx, tx, sec.String); err != nil {
				return fmt.Errorf("honeypot: delete bait password: %w", err)
			}
		}
		return s.auditTx(ctx, tx, actor, "honeypot.token_delete", value, typ)
	})
	if err == nil {
		s.Kick()
	}
	return err
}
