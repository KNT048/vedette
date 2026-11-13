package honeypot

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/knt048/vedette/core/events"
)

// hostCache is what the last Apply learned: Apply is the only writer, Overview reads it (INV-7: a trap listens only
// when the container is up with a configuration that has it and the host confirmed it holds the address).
type hostCache struct {
	available bool
	running   bool
	reason    string
	services  map[ServiceName]bool // the services of the configuration the container was started with
	// conflicts are the trap addresses that were not handed to the host and why: the core found a problem (a device or
	// the box has the address, it left the LAN, it is past the host's 32) or the host refused it.
	conflicts map[netip.Addr]string
	// hostFailed marks the entries of conflicts the host refused for its own failure (ErrHostFailed): no clash, the trap
	// on that address shows "failed".
	hostFailed map[netip.Addr]bool
	// placed are the wanted addresses the host confirmed it holds at the last Apply (it took them now, or took them before
	// and did not refuse them since; an address only on the "applied" record is not confirmed): what the states and the
	// MACs read. links are what the host says of each address it holds: MAC, link, parent card (when the host says).
	placed map[netip.Addr]bool
	links  map[netip.Addr]DecoyLink
	// openPorts: the host cannot keep each address to its own ports (an older vedette-host without decoy_ip.set_ports,
	// host-api §13): every address answers every service that runs, and the Trap IPs say so.
	openPorts bool
}

// portKeeper is the optional part of a Host that says whether it keeps each address to its own ports (D-466); a Host
// without it is taken to keep them.
type portKeeper interface {
	KeepsPorts(ctx context.Context) bool
}

// openPortsNote is the note on a listening Trap IP when the host cannot keep its services apart.
const openPortsNote = "the host program on this box is older and cannot limit each Trap IP to its own services yet: this address answers every service a Trap IP uses until vedette-host is updated"

// refusal is the back-off of one address the host refused: the first refusals are retried at the next Apply, from the
// third on only every refuseBackoff (a host that refuses is not asked, audited and logged each minute; the host takes
// 10 writes a minute, ten failing decoys would use them all).
type refusal struct {
	n         int
	until     time.Time
	err       error
	hostFault bool
}

const (
	refuseFreeTries = 3
	refuseBackoff   = 10 * time.Minute
)

// userReason is the sentence for the screen of a refusal: the host adapter's plain sentence when it has one (the error
// text itself carries code and wrapping for the log), else the text.
func userReason(err error) string {
	var u interface{ UserReason() string }
	if errors.As(err, &u) {
		return u.UserReason()
	}
	return err.Error()
}

// linkReporter is the optional part of a Host that knows how it holds each address: its MAC, link and parent card
// (vedette-host state/net).
type linkReporter interface {
	DecoyLinks(ctx context.Context) map[netip.Addr]DecoyLink
}

// hostView is the host cache with whether a change is still waiting for the host: one consistent read for the overview.
type hostView struct {
	hostCache
	pending bool
}

func (s *Service) hostView() hostView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return hostView{hostCache: s.host, pending: s.kickGen > s.doneGen}
}

// TrapConflicts lists the Trap IP addresses the last Apply left out of the host and why (a device or the box has the
// address, it is outside the LAN now, the host refused it or is full, or could not set it up). The API shows each as the
// state and reason of its Trap IP ("conflict", or "failed" when the host could not set it up); the full list is here and
// in the log.
func (s *Service) TrapConflicts() map[netip.Addr]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.host.conflicts)
}

// HostStatus says whether the traps can listen and, when they cannot, why. The API has no field for it: a trap that is
// on but cannot listen shows state "failed" (Overview.Problem has the reason; it is here and in the log too).
func (s *Service) HostStatus() (listening bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host.available && s.host.running, s.host.reason
}

// DecoyIPs are the addresses the traps own: the ones handed to the host at the last Apply (the enabled Trap IPs the host
// accepted). The inventory must not make a device of them (CONTRACT, open question 2: the answers to ARP
// that the trap itself gives are no device) and the active sensor must not probe them. The set is read from the stored
// "applied" record, so it is right right after a restart too.
func (s *Service) DecoyIPs(ctx context.Context) []netip.Addr {
	out, err := s.DecoyIPsRead(ctx)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "honeypot: read applied addresses", "error", err)
		return nil
	}
	return out
}

// DecoyIPsRead is DecoyIPs that says when the record cannot be read: a caller that must fail closed (response's never-touch list, D-179 (8))
// must not take "unreadable" for "no decoys".
func (s *Service) DecoyIPsRead(ctx context.Context) ([]netip.Addr, error) {
	var applied []string
	if err := loadJSON(ctx, s.db.Reader(), "applied", &applied); err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(applied))
	for _, a := range applied {
		if ip, err := netip.ParseAddr(a); err == nil {
			out = append(out, ip)
		}
	}
	return out, nil
}

// addingFor is how long an address handed to the host counts as "being added" while its MAC is not known yet.
const addingFor = 2 * time.Minute

// ExpectedMACs is, per enabled Trap IP (module on), the MAC its decoy has or will have: the one the host gave it at the last
// Apply, else the one remembered (hp_trap_ips.mac: the host derives it from the address and the vendor), else "" while the
// address is being added and its MAC is not known yet (asked of the host within addingFor). An address with none of these is
// absent. The inventory takes a frame at a Trap IP's address as the box only with no MAC or this one ("" = any while being
// added): any other MAC is a machine on that address (B2 review round 2, H1). Lower case.
func (s *Service) ExpectedMACs(ctx context.Context) map[netip.Addr]string {
	if !s.on() {
		return nil
	}
	tips, err := loadTrapIPs(ctx, s.db.Reader())
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "honeypot: read the Trap IPs", "error", err)
		return nil
	}
	hv := s.hostView()
	now := s.now()
	s.mu.Lock()
	adding := maps.Clone(s.adding)
	s.mu.Unlock()
	out := map[netip.Addr]string{}
	for _, d := range tips {
		if !d.Enabled || !d.ip.IsValid() {
			continue
		}
		switch at, being := adding[d.ip]; {
		case being && now.Sub(at) < addingFor: // being handed over: its MAC may be new, whatever was known before
			out[d.ip] = ""
		case hv.links[d.ip].MAC != "":
			out[d.ip] = strings.ToLower(hv.links[d.ip].MAC)
		case d.mac != "":
			out[d.ip] = d.mac
		}
	}
	return out
}

// TrapIPSince is, per enabled Trap IP (module on), when its address last became a Trap IP that is on (hp_trap_ips.enabled_at):
// a device row the inventory made of it later is a ghost of the decoy (inventory ForgetBoxOwned, B2 review round 2, M1).
func (s *Service) TrapIPSince(ctx context.Context) map[netip.Addr]time.Time {
	if !s.on() {
		return nil
	}
	tips, err := loadTrapIPs(ctx, s.db.Reader())
	if err != nil {
		return nil
	}
	s.mu.Lock()
	on := s.onSince
	s.mu.Unlock()
	out := map[netip.Addr]time.Time{}
	for _, d := range tips {
		if t, err := time.Parse(time.RFC3339Nano, d.enabledAt); err == nil && d.Enabled && d.ip.IsValid() {
			if on.After(t) { // a row made while the module was off is no ghost of a decoy that did not exist
				t = on
			}
			out[d.ip] = t
		}
	}
	return out
}

// TrapIPAddrs are the addresses of the enabled Trap IPs while the module is on, handed to the host or not yet (B2 lab): the
// sensors see such an address before the first Apply hands it over (another machine asking for it, the decoy's link coming up),
// and the inventory must not make a device of it (cmd/vedette adds them to inventory.Config.BoxOwnedIPs with DecoyIPs).
func (s *Service) TrapIPAddrs(ctx context.Context) []netip.Addr {
	if !s.on() {
		return nil
	}
	tips, err := loadTrapIPs(ctx, s.db.Reader())
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "honeypot: read the Trap IPs", "error", err)
		return nil
	}
	var out []netip.Addr
	for _, d := range tips {
		if d.Enabled && d.ip.IsValid() {
			out = append(out, d.ip)
		}
	}
	return out
}

// ghostForgetter is the optional part of the Inventory that deletes the device rows its sensors made of the box's own decoys
// (inventory ForgetBoxOwned, B2 lab): asked at every Apply, before the state is read, with when each Trap IP was switched on (only
// rows first seen after that go), so such a row never holds a Trap IP in conflict.
type ghostForgetter interface {
	ForgetBoxOwned(ctx context.Context, since map[netip.Addr]time.Time) (int, error)
}

// desired is what the host should look like, from the database and the inventory (D-55: configuration comes from the
// database, never edited by hand): the enabled Trap IPs with at least one service, in creation order, and the services of
// all of them (one OpenCanary process runs their union, D-90 (1); the host keeps each address to its own ports, D-466). An
// address that is the box's own, outside the LAN now, or a device's is left out and listed in conflicts (INV-5, INV-6,
// FORBID-1); so is whatever passes the host's 32 addresses, the oldest Trap IPs first.
func (w *world) desired() (ips []netip.Addr, services []ServiceName, conflicts map[netip.Addr]string) {
	conflicts = map[netip.Addr]string{}
	var all []ServiceName
	for _, d := range w.trapIPs {
		if !d.Enabled || !d.ip.IsValid() || len(d.Services) == 0 || slices.Contains(ips, d.ip) {
			continue
		}
		if why := w.ipProblem(d.ip); why != "" {
			conflicts[d.ip] = why
			continue
		}
		if len(ips) >= maxHostIPs {
			conflicts[d.ip] = fmt.Sprintf("the host holds at most %d addresses", maxHostIPs)
			continue
		}
		ips = append(ips, d.ip)
		all = append(all, d.Services...)
	}
	return ips, inOrder(all), conflicts
}

// specs is how the host builds each wanted address (D-466).
func (w *world) specs(ips []netip.Addr) map[netip.Addr]DecoySpec {
	out := make(map[netip.Addr]DecoySpec, len(ips))
	for _, d := range w.trapIPs {
		if slices.Contains(ips, d.ip) {
			out[d.ip] = d.spec()
		}
	}
	return out
}

// trapIPAt is the Trap IP handed to the host at ip, nil when none is.
func (w *world) trapIPAt(ip netip.Addr) *trapIPRow {
	for i := range w.trapIPs {
		if d := &w.trapIPs[i]; d.ip == ip && d.Enabled {
			return d
		}
	}
	return nil
}

// writeFiles renders opencanary.conf and honeytokens.json and writes the ones that differ from what this process wrote
// last. Nothing in ConfigDir is ever read: the container could have left anything there (it mounts the folder read-only
// in the real setup, this is the second line of defence).
func (s *Service) writeFiles(ctx context.Context, w *world, services []ServiceName) error {
	toks, err := s.loadTokens(ctx, s.db.Reader())
	if err != nil {
		return err
	}
	var files []string
	for _, t := range toks {
		if t.Type == TokenFile {
			files = append(files, t.Value)
		}
	}
	// One login page and one share name for the whole box (D-466 (4)): the oldest Trap IP handed to the host decides each.
	smb, http := w.boxWide()
	conf, err := RenderConfig(ConfigInput{Enabled: services, LogPath: filepath.Join(s.cfg.LogDir, defaultLogFile), NASDecoy: http != nil && http.Preset == NAS})
	if err != nil {
		return err
	}
	netbios := ""
	if smb != nil {
		netbios = smb.Name
	}
	tok, err := RenderTokens(files, netbios)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{ConfFile, conf}, {TokensFile, tok}} {
		sum := sha256.Sum256(f.data)
		if old, ok := s.written[f.name]; ok && old == sum {
			continue
		}
		s.restartDue = true // set before the write: a write cut short may still have replaced the file
		if err := writeInRoot(s.cfg.ConfigDir, f.name, f.data); err != nil {
			return err
		}
		s.written[f.name] = sum
	}
	return nil
}

// Apply makes the host match the database: writes opencanary.conf and honeytokens.json (atomically, only when they
// changed), then, if the host is an appliance, hands it the decoy IPs and starts or stops the container. It is
// idempotent and safe to call at any time. The host is reconciled even when the files cannot be written: addresses that
// must go are removed and the container is stopped when nothing may listen (FORBID-1, POST-5); only the starting of
// addresses and of the container waits for a configuration that was written.
func (s *Service) Apply(ctx context.Context) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.Lock()
	gen := s.kickGen
	s.mu.Unlock()
	defer func() { // what was asked before this Apply started is now answered, well or badly
		s.mu.Lock()
		s.doneGen = max(s.doneGen, gen)
		s.mu.Unlock()
	}()
	if !s.on() { // checked under the lock the teardown also holds: an Apply that waited behind a switch-off must not bring the traps back (D-189)
		return nil
	}
	if g, ok := s.cfg.Inventory.(ghostForgetter); ok {
		if n, err := g.ForgetBoxOwned(ctx, s.TrapIPSince(ctx)); err != nil {
			s.cfg.Log.WarnContext(ctx, "honeypot: the inventory could not forget the rows of the box's own decoys", "error", err)
		} else if n > 0 {
			s.cfg.Log.InfoContext(ctx, "honeypot: the inventory forgot device rows made of the box's own decoys", "rows", n)
		}
	}
	w, err := s.load(ctx)
	if err != nil {
		return err
	}
	ips, services, conflicts := w.desired()
	var errs []error
	filesOK := true
	if s.cfg.ConfigDir != "" {
		if err := s.writeFiles(ctx, w, services); err != nil {
			// A write cut short because core is stopping is not a broken config folder: leave the host as it is
			// (a restart of core must not take the traps down).
			if ctx.Err() != nil {
				return errors.Join(err, ctx.Err())
			}
			filesOK = false
			errs = append(errs, err)
		}
	}
	// One time budget for everything this Apply asks of the host: a host that is slow must not keep the run loop from
	// reading the log (Poll runs in the same loop). What the budget cuts off is an unknown outcome, retried next Apply.
	parent := ctx
	ctx, cancelBudget := context.WithTimeout(ctx, hostBudget)
	defer cancelBudget()
	st, err := s.cfg.Host.Status(ctx)
	if err != nil {
		s.setHost(hostCache{reason: "the host does not answer"})
		return errors.Join(append(errs, fmt.Errorf("honeypot: host status: %w", err))...)
	}
	if s.cfg.ConfigDir == "" {
		st = HostStatus{Reason: "the honeypot volume is not configured"}
	}
	if !st.Available {
		reason := st.Reason
		if reason == "" {
			reason = "this machine is not an appliance"
		}
		s.setHost(hostCache{reason: reason, conflicts: conflicts})
		s.cfg.Log.InfoContext(ctx, "honeypot: traps cannot listen", "reason", reason)
		return errors.Join(errs...)
	}
	specs := w.specs(ips)
	ask, backedOff := s.backOff(ips, services, specs)
	keep := slices.Collect(maps.Keys(backedOff))
	placed, confirmed, refused, err := s.syncIPs(ctx, ask, specs, keep, filesOK)
	if parent.Err() != nil { // core is stopping: what the host did not answer is not a refusal; change nothing more
		return errors.Join(append(errs, err, parent.Err())...)
	}
	if err != nil {
		errs = append(errs, err)
	}
	hostFailed := map[netip.Addr]bool{}
	for ip, r := range backedOff { // not asked this time: what it said last time still stands
		conflicts[ip] = userReason(r.err)
		hostFailed[ip] = r.hostFault
	}
	for ip, rerr := range refused {
		conflicts[ip] = userReason(rerr)
		hostFault := errors.Is(rerr, ErrHostFailed)
		if hostFault {
			hostFailed[ip] = true
		}
		s.noteRefused(ip, rerr, hostFault)
		if s.due("refused " + ip.String()) {
			s.cfg.Log.WarnContext(ctx, "honeypot: the host did not take a decoy address; the other traps go on", "ip", ip.String(), "reason", rerr.Error())
		}
	}
	for _, ip := range placed {
		delete(s.refusals, ip)
	}
	// What the host confirmed and its MACs go into the same cache write as the rest, so a reader never sees the new state with the old addresses.
	placedSet, links := s.placedAndLinks(ctx, confirmed)
	if err := s.rememberMACs(ctx, w, links); err != nil {
		errs = append(errs, err)
	}
	open := false
	if k, ok := s.cfg.Host.(portKeeper); ok && len(placed) > 0 {
		open = !k.KeepsPorts(ctx)
	}
	set := func(h hostCache) {
		h.placed, h.links, h.openPorts = placedSet, links, open
		s.setHost(h)
	}
	switch {
	case len(services) == 0 || len(ips) == 0:
		if err := s.cfg.Host.StopContainer(ctx); err != nil {
			errs = append(errs, fmt.Errorf("honeypot: stop container: %w", err))
		}
		set(hostCache{available: true, reason: "no Trap IP is on", conflicts: conflicts, hostFailed: hostFailed})
	case len(placed) == 0:
		if err := s.cfg.Host.StopContainer(ctx); err != nil {
			errs = append(errs, fmt.Errorf("honeypot: stop container: %w", err))
		}
		reason := "the host did not take any Trap IP address"
		switch {
		case !filesOK: // nothing was asked
			reason = "the trap configuration could not be written"
		case len(refused) < len(ask): // not every address asked for was refused: an answer is missing (busy, lost)
			reason = notConfirmed
		}
		set(hostCache{available: true, reason: reason, conflicts: conflicts, hostFailed: hostFailed})
		errs = append(errs, errors.New("honeypot: the host did not take any decoy address"))
	case !filesOK:
		set(hostCache{available: true, reason: "the trap configuration could not be written", conflicts: conflicts, hostFailed: hostFailed})
	default:
		if err := s.cfg.Host.StartContainer(parent, s.restartDue); err != nil { // not the budget: a restart plus its health wait can take 4 minutes, and a cut-off start would restart again next Apply
			set(hostCache{available: true, reason: "the honeypot container did not start", conflicts: conflicts, hostFailed: hostFailed})
			errs = append(errs, fmt.Errorf("honeypot: start container: %w", err))
			break
		}
		s.restartDue = false
		m := map[ServiceName]bool{}
		for _, svc := range services {
			m[svc] = true
		}
		set(hostCache{available: true, running: true, services: m, conflicts: conflicts, hostFailed: hostFailed})
	}
	return errors.Join(errs...)
}

// backOff splits the wanted addresses into the ones to ask the host for now and the ones in back-off (refused before,
// not due yet). A change of what is wanted starts over; an address no longer wanted is forgotten.
func (s *Service) backOff(ips []netip.Addr, services []ServiceName, specs map[netip.Addr]DecoySpec) (ask []netip.Addr, backedOff map[netip.Addr]*refusal) {
	sig := fmt.Sprint(ips, services, specs) // fmt prints maps sorted by key: the same wanted state gives the same text
	if sig != s.sig {
		clear(s.refusals)
		s.sig = sig
	}
	now := s.now()
	for _, ip := range ips {
		if r := s.refusals[ip]; r != nil && now.Before(r.until) {
			if backedOff == nil {
				backedOff = map[netip.Addr]*refusal{}
			}
			backedOff[ip] = r
			continue
		}
		ask = append(ask, ip)
	}
	return ask, backedOff
}

func (s *Service) noteRefused(ip netip.Addr, err error, hostFault bool) {
	if s.refusals == nil {
		s.refusals = map[netip.Addr]*refusal{}
	}
	r := s.refusals[ip]
	if r == nil {
		r = &refusal{}
		s.refusals[ip] = r
	}
	r.n++
	r.err, r.hostFault = err, hostFault
	if r.n >= refuseFreeTries {
		r.until = s.now().Add(refuseBackoff)
	}
}

// placedAndLinks is the set of addresses the host holds and, when the host says, how it holds them, for the overview.
func (s *Service) placedAndLinks(ctx context.Context, placed []netip.Addr) (map[netip.Addr]bool, map[netip.Addr]DecoyLink) {
	var links map[netip.Addr]DecoyLink
	if r, ok := s.cfg.Host.(linkReporter); ok && len(placed) > 0 {
		links = r.DecoyLinks(ctx)
	}
	set := make(map[netip.Addr]bool, len(placed))
	for _, ip := range placed {
		set[ip] = true
	}
	return set, links
}

// rememberMACs keeps, per Trap IP, the last MAC the host gave its address (hp_trap_ips.mac): the host derives it from the address
// and the vendor, so it is the same next time. A device row the inventory made from the decoy's own frames before it knew them
// (B2 lab) carries that MAC; deviceAt ignores it even after the address left the host, so a ghost never holds a Trap IP in conflict.
func (s *Service) rememberMACs(ctx context.Context, w *world, links map[netip.Addr]DecoyLink) error {
	type change struct{ id, mac string }
	var todo []change
	for _, d := range w.trapIPs {
		if l, ok := links[d.ip]; ok && l.MAC != "" && strings.ToLower(l.MAC) != d.mac {
			todo = append(todo, change{d.ID, strings.ToLower(l.MAC)})
		}
	}
	if len(todo) == 0 {
		return nil
	}
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		for _, c := range todo {
			if _, err := tx.ExecContext(ctx, `UPDATE hp_trap_ips SET mac = ? WHERE id = ?`, c.mac, c.id); err != nil {
				return fmt.Errorf("honeypot: remember a decoy MAC: %w", err)
			}
		}
		return nil
	})
}

// markAdding notes that ip is being handed to the host and its MAC may change or not be known yet (ExpectedMACs): unless the
// last Apply confirmed the host holds it with a MAC of the wanted vendor (then the adapter writes nothing). A MAC of another
// vendor means the adapter removes and adds it again, with a new MAC (B2 lab, last run: a stale MAC made the new one a device).
func (s *Service) markAdding(ip netip.Addr, spec DecoySpec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.host.links[ip]; s.host.placed[ip] && l.MAC != "" && macFits(l.MAC, spec.OUI) {
		return
	}
	if s.adding == nil {
		s.adding = map[netip.Addr]time.Time{}
	}
	s.adding[ip] = s.now()
	now := s.now()
	for a, at := range s.adding {
		if now.Sub(at) >= addingFor {
			delete(s.adding, a)
		}
	}
}

func (s *Service) setHost(h hostCache) {
	s.mu.Lock()
	for ip := range s.adding { // the host confirmed it holds it, with the MAC it reports now
		if h.placed[ip] && h.links[ip].MAC != "" {
			delete(s.adding, ip)
		}
	}
	s.host = h
	s.mu.Unlock()
}

// syncIPs adds the wanted decoy IPs (when add is true), removes the ones handed over earlier that are no longer wanted,
// and remembers the set (hp_config "applied") so a restart can still remove a stale one. An address the host refuses is
// returned in refused with the host's error; keep lists wanted addresses that are not asked for now (back-off) and must stay as they are, it does not stop the others.
// placed is what the host may hold of the wanted ones (it decides whether the container runs: one slow answer must not
// stop the traps); confirmed is what it said it holds (it took it now, or confirmed it at the last Apply and has not
// refused it since): only that is "listening" (S-HP-1, #475). err carries what went wrong besides refusals (a removal, the database).
func (s *Service) syncIPs(ctx context.Context, want []netip.Addr, specs map[netip.Addr]DecoySpec, keep []netip.Addr, add bool) (placed, confirmed []netip.Addr, refused map[netip.Addr]error, err error) {
	var prev []string
	if err := loadJSON(ctx, s.db.Reader(), "applied", &prev); err != nil {
		return nil, nil, nil, err
	}
	s.mu.Lock()
	before := s.host.placed // confirmed at the last Apply; setHost always puts a new map, this one is never written again
	s.mu.Unlock()
	took := map[netip.Addr]bool{} // the host said yes this Apply
	have := map[netip.Addr]bool{}
	var errs []error
	refused = map[netip.Addr]error{}
	unknown := map[netip.Addr]bool{} // asked, outcome unknown: on record, not placed, not a conflict
	for _, p := range prev {
		if a, err := netip.ParseAddr(p); err == nil {
			have[a] = true
		}
	}
	// The record is written with a context that a switch-off cannot cancel, and BEFORE the host is asked to add an address:
	// an address the host took while core was being stopped must still be known, so the teardown removes it (M1, D-189).
	saved := slices.Clone(prev)
	save := func() {
		now := make([]string, 0, len(have))
		for ip := range have {
			now = append(now, ip.String())
		}
		sort.Strings(now)
		if slices.Equal(saved, now) {
			return
		}
		wctx := context.WithoutCancel(ctx)
		if err := s.db.Write(wctx, func(tx *sql.Tx) error { return s.saveJSON(wctx, tx, "applied", now, "system") }); err != nil {
			errs = append(errs, err)
			return
		}
		saved = now
	}
	for _, ip := range want {
		if !add { // no configuration was written: nothing new is handed over
			continue
		}
		wasHeld := have[ip]
		if !wasHeld {
			have[ip] = true
			save()
		}
		s.markAdding(ip, specs[ip])
		if err := s.cfg.Host.AddDecoyIP(ctx, ip, specs[ip]); err != nil {
			if ctx.Err() != nil || !errors.Is(err, ErrRefused) {
				// Unknown whether the host took it (cancelled, out of time, busy, an answer lost): keep it on record so
				// the teardown removes it, show no conflict, do not call it placed, and stop asking this Apply (the next
				// one asks again). Treating this as a refusal would forget an address the host may hold (SYS-5).
				// An address the host took at an earlier Apply stays placed: one slow answer must not stop the traps.
				unknown[ip] = !wasHeld
				errs = append(errs, fmt.Errorf("honeypot: decoy IP %s: %w", ip, err))
				break
			}
			refused[ip] = err
			s.mu.Lock()
			delete(s.adding, ip) // the host did not take it (a refused address may well be another machine's: H1)
			s.mu.Unlock()
			if !wasHeld { // the host said no: it does not hold it
				delete(have, ip)
				save()
			}
			continue
		}
		took[ip] = true
	}
	for ip := range have {
		if !slices.Contains(want, ip) && !slices.Contains(keep, ip) { // keep: in back-off, not asked this time and not removed either (no host write)
			if err := s.cfg.Host.RemoveDecoyIP(ctx, ip); err != nil {
				errs = append(errs, fmt.Errorf("honeypot: remove decoy IP %s: %w", ip, err))
				continue
			}
			delete(have, ip)
		}
	}
	for _, ip := range want {
		if have[ip] && !unknown[ip] {
			placed = append(placed, ip)
		}
		if took[ip] || (have[ip] && before[ip] && refused[ip] == nil) {
			confirmed = append(confirmed, ip)
		}
	}
	save()
	return placed, confirmed, refused, errors.Join(errs...)
}

// Disable is what the module does when it is switched off (SYS-5): the container stops, the decoy IPs go, nothing
// listens. The data stays. It is idempotent and safe to repeat; a failure leaves the module saying it is still turning
// off, and core's OffGuard calls EnsureOff again until the host has confirmed (D-189).
func (s *Service) Disable(ctx context.Context) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	return s.disable(ctx)
}

func (s *Service) disable(ctx context.Context) error {
	defer func() { // a later switch-on must read "starting", never the "the module is off" this left behind; the back-off starts over
		s.mu.Lock()
		s.kickGen++
		s.mu.Unlock()
		clear(s.refusals)
		s.sig = ""
	}()
	st, err := s.cfg.Host.Status(ctx)
	if err != nil {
		s.setHost(hostCache{reason: turningOff})
		return err
	}
	if s.cfg.ConfigDir == "" { // nothing was ever started without a configuration folder
		s.setHost(hostCache{reason: "the module is off"})
		return nil
	}
	if !st.Available {
		// A host that is unreachable or rebooting is not a host with nothing on it: say "done" only when the record
		// of what was handed over is empty and the host does not report the container running (H1).
		var applied []string
		if err := loadJSON(ctx, s.db.Reader(), "applied", &applied); err != nil {
			return err
		}
		if len(applied) > 0 || st.Running {
			// The host answered (no error from Status) but cannot run the container, for example its unit is missing:
			// the addresses it was handed can still be removed, and a decoy must not answer forever (M2). Done only when
			// every one is gone and the container is not running.
			var rerr error
			if len(applied) > 0 {
				_, _, _, rerr = s.syncIPs(ctx, nil, nil, nil, false)
			}
			if rerr != nil || st.Running {
				s.setHost(hostCache{reason: turningOff})
				return errors.Join(rerr, errors.New("honeypot: the host is not available and may still hold decoy addresses or the container"))
			}
		}
		s.setHost(hostCache{reason: "the module is off"})
		return nil
	}
	var errs []error
	if err := s.cfg.Host.StopContainer(ctx); err != nil {
		errs = append(errs, err)
	}
	_, _, _, err = s.syncIPs(ctx, nil, nil, nil, false)
	errs = append(errs, err)
	if err := errors.Join(errs...); err != nil {
		s.setHost(hostCache{available: true, reason: turningOff})
		return err
	}
	s.setHost(hostCache{available: true, reason: "the module is off"})
	return nil
}

const turningOff = "the module is turning off: the host has not confirmed yet that the container stopped and the Trap IP addresses are gone"

// EnsureOff is the Teardown core's OffGuard runs while the module is off, at start and after every switch-off, with
// backoff until it returns nil (D-189, SYS-5): a failed teardown or a restart never leaves traps listening. It does
// nothing, and returns nil, if the module is on again.
func (s *Service) EnsureOff(ctx context.Context) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.on() { // checked under the lock: a switch-on between the check and the host calls must not be undone
		return nil
	}
	return s.disable(ctx)
}

// Bus is the part of core/events the module subscribes through.
type Bus interface {
	Subscribe(name string, fn events.Handler) (unsubscribe func())
}

// Subscribe registers the reactions: a device that appears or changes may now sit on a Trap IP, so the
// state is applied again (INV-6: the trap becomes conflict and stops listening). Events are hints; the run loop also
// applies every minute.
func (s *Service) Subscribe(bus Bus) (unsubscribe func()) {
	var undo []func()
	for _, name := range []string{"inventory.asset.discovered", "inventory.asset.updated"} {
		undo = append(undo, bus.Subscribe(name, func(context.Context, events.Event) error {
			if s.on() {
				s.hint()
			}
			return nil
		}))
	}
	return func() {
		for _, u := range undo {
			u()
		}
	}
}

// applyEvery is how often the state is applied again whatever happened.
const applyEvery = time.Minute

// hostBudget is the time one Apply may spend asking the host (its status, the addresses, the container). The loop
// applies every applyEvery; a host that is slower than this is an unknown outcome, retried at the next Apply.
const hostBudget = 2 * time.Minute

// Run is the job of the module: it applies the state, then tails the OpenCanary log until ctx ends (the scheduler
// cancels it when the module is switched off, SYS-5). It returns nil on cancellation.
func (s *Service) Run(ctx context.Context) error {
	defer func() {
		if s.on() { // the process is stopping or the loop failed: the module is still on, the traps stay as they are
			return
		}
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.Disable(dctx); err != nil {
			s.cfg.Log.WarnContext(dctx, "honeypot: switching off", "error", err)
		}
	}()
	s.mu.Lock()
	s.kickGen++ // the module was just switched on: until this Apply answers, the traps are "starting", not the "module is off" of the last run
	s.onSince = s.now()
	s.mu.Unlock()
	if err := s.Apply(ctx); err != nil && ctx.Err() == nil {
		if s.due("apply") {
			s.cfg.Log.WarnContext(ctx, "honeypot: apply", "error", err)
		}
	}
	if err := s.restoreTail(ctx); err != nil {
		if ctx.Err() != nil { // stopped while starting: a clean shutdown, not a failure
			return nil
		}
		return err
	}
	poll := time.NewTicker(s.cfg.PollEvery)
	defer poll.Stop()
	touch := time.NewTicker(touchEvery)
	defer touch.Stop()
	again := time.NewTicker(applyEvery)
	defer again.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.kick:
			if err := s.Apply(ctx); err != nil && ctx.Err() == nil {
				if s.due("apply") {
					s.cfg.Log.WarnContext(ctx, "honeypot: apply", "error", err)
				}
			}
		case <-again.C:
			if err := s.Apply(ctx); err != nil && ctx.Err() == nil {
				if s.due("apply") {
					s.cfg.Log.WarnContext(ctx, "honeypot: apply", "error", err)
				}
			}
		case <-touch.C:
			if err := s.PollTouches(ctx); err != nil && ctx.Err() == nil {
				if s.due("touches") {
					s.cfg.Log.WarnContext(ctx, "honeypot: read the attempts the host recorded", "error", err)
				}
			}
		case <-poll.C:
			if err := s.Poll(ctx); err != nil && ctx.Err() == nil {
				if s.due("poll") {
					s.cfg.Log.WarnContext(ctx, "honeypot: read the trap log", "error", err)
				}
			}
		}
	}
}

// macFits says whether mac carries the vendor prefix ouiHex (six hex digits), or with no vendor is locally administered.
func macFits(mac, ouiHex string) bool {
	h := strings.ReplaceAll(strings.ToLower(mac), ":", "")
	if len(h) != 12 {
		return false
	}
	if ouiHex != "" {
		return h[:6] == strings.ToLower(ouiHex)
	}
	b, err := hex.DecodeString(h[:2])
	return err == nil && b[0]&0x02 != 0
}
