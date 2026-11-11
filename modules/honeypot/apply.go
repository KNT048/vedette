package honeypot

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/knt048/vedette/core/events"
)

// hostCache is what the last Apply learned: Apply is the only writer, Overview reads it (INV-7: a trap listens only
// when the container is up with a configuration that has it).
type hostCache struct {
	available bool
	running   bool
	reason    string
	services  map[ServiceName]bool // the services of the configuration the container was started with
	// conflicts are the trap addresses that were not handed to the host and why: the core found a problem (a device or
	// the box has the address, it left the LAN, it is past the host's 32) or the host refused it.
	conflicts map[netip.Addr]string
}

// listening reports that the container was started with a configuration that has this service on, on a host that is an
// appliance. It does not mean the port was probed: the box never connects to its own trap (INV-1, FORBID-3).
func (s *Service) listening(svc ServiceName) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host.available && s.host.running && s.host.services[svc]
}

// refused is the reason the last Apply did not hand ip to the host, "" when it did or never tried.
func (s *Service) refused(ip netip.Addr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host.conflicts[ip]
}

// TrapConflicts lists the secondary or decoy addresses the last Apply left out of the host and why (a device or the box
// has the address, it is outside the LAN now, the host refused it or is full). The API has no field for it: the trap
// shows state "conflict" when the secondary IP is among them, the reasons are here and in the log.
func (s *Service) TrapConflicts() map[netip.Addr]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.host.conflicts)
}

// HostStatus says whether the traps can listen and, when they cannot, why. The API has no field for it: a trap that is
// on but cannot listen shows state "off" and the reason is here and in the log.
func (s *Service) HostStatus() (listening bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host.available && s.host.running, s.host.reason
}

// DecoyIPs are the addresses the traps own: the ones handed to the host at the last Apply (the secondary IP and the enabled
// decoys the host accepted). The inventory must not make a device of them (CONTRACT, open question 2: the answers to ARP
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

// desired is what the host should look like, from the database and the inventory (D-55: configuration comes from the
// database, never edited by hand). An address that is the box's own, outside the LAN now, or a device's is left out and
// listed in conflicts (INV-5, INV-6, FORBID-1); so is whatever passes the host's 32 addresses, the secondary IP first.
func (w *world) desired() (ips []netip.Addr, services []ServiceName, conflicts map[netip.Addr]string) {
	conflicts = map[netip.Addr]string{}
	if w.secIP.IsValid() {
		if why := w.ipProblem(w.secIP); why != "" {
			conflicts[w.secIP] = why
		} else {
			for _, svc := range Services {
				if w.traps[svc].enabled {
					services = append(services, svc)
				}
			}
			if len(services) > 0 {
				ips = append(ips, w.secIP)
			}
		}
	}
	if len(services) > 0 {
		for _, d := range w.decoys {
			if !d.Enabled || !d.ip.IsValid() || slices.Contains(ips, d.ip) {
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
		}
	}
	return ips, services, conflicts
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
	nas := false
	for _, d := range w.decoys {
		nas = nas || d.Enabled && d.Personality == NAS
	}
	conf, err := RenderConfig(ConfigInput{Enabled: services, LogPath: filepath.Join(s.cfg.LogDir, defaultLogFile), NASDecoy: nas})
	if err != nil {
		return err
	}
	tok, err := RenderTokens(files)
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
	if !s.on() { // checked under the lock the teardown also holds: an Apply that waited behind a switch-off must not bring the traps back (D-189)
		return nil
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
	placed, refused, err := s.syncIPs(ctx, ips, filesOK)
	if ctx.Err() != nil { // core is stopping: what the host did not answer is not a refusal; change nothing more
		return errors.Join(append(errs, err, ctx.Err())...)
	}
	if err != nil {
		errs = append(errs, err)
	}
	for ip, why := range refused {
		conflicts[ip] = why
		if s.due("refused " + ip.String()) {
			s.cfg.Log.WarnContext(ctx, "honeypot: the host did not take a decoy address; the other traps go on", "ip", ip.String(), "reason", why)
		}
	}
	switch {
	case len(services) == 0 || len(ips) == 0:
		if err := s.cfg.Host.StopContainer(ctx); err != nil {
			errs = append(errs, fmt.Errorf("honeypot: stop container: %w", err))
		}
		s.setHost(hostCache{available: true, reason: "no trap is on", conflicts: conflicts})
	case len(placed) == 0:
		if err := s.cfg.Host.StopContainer(ctx); err != nil {
			errs = append(errs, fmt.Errorf("honeypot: stop container: %w", err))
		}
		s.setHost(hostCache{available: true, reason: "the host did not take any decoy address", conflicts: conflicts})
		errs = append(errs, errors.New("honeypot: the host did not take any decoy address"))
	case !filesOK:
		s.setHost(hostCache{available: true, reason: "the trap configuration could not be written", conflicts: conflicts})
	default:
		if err := s.cfg.Host.StartContainer(ctx); err != nil {
			s.setHost(hostCache{available: true, reason: "the honeypot container did not start", conflicts: conflicts})
			errs = append(errs, fmt.Errorf("honeypot: start container: %w", err))
			break
		}
		m := map[ServiceName]bool{}
		for _, svc := range services {
			m[svc] = true
		}
		s.setHost(hostCache{available: true, running: true, services: m, conflicts: conflicts})
	}
	return errors.Join(errs...)
}

func (s *Service) setHost(h hostCache) {
	s.mu.Lock()
	s.host = h
	s.mu.Unlock()
}

// syncIPs adds the wanted decoy IPs (when add is true), removes the ones handed over earlier that are no longer wanted,
// and remembers the set (hp_config "applied") so a restart can still remove a stale one. An address the host refuses is
// returned in refused with the reason, it does not stop the others; placed is what the host holds of the wanted ones.
// err carries what went wrong besides refusals (a removal, the database).
func (s *Service) syncIPs(ctx context.Context, want []netip.Addr, add bool) (placed []netip.Addr, refused map[netip.Addr]string, err error) {
	var prev []string
	if err := loadJSON(ctx, s.db.Reader(), "applied", &prev); err != nil {
		return nil, nil, err
	}
	have := map[netip.Addr]bool{}
	var errs []error
	refused = map[netip.Addr]string{}
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
		if err := s.cfg.Host.AddDecoyIP(ctx, ip); err != nil {
			refused[ip] = err.Error()
			if ctx.Err() != nil { // unknown whether the host took it: keep it on record and stop asking
				break
			}
			if !wasHeld { // the host said no: it does not hold it
				delete(have, ip)
				save()
			}
			continue
		}
	}
	for ip := range have {
		if !slices.Contains(want, ip) {
			if err := s.cfg.Host.RemoveDecoyIP(ctx, ip); err != nil {
				errs = append(errs, fmt.Errorf("honeypot: remove decoy IP %s: %w", ip, err))
				continue
			}
			delete(have, ip)
		}
	}
	for _, ip := range want {
		if have[ip] {
			placed = append(placed, ip)
		}
	}
	save()
	return placed, refused, errors.Join(errs...)
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
			s.setHost(hostCache{reason: turningOff})
			return errors.New("honeypot: the host is not available and may still hold decoy addresses or the container")
		}
		s.setHost(hostCache{reason: "the module is off"})
		return nil
	}
	var errs []error
	if err := s.cfg.Host.StopContainer(ctx); err != nil {
		errs = append(errs, err)
	}
	_, _, err = s.syncIPs(ctx, nil, false)
	errs = append(errs, err)
	if err := errors.Join(errs...); err != nil {
		s.setHost(hostCache{available: true, reason: turningOff})
		return err
	}
	s.setHost(hostCache{available: true, reason: "the module is off"})
	return nil
}

const turningOff = "the module is turning off: the host has not confirmed yet that the container stopped and the decoy addresses are gone"

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

// Subscribe registers the reactions: a device that appears or changes may now sit on a secondary or decoy IP, so the
// state is applied again (INV-6: the trap becomes conflict and stops listening). Events are hints; the run loop also
// applies every minute.
func (s *Service) Subscribe(bus Bus) (unsubscribe func()) {
	var undo []func()
	for _, name := range []string{"inventory.asset.discovered", "inventory.asset.updated"} {
		undo = append(undo, bus.Subscribe(name, func(context.Context, events.Event) error {
			if s.on() {
				s.Kick()
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
		case <-poll.C:
			if err := s.Poll(ctx); err != nil && ctx.Err() == nil {
				if s.due("poll") {
					s.cfg.Log.WarnContext(ctx, "honeypot: read the trap log", "error", err)
				}
			}
		}
	}
}
