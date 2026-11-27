package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// The inventory is what sensors and agents write to, through core/observe (they do not import this package).
var (
	_ observe.Sink         = (*Service)(nil)
	_ observe.SoftwareSink = (*Service)(nil)
)

const maxBatch = 5000

// maxObsPerSeries is how many observation rows one (device, field, source) keeps: Record deletes the older ones in the
// same transaction (INV-16), so one MAC that keeps changing a value cannot grow the table without limit.
const maxObsPerSeries = 32

// maxClockSkew is how far into the future a sensor's clock may be before its time is replaced by ours.
const maxClockSkew = 5 * time.Minute

// LearningWindow is how long a source learns the network after its first report to this box: a device it finds meanwhile is
// announced with AssetEvent.Learning, like Darktrace's and Zeek's learning periods, so notify folds the first sweep into one summary.
const LearningWindow = 36 * time.Hour

// learning records the source's first contact with this box (inv_source, written once) and reports whether that was less than
// LearningWindow ago, by the box's clock. It runs in the transaction of the report, so a refused report leaves no contact. The time only
// ever moves back: a first contact stored while the clock was ahead (#721) becomes now once the clock is corrected, so the
// window is never longer than LearningWindow of the corrected clock.
func (s *Service) learning(ctx context.Context, tx *sql.Tx, source string) (bool, error) {
	now := s.clock()
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_source (source, first_seen) VALUES (?, ?) ON CONFLICT (source) DO NOTHING`, source, store.FormatTS(now)); err != nil {
		return false, fmt.Errorf("inventory: record the source's first contact: %w", err)
	}
	var first string
	if err := tx.QueryRowContext(ctx, `SELECT first_seen FROM inv_source WHERE source = ?`, source).Scan(&first); err != nil {
		return false, fmt.Errorf("inventory: read the source's first contact: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, first)
	if err != nil {
		return false, fmt.Errorf("inventory: read the source's first contact: %w", err)
	}
	if now.Before(t) {
		if _, err := tx.ExecContext(ctx, `UPDATE inv_source SET first_seen = ? WHERE source = ?`, store.FormatTS(now), source); err != nil {
			return false, fmt.Errorf("inventory: correct the source's first contact: %w", err)
		}
		t = now
	}
	return now.Sub(t) < LearningWindow, nil
}

// RecordObservation stores one observation (PRE-1, POST-1). It is Record with a batch of one.
func (s *Service) RecordObservation(ctx context.Context, o observe.Observation) error {
	return s.Record(ctx, []observe.Observation{o})
}

// cleanObs is an observation that passed the boundary check.
type cleanObs struct {
	ip    netip.Addr
	mac   string     // hint, normalised, may be ""
	agent string     // hint: the agent that reports (agent source only), may be ""
	from  netip.Addr // hint: where an agent-only report came from (AssetHint.From, #829); judges keyHit's binding, nothing else
	// device: the id of the device an SNMP read of its own read address is about (AssetHint.Device): it goes there or nowhere.
	device string
	list   bool // a list (software, services: deviceFor), not an observation: at a stale address it makes no device
	// keyless: a list of an agent with no key and no card (Wazuh, by address): admit checks it at a removed device's last address
	keyless bool
	// agentMACs are the MACs the agent reports in this batch (its mac observations); bindAgent checks the device against them.
	agentMACs []string
	// claims are the cards this hint names in the batch: its MAC and the values of the batch's mac observations with the same hint
	// (Wazuh and an agent by address report their card as a value). The removal check reads them (admit).
	claims []string
	// own: an agent's report by address only at a hand-added address another MAC was seen at (handClaims): a device of its own, never
	// the hand-added one. card is the card it claims there, which may reach only the newcomer a sensor saw (ownDevice), never a lookup key.
	own    bool
	card   string
	field  string
	value  string
	source string
	conf   float64
	seenAt string
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// checkHint validates the device hint: a MAC, an IPv4 address or an agent, at least one (the agent is checked by checkAgent). A
// device hint (AssetHint.Device) is refused here: only Record takes one (checkDevice), so a list sink or an enrolment never makes a
// device from it.
func checkHint(h observe.AssetHint) (ip netip.Addr, mac string, err error) {
	if h.Device != "" {
		return ip, "", invalid("hint: a device hint is only for SNMP observations")
	}
	if h.MAC != "" {
		m, ok := normMAC(h.MAC)
		if !ok {
			return ip, "", invalid("hint: not a MAC address")
		}
		mac = m
	}
	if h.IP.IsValid() {
		ip = h.IP.Unmap()
		if !ip.Is4() {
			return ip, "", invalid("hint: only IPv4 addresses are supported")
		}
	}
	if mac == "" && !ip.IsValid() && h.Agent == "" {
		return ip, "", invalid("hint: a MAC or an IP is required")
	}
	return ip, mac, nil
}

// checkDevice validates AssetHint.Device: only an SNMP observation names a device, and then nothing else.
func checkDevice(h observe.AssetHint, source observe.Source) (string, error) {
	if h.Device == "" {
		return "", nil
	}
	if source != observe.SNMP || h.IP.IsValid() || h.MAC != "" || h.Agent != "" || h.From.IsValid() || len(h.Device) > 64 || !cleanText(h.Device) {
		return "", invalid("hint: only an SNMP read names a device, and alone")
	}
	return h.Device, nil
}

// checkFrom validates AssetHint.From: an IPv4 address, only on an agent's hint that names no address (#829).
func checkFrom(h observe.AssetHint) (netip.Addr, error) {
	if !h.From.IsValid() {
		return netip.Addr{}, nil
	}
	from := h.From.Unmap()
	if h.Agent == "" || h.IP.IsValid() || !from.Is4() {
		return netip.Addr{}, invalid("hint: From is an IPv4 address, only on an agent's hint without an IP")
	}
	return from, nil
}

func (s *Service) seen(t time.Time) string {
	now := s.clock()
	if t.IsZero() || t.After(now.Add(maxClockSkew)) {
		t = now
	}
	return store.FormatTS(t)
}

// checkAgent validates the agent of a hint: only an agent's report names one, in the shape core/observe gives it.
func checkAgent(h observe.AssetHint, source observe.Source) (string, error) {
	if h.Agent == "" {
		return "", nil
	}
	if source != observe.Agent || !observe.ValidAgentKey(h.Agent) {
		return "", invalid("hint: only an agent's report names an agent, as kind:id")
	}
	return h.Agent, nil
}

// check validates a batch before any write (SYS-2, SYS-6): the data comes from the network. "manual" is
// refused: only a person in the interface may claim the top rank.
func (s *Service) check(batch []observe.Observation) ([]cleanObs, error) {
	if len(batch) > maxBatch {
		return nil, invalid("a batch has at most %d observations", maxBatch)
	}
	out := make([]cleanObs, 0, len(batch))
	for i, o := range batch {
		c, err := s.checkOne(i, o)
		if err != nil {
			return nil, &observe.ErrRejected{Index: i, Err: err} // the caller may drop this item and send the rest
		}
		out = append(out, c)
	}
	return out, nil
}

// checkOne validates observation i of a batch.
func (s *Service) checkOne(i int, o observe.Observation) (cleanObs, error) {
	var ip netip.Addr
	var mac string
	var err error
	if o.AssetHint.Device == "" { // a device hint stands alone: checkDevice below
		if ip, mac, err = checkHint(o.AssetHint); err != nil {
			return cleanObs{}, fmt.Errorf("observation %d: %w", i, err)
		}
	}
	if !observe.ValidSource(o.Source) || o.Source == observe.Manual {
		return cleanObs{}, invalid("observation %d: source %q is not allowed", i, o.Source)
	}
	agent, err := checkAgent(o.AssetHint, o.Source)
	if err != nil {
		return cleanObs{}, fmt.Errorf("observation %d: %w", i, err)
	}
	from, err := checkFrom(o.AssetHint)
	if err != nil {
		return cleanObs{}, fmt.Errorf("observation %d: %w", i, err)
	}
	device, err := checkDevice(o.AssetHint, o.Source)
	if err != nil {
		return cleanObs{}, fmt.Errorf("observation %d: %w", i, err)
	}
	if device != "" && o.Field == observe.MAC { // a read address answers for the device, not for a card of it
		return cleanObs{}, invalid("observation %d: a device hint carries no MAC", i)
	}
	if !observe.ValidField(o.Field) {
		return cleanObs{}, invalid("observation %d: field %q is unknown", i, o.Field)
	}
	if math.IsNaN(o.Confidence) || o.Confidence < 0 || o.Confidence > 1 {
		return cleanObs{}, invalid("observation %d: confidence must be between 0 and 1", i)
	}
	value := o.Value
	switch o.Field {
	case observe.MAC:
		m, ok := normMAC(value)
		if !ok {
			return cleanObs{}, invalid("observation %d: value is not a MAC address", i)
		}
		value = m
	case observe.Kind:
		if !validKind(value) {
			return cleanObs{}, invalid("observation %d: unknown device type", i)
		}
	default:
		value = stripIgnorable(value)
		if !cleanText(value) {
			return cleanObs{}, invalid("observation %d: value must be 1 to %d printable characters", i, maxObsValue)
		}
	}
	return cleanObs{ip: ip, mac: mac, agent: agent, from: from, device: device, field: string(o.Field), value: value, source: string(o.Source), conf: o.Confidence, seenAt: s.seen(o.SeenAt)}, nil
}

// Record implements observe.Sink: the whole batch in one transaction (all or none). A device is found by the agent bound to it, then
// by MAC, then by IP; one that matches nothing is created unapproved (INV-9, POST-1). Rows that turn out to be one device are joined
// (joinSame).
func (s *Service) Record(ctx context.Context, batch []observe.Observation) error {
	clean, err := s.check(batch)
	if err != nil {
		return err
	}
	// An address the box itself answers on (a decoy of the honeypot) is no device: what the sensors see there is the box, unless a
	// foreign MAC says another machine took the address (ownedFilter).
	if isBox := s.ownedFilter(ctx); isBox != nil {
		clean = slices.DeleteFunc(clean, func(c cleanObs) bool {
			if isBox(c.ip, c.mac) {
				s.ownedHit.Add(1)
				return true
			}
			return false
		})
	}
	if len(clean) == 0 {
		return nil
	}
	// What names an address goes first (#829, C1): the passive sensor queues a MAC's vendor (a MAC-only hint) before the ARP that
	// pairs the MAC with its address, and a MAC-only hint that matches nothing makes a device, so the address's own device (a
	// hand-added one waiting for its MAC) was never found. The order inside one batch says nothing else.
	slices.SortStableFunc(clean, func(a, b cleanObs) int {
		switch {
		case a.ip.IsValid() == b.ip.IsValid():
			return 0
		case a.ip.IsValid():
			return -1
		}
		return 1
	})
	reported := map[string][]string{} // agent → the MACs it reports in this batch
	for _, c := range clean {
		if c.agent != "" && c.field == string(observe.MAC) && !slices.Contains(reported[c.agent], c.value) {
			reported[c.agent] = append(reported[c.agent], c.value)
		}
	}
	claimed := map[string][]string{} // hint → the cards it names in this batch
	for _, c := range clean {
		k := c.hintKey()
		cards := []string{c.mac}
		if c.field == string(observe.MAC) {
			cards = append(cards, c.value)
		}
		for _, m := range cards {
			if m != "" && !slices.Contains(claimed[k], m) {
				claimed[k] = append(claimed[k], m)
			}
		}
	}
	for i := range clean {
		if clean[i].agent != "" {
			clean[i].agentMACs = reported[clean[i].agent]
		}
		clean[i].claims = claimed[clean[i].hintKey()]
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		if err := handClaims(ctx, tx, clean); err != nil {
			return err
		}
		notify, err := notifyNew(ctx, tx)
		if err != nil {
			return err
		}
		learn := map[string]bool{} // source → still learning; every source of the batch has made contact
		for _, c := range clean {
			if _, ok := learn[c.source]; !ok {
				if learn[c.source], err = s.learning(ctx, tx, c.source); err != nil {
					return err
				}
			}
		}
		created := map[string]string{}   // device → the source whose observation created it
		ownAt := map[netip.Addr]string{} // address → the device of its own an agent's report there resolved to (handClaims)
		touched := []string{}
		evidence := map[string]bool{}  // devices an observation found by its MAC, address or agent: only those run the join rules
		before := map[string]string{}  // what the findings matcher reads of each device (matchView), before the batch
		binds := map[string]cleanObs{} // device → an observation of the agent that reported on it
		for _, c := range clean {
			if c.source != string(observe.Agent) {
				about, err := aboutBox(ctx, tx, c)
				if err != nil {
					return err
				}
				if about { // only an agent describes the box; a sensor's view of its MAC or address is not the box
					continue
				}
			}
			var id string
			var isNew bool
			if id = ownAt[c.ip]; !c.own || id == "" { // one report, one device of its own (handClaims)
				if id, isNew, err = s.resolve(ctx, tx, o, c); err != nil {
					return err
				}
				if c.own {
					ownAt[c.ip] = id
				}
			}
			if id == "" { // no device may take it (resolve: an agent-only report of an unbound agent, an address not confirmed lately)
				continue
			}
			if c.source == string(observe.Agent) && !isNew {
				off, err := agentRefused(ctx, tx, id)
				if err != nil {
					return err
				}
				if off { // a person turned the agent off for this device (ChangeSources): nothing of it is taken
					continue
				}
			}
			if isNew {
				created[id] = c.source
				if err := s.auditTx(ctx, tx, systemActor, "inventory.discover", c.target(), id); err != nil {
					return err
				}
			}
			if c.device == "" {
				evidence[id] = true
			}
			if !slices.Contains(touched, id) {
				touched = append(touched, id)
				if before[id], err = matchView(ctx, tx, id); err != nil {
					return err
				}
			}
			if err := insertPruned(ctx, tx, id, c.field, c.value, c.source, c.conf, c.seenAt); err != nil {
				return err
			}
			if c.mac != "" && c.field != "mac" { // the MAC that found the device is itself an observation
				if err := insertPruned(ctx, tx, id, "mac", c.mac, c.source, c.conf, c.seenAt); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET last_seen = max(last_seen, ?) WHERE id = ?`, c.seenAt, id); err != nil {
				return fmt.Errorf("inventory: touch device: %w", err)
			}
			if c.agent != "" {
				binds[id] = c
			}
		}
		for id, c := range binds { // after the batch's own mac observations are in
			if err := bindAgent(ctx, tx, id, c.agent, c.agentMACs); err != nil {
				return err
			}
		}
		// A read of a device's own read address (AssetHint.Device) says nothing about which row is which machine: it never joins.
		gone, joined, err := s.joinSame(ctx, tx, o, slices.DeleteFunc(slices.Clone(touched), func(id string) bool { return !evidence[id] }), created, before)
		if err != nil {
			return err
		}
		for _, id := range joined {
			if !slices.Contains(touched, id) {
				touched = append(touched, id)
			}
		}
		for _, id := range touched {
			if gone[id] {
				continue
			}
			changed, err := s.RecomputeAsset(ctx, tx, id)
			if err != nil {
				return err
			}
			after, err := matchView(ctx, tx, id)
			if err != nil {
				return err
			}
			match := after != before[id] || slices.Contains(joined, id) // findings matches the device again only when its OS or model changed; or another device joined it
			switch {
			case created[id] != "":
				quiet, err := isQuiet(ctx, tx, id) // a rotating private address is announced only once it earns a look (INV-49)
				if err != nil {
					return err
				}
				o.add(EventAssetDiscovered, AssetEvent{AssetID: id, Notify: notify && !quiet, Match: match, Learning: learn[created[id]]})
			case changed || match:
				o.add(EventAssetUpdated, AssetEvent{AssetID: id, Match: match})
			}
			if created[id] == "" { // a stay past a day, also of the device a fold kept (INV-49)
				if err := s.earnReview(ctx, tx, o, id, false); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// aboutBox reports whether the observation names the MAC or the address of the box device.
func aboutBox(ctx context.Context, tx *sql.Tx, c cleanObs) (bool, error) {
	var n int
	ip := ""
	if c.ip.IsValid() {
		ip = c.ip.String()
	}
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_asset WHERE is_box = 1 AND ((? <> '' AND mac = ?) OR (? <> '' AND ip = ?))`,
		c.mac, c.mac, ip, ip).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("inventory: check the box: %w", err)
	}
	return n > 0, nil
}

var (
	_ observe.Approver      = (*Service)(nil)
	_ observe.AgentReleaser = (*Service)(nil)
	_ observe.AgentDevices  = (*Service)(nil)
)

// ApproveEnrolled implements observe.Approver (S-INV-4): the device an osquery agent reports on is approved by the enrolment,
// because an admin made the token and ran the install. The device is found as Record finds it (MAC, then IP) and never created here;
// an address the box answers on is no device (ownedFilter, as in Record). The row must be this machine's: it is approved only when no
// source ever saw it with a MAC other than nodeMAC (the agent's card on that address). An address DHCP gave to a new machine still
// resolves to the old machine's row until a sensor sees the move, and the agent's own MAC observation has by then made nodeMAC the
// row's MAC (the newest MAC), so the column alone proves nothing: the old MAC's observations do. Such a row is found but
// left waiting for a person, with a log line. A device a person marked suspicious or ignored keeps waiting (a person's flag wins); the box and
// an approved device are left as they are. One audit row inventory.approve_enrolled by "system", reason naming the token and its
// maker, only when the flag changes. On the same row (not the box, not one seen with another MAC) an agent OS stored with no agent kind
// gives the device its kind (typeFromAgentOS), approved or not: a node enrolled before agents sent a kind is typed without a new report.
// With agentSaw (a caller not answering a live report: agent-intake's approve-enrolled job) a row counts as found only when it holds an
// agent mac observation equal to nodeMAC; any other row is "not found" and left as it is.
func (s *Service) ApproveEnrolled(ctx context.Context, hint observe.AssetHint, nodeMAC, reason string, agentSaw bool) (bool, error) {
	ip, mac, err := checkHint(hint)
	if err != nil {
		return false, err
	}
	agent, err := checkAgent(hint, observe.Agent)
	if err != nil {
		return false, err
	}
	if isBox := s.ownedFilter(ctx); isBox != nil && isBox(ip, mac) {
		s.ownedHit.Add(1)
		return false, nil
	}
	if nodeMAC != "" {
		m, ok := normMAC(nodeMAC)
		if !ok {
			return false, invalid("enrolment: not a MAC address")
		}
		nodeMAC = m
	}
	ipS := ""
	if ip.IsValid() {
		ipS = ip.String()
	}
	found := false
	err = s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var id string
		// the main address first, then the device's other addresses (INV-57)
		err := tx.QueryRowContext(ctx, `SELECT id FROM (SELECT id, (?1 <> '' AND agent_key = ?1) AS byKey, (?2 <> '' AND mac = ?2) AS byMAC, 1 AS main FROM inv_asset
			WHERE (?1 <> '' AND agent_key = ?1) OR (?2 <> '' AND mac = ?2) OR (?3 <> '' AND ip = ?3)
			UNION ALL SELECT asset_id, 0, (?2 <> '' AND mac = ?2), 0 FROM inv_asset_address WHERE (?2 <> '' AND mac = ?2) OR (?3 <> '' AND ip = ?3))
			ORDER BY byKey DESC, byMAC DESC, main DESC LIMIT 1`, agent, mac, ipS).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return fmt.Errorf("inventory: find enrolled device: %w", err)
		}
		if agentSaw { // not a live report: the agent must once have reported this MAC on this very row (#673)
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'mac' AND source = 'agent' AND value = ?`,
				id, nodeMAC).Scan(&n); err != nil {
				return fmt.Errorf("inventory: check the agent's MAC: %w", err)
			}
			if n == 0 || nodeMAC == "" {
				return nil
			}
		}
		if shared, err := handShared(ctx, tx, id); err != nil || shared { // found by its address only, which another machine shares (#829)
			return err
		}
		found = true
		var other sql.NullString
		err = tx.QueryRowContext(ctx, `SELECT value FROM inv_observation WHERE asset_id = ? AND field = 'mac' AND value <> ? LIMIT 1`, id, nodeMAC).Scan(&other)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("inventory: check the enrolled device's MAC: %w", err)
		}
		if other.Valid {
			s.log.WarnContext(ctx, "inventory: the enrolment did not approve a device seen with another MAC; a person decides",
				"device", id, "agent_mac", nodeMAC, "other_mac", other.String)
			return nil
		}
		res, err := tx.ExecContext(ctx, `UPDATE inv_asset SET approved = 1, approved_at = ? WHERE id = ? AND approved = 0 AND suspicious = 0 AND is_box = 0 AND ignored_at IS NULL`, s.now(), id)
		if err != nil {
			return fmt.Errorf("inventory: approve enrolled device: %w", err)
		}
		approved, _ := res.RowsAffected()
		typed, err := s.typeFromAgentOS(ctx, tx, id)
		if err != nil {
			return err
		}
		if approved+typed == 0 {
			return nil
		}
		o.add(EventAssetUpdated, AssetEvent{AssetID: id})
		if approved == 0 {
			return nil
		}
		return s.auditTx(ctx, tx, systemActor, "inventory.approve_enrolled", deviceName(ctx, tx, id), reason)
	})
	return found, err
}

// typeFromAgentOS gives the device the kind of the OS its agent reported, for an OS stored before agents sent a kind (the upgrade
// path): when the device has an agent os observation and no agent kind observation, it adds the kind of core/observe AgentKindOfOS as an
// agent observation with that OS's confidence and time, and recomputes the device. A person's kind still wins (manual outranks agent);
// the box is left as it is. It returns 1 when the device changed.
func (s *Service) typeFromAgentOS(ctx context.Context, tx *sql.Tx, id string) (int64, error) {
	var os, seen string
	var conf float64
	err := tx.QueryRowContext(ctx, `SELECT o.value, o.confidence, o.seen_at FROM inv_observation o JOIN inv_asset a ON a.id = o.asset_id
		WHERE o.asset_id = ? AND o.field = 'os' AND o.source = 'agent' AND a.is_box = 0
		AND NOT EXISTS (SELECT 1 FROM inv_observation k WHERE k.asset_id = o.asset_id AND k.field = 'kind' AND k.source = 'agent')
		ORDER BY o.seen_at DESC, o.id DESC LIMIT 1`, id).Scan(&os, &conf, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	} else if err != nil {
		return 0, fmt.Errorf("inventory: read the agent's OS: %w", err)
	}
	kind := observe.AgentKindOfOS(os)
	if kind == "" {
		return 0, nil
	}
	if err := insertPruned(ctx, tx, id, "kind", kind, string(observe.Agent), conf, seen); err != nil {
		return 0, err
	}
	changed, err := s.RecomputeAsset(ctx, tx, id)
	if changed {
		return 1, err
	}
	return 0, err
}

// hintKey is the hint of c as one key: the observations of one report share it.
func (c cleanObs) hintKey() string {
	return c.ip.String() + "|" + c.mac + "|" + c.agent + "|" + c.device + "|" + c.from.String()
}

// target names the device a hint points to, for the audit row.
func (c cleanObs) target() string {
	if c.mac != "" {
		return c.mac
	}
	return c.ip.String()
}

// ipTrust is how long a device's address stays its own without a sighting that ties the two: a sensor that saw the
// device's MAC at that address, its bound agent reporting from it, a person declaring it, or, for a discovered device known by address
// only, anything seen there (ip_confirmed_at). Past it, while the discovery sweep runs (sweepRan), a hint with only an address (a
// version scan, an SNMP read, a Wazuh or software list) is not given to the device, an address-only device no longer adopts a MAC seen
// there, and a hand-added device nobody saw binds no MAC: DHCP may have given the address to another machine. Three days, as runZero (an address not confirmed by a scan for three days is not trusted on its own): the slowest
// source that confirms one is the daily discovery sweep (sensor-active, once per scan window, an ARP ping every live host on the segment
// answers), so a day with no sweep does not drop a live device's facts; the passive sensor confirms every 15 minutes.
const ipTrust = 72 * time.Hour

// resolve finds the device a hint points to, or creates it (#829: the address is an attribute, never the identity); "" when no device
// may take it. The agent bound to a device wins; a hint with only an agent reaches that device or nothing. Then the MAC; then
// the address.
//
// A hint with no MAC goes to the device holding the address when that device has no MAC (the address is all it is known by), when its
// address was confirmed within ipTrust, or when the discovery sweep could not have confirmed it (sweptAway: the sweep did not run, or
// does not probe that device). Otherwise a sensor's hint or a list goes nowhere (logged), and an agent's observation makes a device of its own,
// which agentOrphan joins to the old one when the agent reports its card.
//
// A hint with a MAC nobody owns binds the address's device when that device has no MAC yet: a hand-added one when the MAC is burned in,
// a person declared the address within ipTrust (the bootstrap Lansweeper and Tenable do; a private MAC is a phone or a guest, never
// bound by an address alone: #872) and no other MAC was seen at the address since (firstAtHand), a discovered one when its address was seen within ipTrust; otherwise, or when the
// holder has another MAC, a new device is made and takes the address (claimIP). A known MAC at such a hand-added device's address
// whose device is a waiting discovered one goes to the hand-added device, and joinSame folds the other into it (handBound:
// the duplicate an earlier batch made). A hint with only a MAC that a join left as a chassis MAC is about the device it
// joined.
func (s *Service) resolve(ctx context.Context, tx *sql.Tx, o *outbox, c cleanObs) (id string, created bool, err error) {
	if ok, err := s.admit(ctx, tx, c, false); !ok || err != nil { // a card a removal keeps out: the sighting reaches nothing (INV-59)
		return "", false, err
	}
	if c.device != "" { // that device or nothing; never by address, never a new one, never the box
		err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE id = ? AND is_box = 0`, c.device).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("inventory: find device by id: %w", err)
		}
		return id, false, nil
	}
	if err := handSeen(ctx, tx, c); err != nil {
		return "", false, err
	}
	if c.agent != "" { // the agent bound to a device finds it wherever its address went; an agent moves the address
		if id, err := s.keyHit(ctx, tx, o, c); id != "" || err != nil {
			return id, false, err
		}
		if c.mac == "" && !c.ip.IsValid() { // the agent's key alone (AssetHint.From): only its bound device takes it
			return "", false, nil
		}
	}
	if c.own && c.mac == "" {
		return s.ownDevice(ctx, tx, c)
	}
	cutoff := store.FormatTS(s.clock().Add(-ipTrust))
	if c.mac != "" {
		switch err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE mac = ?`, c.mac).Scan(&id); {
		case err == nil:
			if hand, err := handHolder(ctx, tx, c, id, cutoff); hand != "" || err != nil {
				if err != nil {
					return "", false, err
				}
				return hand, false, confirmIP(ctx, tx, hand, c.ip, c.seenAt)
			}
			return id, false, s.claimIP(ctx, tx, o, id, c.ip, c.source, c.seenAt)
		case !errors.Is(err, sql.ErrNoRows):
			return "", false, fmt.Errorf("inventory: find device by MAC: %w", err)
		}
		// one of a device's other addresses (INV-57): that device, wherever the interface is now
		if x, ok, err := extraByMAC(ctx, tx, c.mac); err != nil {
			return "", false, err
		} else if ok {
			id, err := s.atExtraMAC(ctx, tx, o, x, c)
			return id, false, err
		}
		if !c.ip.IsValid() {
			if id, err := chassisOwner(ctx, tx, c.mac); id != "" || err != nil {
				return id, false, err
			}
		}
	}
	if c.ip.IsValid() {
		var holderMAC, confirmed sql.NullString
		var manual bool
		err := tx.QueryRowContext(ctx, `SELECT id, mac, ip_confirmed_at, origin = 'manual' FROM inv_asset WHERE ip = ?`, c.ip.String()).Scan(&id, &holderMAC, &confirmed, &manual)
		fresh := confirmed.Valid && confirmed.String >= cutoff
		first := true // c's MAC is the only one seen at a hand-added device's address since a person added it (inv_hand_seen)
		if err == nil && manual && !holderMAC.Valid && c.mac != "" {
			if first, err = firstAtHand(ctx, tx, id, c.mac); err != nil {
				return "", false, err
			}
		}
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// one of a device's other addresses (INV-57), by the rules of the main address (atExtraIP)
			x, ok, err := extraByIP(ctx, tx, c.ip.String())
			if err != nil {
				return "", false, err
			}
			if ok {
				if id, done, err := s.atExtraIP(ctx, tx, x, c, cutoff); done || err != nil {
					return id, false, err
				}
			}
		case err != nil:
			return "", false, fmt.Errorf("inventory: find device by IP: %w", err)
		case c.mac == "":
			switch {
			case !holderMAC.Valid: // known by its address only: the address is its identity, and this is a sighting of it
				if manual { // a hand-added device's address stays the person's word (handHolder, the bind below)
					if !c.list {
						return id, false, nil
					}
					// a list by address only (an osquery node not bound yet, Wazuh) at an address where a MAC was seen that this device
					// did not take is not known to be the person's machine (#829): dropped until a person merges
					if shared, err := handShared(ctx, tx, id); err != nil || !shared {
						return id, false, err
					}
					s.staleLog(ctx, id, c, "", staleHandList)
					return "", false, nil
				}
				return id, false, confirmIP(ctx, tx, id, c.ip, c.seenAt)
			case fresh:
				return id, false, nil
			}
			judged, err := sweptAway(ctx, tx, id, cutoff)
			if err != nil {
				return "", false, err
			}
			switch {
			case !judged:
				return id, false, nil
			case c.agent == "" || c.list:
				s.staleLog(ctx, id, c, confirmed.String, staleSwept)
				return "", false, nil
			}
			// an agent's observation at a stale address: a device of its own takes the address (below); when the agent reports the old
			// device's card, agentOrphan joins the two in this write (INV-31 (3)), keeping the old device
		case !holderMAC.Valid && fresh && (!manual || first && !localMAC(c.mac)):
			// Same device, first time its MAC is known. Set it now so the next observation of this batch finds the device by MAC
			// (RecomputeAsset only runs at the end of the batch).
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET mac = ? WHERE id = ?`, c.mac, id); err != nil {
				return "", false, fmt.Errorf("inventory: set MAC: %w", err)
			}
			if manual {
				if err := s.auditTx(ctx, tx, systemActor, "inventory.bind_mac", deviceName(ctx, tx, id), c.mac+" seen at "+c.ip.String()); err != nil {
					return "", false, err
				}
			}
			return id, false, confirmIP(ctx, tx, id, c.ip, c.seenAt)
		}
	}
	if ok, err := s.admit(ctx, tx, c, true); !ok || err != nil {
		return "", false, err
	}
	now := c.seenAt
	id = store.NewID("a")
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, mac, kind, origin, approved, fragile, first_seen, last_seen) VALUES (?, ?, 'unknown', 'discovered', 0, 0, ?, ?)`, id, nullStr(c.mac), now, now); err != nil {
		return "", false, fmt.Errorf("inventory: create device: %w", err)
	}
	return id, true, s.claimIP(ctx, tx, o, id, c.ip, c.source, c.seenAt)
}

// handSeen records that a sighting put c's MAC at the address of a device added by hand and known by that address only (no MAC, no
// agent): inv_hand_seen, any source, before anything else decides (#829). It is how the inventory knows that the
// address was not the person's machine alone since they added it.
func handSeen(ctx context.Context, tx *sql.Tx, c cleanObs) error {
	if c.mac == "" || !c.ip.IsValid() {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_hand_seen (asset_id, mac, first_seen, last_seen)
		SELECT id, ?2, ?3, ?3 FROM inv_asset WHERE ip = ?1 AND origin = 'manual' AND mac IS NULL AND agent_key IS NULL AND is_box = 0
		AND NOT EXISTS (SELECT 1 FROM inv_asset WHERE is_box = 1 AND mac = ?2)
		ON CONFLICT (asset_id, mac) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen)`, c.ip.String(), c.mac, c.seenAt); err != nil {
		return fmt.Errorf("inventory: record a MAC at a hand-added address: %w", err)
	}
	return nil
}

// handClaims runs before a batch resolves (#829). It records every
// MAC the batch puts at an address (a hint's MAC, or the card an agent hinted by address only reports as a mac observation: osquery,
// Wazuh), so a bind sees every MAC of the batch, not only those resolved before it. An agent's report by address only at the address of
// a hand-added device known by that address only, where a MAC the report does not claim was seen since the person added it, is marked
// own: a device of its own (ownDevice), announced and offered as possibly the same device, never the person's device by its address.
// Its card is never a lookup key (a node declares it): it may reach only the newcomer a sensor saw at that address, and only
// for an agent no device is bound to (a binding keyHit drops as a spoof never comes back through it).
func handClaims(ctx context.Context, tx *sql.Tx, clean []cleanObs) error {
	claims := map[netip.Addr][]string{} // address → the cards agents' reports by address only claim there
	agentAt := []netip.Addr{}           // the addresses of agents' reports by address only, in batch order
	for _, c := range clean {
		mac := c.mac
		if mac == "" && c.ip.IsValid() && c.source == string(observe.Agent) {
			if !slices.Contains(agentAt, c.ip) {
				agentAt = append(agentAt, c.ip)
			}
			if c.field == string(observe.MAC) {
				mac = c.value
				if !slices.Contains(claims[c.ip], mac) {
					claims[c.ip] = append(claims[c.ip], mac)
				}
			}
		}
		if mac != "" && c.ip.IsValid() {
			if err := handSeen(ctx, tx, cleanObs{ip: c.ip, mac: mac, seenAt: c.seenAt}); err != nil {
				return err
			}
		}
	}
	for _, ip := range agentAt {
		var id string
		switch err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE ip = ? AND origin = 'manual' AND mac IS NULL AND agent_key IS NULL AND is_box = 0`, ip.String()).Scan(&id); {
		case errors.Is(err, sql.ErrNoRows):
			continue
		case err != nil:
			return fmt.Errorf("inventory: find the hand-added device at the address: %w", err)
		}
		seen, err := candidates(ctx, tx, `SELECT mac FROM inv_hand_seen WHERE asset_id = ?`, id)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(seen, func(m string) bool { return !slices.Contains(claims[ip], m) }) {
			continue // the report's cards are the only MACs seen there: the person's device (#829)
		}
		for i := range clean {
			c := &clean[i]
			if c.ip != ip || c.mac != "" || c.source != string(observe.Agent) {
				continue
			}
			c.own = true
			if len(claims[ip]) == 0 {
				continue
			}
			bound := false
			if c.agent != "" {
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_asset WHERE agent_key = ?)`, c.agent).Scan(&bound); err != nil {
					return fmt.Errorf("inventory: find the agent's device: %w", err)
				}
			}
			if !bound {
				c.card = claims[ip][0]
			}
		}
	}
	return nil
}

// ownDevice is the device of its own of an agent's report c that handClaims marked own: the newcomer a sensor saw with c's card at the
// hand-added address (a discovered row nobody approved or bound, with no address: the hand-added row holds it), or the device of its own
// an earlier report with that card made (a Wazuh report has no key to find it by), else a new device with no MAC and no address (the
// card stays an agent observation, which never takes a MAC another device owns). A report with neither a key nor a card is
// held ("": nothing would find its device again, so each report would make one).
func (s *Service) ownDevice(ctx context.Context, tx *sql.Tx, c cleanObs) (string, bool, error) {
	var id string
	if c.card != "" {
		switch err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE origin = 'discovered' AND approved = 0 AND agent_key IS NULL AND is_box = 0
			AND ip IS NULL AND (mac = ?1 OR id IN (SELECT asset_id FROM inv_observation WHERE field = 'mac' AND source = 'agent' AND value = ?1))
			ORDER BY mac = ?1 DESC, last_seen DESC LIMIT 1`, c.card).Scan(&id); {
		case err == nil:
			return id, false, nil
		case !errors.Is(err, sql.ErrNoRows):
			return "", false, fmt.Errorf("inventory: find the newcomer: %w", err)
		}
	}
	if c.agent == "" && c.card == "" { // no key and no card (Wazuh with no network data): nothing would find it again; held, logged
		s.staleLog(ctx, c.ip.String(), c, "", staleHandNoKey)
		return "", false, nil
	}
	if ok, err := s.admit(ctx, tx, c, true); !ok || err != nil {
		return "", false, err
	}
	id = store.NewID("a")
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, kind, origin, approved, fragile, first_seen, last_seen) VALUES (?, 'unknown', 'discovered', 0, 0, ?, ?)`,
		id, c.seenAt, c.seenAt); err != nil {
		return "", false, fmt.Errorf("inventory: create device: %w", err)
	}
	return id, true, nil
}

// handShared reports whether a MAC was seen at the address of hand-added device id since it was added while it is still known by
// that address only: the MAC was not given to it (another machine, a private MAC, a MAC known elsewhere), so the address is shared.
func handShared(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var shared bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_hand_seen s JOIN inv_asset a ON a.id = s.asset_id
		WHERE s.asset_id = ? AND a.origin = 'manual' AND a.mac IS NULL AND a.agent_key IS NULL)`, id).Scan(&shared); err != nil {
		return false, fmt.Errorf("inventory: read the MACs seen at a hand-added address: %w", err)
	}
	return shared, nil
}

// firstAtHand reports whether mac is the only MAC seen at the address of hand-added device id since the person added it (handSeen).
// Only then may an address bind it (#829: a person adds "printer .201", the printer is off, DHCP gives .201 to a laptop, then to
// another one; the second must not silently become the approved printer). Any other MAC there, private or burned in, known or new,
// means the address is shared: the newcomer is a new, announced device, offered as possibly the same device (byAddress).
func firstAtHand(ctx context.Context, tx *sql.Tx, id, mac string) (bool, error) {
	var other bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_hand_seen WHERE asset_id = ? AND mac <> ?)`, id, mac).Scan(&other); err != nil {
		return false, fmt.Errorf("inventory: read the MACs seen at a hand-added address: %w", err)
	}
	return !other, nil
}

// handHolder is the hand-added device at c's address that a sighting of c's burned-in MAC, which device other already owns, is about
// (#872): it has no MAC and no agent, a person declared its address within ipTrust (cutoff), no other MAC was seen at
// that address since (firstAtHand), and other is a discovered
// device nobody approved that never had an address (the duplicate an earlier batch made of it: a MAC-only hint before the ARP, an LLDP
// frame; a machine already announced at another address is not folded). "" otherwise.
// The hint then goes to the hand-added device, and joinSame folds other into it (handBound).
func handHolder(ctx context.Context, tx *sql.Tx, c cleanObs, other, cutoff string) (string, error) {
	if !c.ip.IsValid() || localMAC(c.mac) {
		return "", nil
	}
	var id string
	err := tx.QueryRowContext(ctx, `SELECT h.id FROM inv_asset h, inv_asset o WHERE h.ip = ? AND h.origin = 'manual' AND h.mac IS NULL AND h.agent_key IS NULL
		AND h.is_box = 0 AND h.ip_confirmed_at >= ? AND o.id = ? AND o.id <> h.id AND o.origin = 'discovered' AND o.approved = 0 AND o.is_box = 0
		AND o.ip IS NULL AND NOT EXISTS (SELECT 1 FROM inv_hand_seen WHERE asset_id = h.id AND mac <> ?)`,
		c.ip.String(), cutoff, other, c.mac).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("inventory: find the hand-added device at the address: %w", err)
	}
	if apart, err := keptApart(ctx, tx, id, other); err != nil || apart { // a person said they are two devices
		return "", err
	}
	return id, nil
}

// handBound is the waiting discovered device a hand-added device (id) is (#872): id has no MAC and no agent, and holds
// the one burned-in MAC a sensor saw on it (resolve gave it the sighting: handHolder), which that discovered device, nobody approved,
// owns. "" otherwise. The discovered device goes into the hand-added one, which keeps its id, approval and notes.
func handBound(ctx context.Context, tx *sql.Tx, id string) (from, why string, err error) {
	macs, err := candidates(ctx, tx, `SELECT DISTINCT o.value FROM inv_observation o JOIN inv_asset h ON h.id = o.asset_id
		WHERE o.asset_id = ? AND o.field = 'mac' AND o.source <> 'agent' AND o.evidence IS NOT ? AND h.origin = 'manual' AND h.mac IS NULL
		AND h.agent_key IS NULL AND h.is_box = 0`, id, chassisEvidence)
	if err != nil || len(macs) != 1 || localMAC(macs[0]) {
		return "", "", err
	}
	err = tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE mac = ? AND id <> ? AND origin = 'discovered' AND approved = 0 AND is_box = 0 AND ip IS NULL`, macs[0], id).Scan(&from)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	} else if err != nil {
		return "", "", fmt.Errorf("inventory: find the hand-added device's MAC: %w", err)
	}
	return from, "a sensor saw its network card " + macs[0] + " at the address it was added with", nil
}

// sweptAway says whether the discovery sweep could have confirmed device id at its address since cutoff and did not
// (#872): the sweep ran since cutoff (sensor-active's nmap mac observations; an ARP ping is answered by every live host on
// the segment), the address is in the confirmed scope, and the sweep probes the device (not sweepSkips: a device added by hand, the box,
// one set to "never", a fragile or unclassified one after its first scan are never probed). Only then is its silence news; the passive
// sensor hears broadcasts only, so a quiet server it never hears is not stale.
func sweptAway(ctx context.Context, tx *sql.Tx, id, cutoff string) (bool, error) {
	return sweptAwayAt(ctx, tx, id, netip.Addr{}, cutoff)
}

// sweptAwayAt is sweptAway for one of the device's other addresses at (INV-57): the same rules, with that address in place of the
// device's main one. The zero at is the main address.
func sweptAwayAt(ctx context.Context, tx *sql.Tx, id string, at netip.Addr, cutoff string) (bool, error) {
	var ran bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM inv_observation WHERE field = 'mac' AND source = 'nmap' AND seen_at >= ?)`, cutoff).Scan(&ran); err != nil {
		return false, fmt.Errorf("inventory: check the discovery sweep: %w", err)
	}
	if !ran {
		return false, nil
	}
	var f scanFacts
	if err := f.scan(tx.QueryRowContext(ctx, `SELECT `+scanCols+` FROM inv_asset WHERE id = ?`, id)); err != nil {
		return false, fmt.Errorf("inventory: read device: %w", err)
	}
	if at.IsValid() {
		f.addr = at
	}
	st, err := loadSettings(ctx, tx)
	if err != nil {
		return false, err
	}
	return st.ScopeConfirmedAt != nil && f.addr.IsValid() && st.InScope(f.addr) && !sweepSkips(st, f), nil
}

// Why a report by address only was not given to the device at the address (staleLog).
const (
	staleSwept     = "inventory: reports by address only are not given to the device at that address: the discovery sweep has not seen it there for 3 days (DHCP may have given the address to another machine)"
	staleHandList  = "inventory: a list by address only is not given to the hand-added device at that address: another machine was seen there since it was added (on the device page: merge it when it is that machine; else delete the hand-added device, or keep it, and the machine's own lists by address only stay held)"
	staleHandNoKey = "inventory: an agent report by address only, with no card and no key, is not given to the hand-added device at that address: another machine was seen there since it was added"
	staleRemoved   = "inventory: a sighting of a device a person removed makes no device (Devices, To review, Removed: forget the removal to see it again)"
)

// staleLog logs, at most once an hour per device and reason (one of the stale* messages), that a report by address only was not given
// to the device at the address.
func (s *Service) staleLog(ctx context.Context, id string, c cleanObs, confirmed, msg string) {
	s.staleMu.Lock()
	if s.stale == nil || len(s.stale) > 4096 {
		s.stale = map[string]time.Time{}
	}
	now := s.clock()
	key := id + "\x00" + msg // one line an hour per device and reason
	last, seen := s.stale[key]
	due := !seen || now.Sub(last) >= time.Hour
	if due {
		s.stale[key] = now
	}
	s.staleMu.Unlock()
	if due {
		args := []any{"device", id, "ip", c.ip, "source", c.source, "confirmed_at", confirmed}
		switch msg {
		case staleHandList:
			s.log.InfoContext(ctx, staleHandList, args...)
		case staleHandNoKey:
			s.log.InfoContext(ctx, staleHandNoKey, args...)
		case staleRemoved:
			s.log.InfoContext(ctx, staleRemoved, args...)
		default:
			s.log.InfoContext(ctx, staleSwept, args...)
		}
	}
}

// keyHit is the device the agent of c is bound to, moved to c's address, or "" (then the caller goes on by MAC and address).
// The binding follows the node through any change of its own address or card (a laptop off its dock reports from Wi-Fi;
// #831), and is dropped only on evidence from the wire, never on what the agent declares: the device's MAC is one its maker burned
// in, a sensor saw that MAC after the agent's last report on the device, and saw it at another address than the one that report came
// from (the device's address moved away from agentIP: claimIP by MAC), while this report comes from yet another address. Then the
// machine is elsewhere while the node reports from here: a binding a spoof made (the node once took the machine's MAC and address). The
// binding is cleared, logged, and the report goes by address like any other. A report from the very address the sensor saw the machine
// at is the machine moved by DHCP, seen by a sensor before its agent's next report (#829): it is followed. A report by the key alone
// (no address the agent confirmed, AssetHint.From) reaches the device only when the device is at the address it came from, and moves
// nothing: a key used from another machine's address writes nothing (agent-intake INV-12). A rotating private MAC is no evidence (it
// is never burned in).
func (s *Service) keyHit(ctx context.Context, tx *sql.Tx, o *outbox, c cleanObs) (string, error) {
	var id string
	var mac, ip, agentIP sql.NullString
	switch err := tx.QueryRowContext(ctx, `SELECT id, mac, ip, agent_ip FROM inv_asset WHERE agent_key = ?`, c.agent).Scan(&id, &mac, &ip, &agentIP); {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("inventory: find device by agent: %w", err)
	}
	if !c.ip.IsValid() { // the agent's key alone: only where a sensor (or the agent's last confirmed report) put the device
		if !c.from.IsValid() || !ip.Valid || c.from.String() != ip.String {
			return "", nil
		}
		return id, nil
	}
	if mac.Valid && !localMAC(mac.String) && ip.Valid && agentIP.Valid && ip.String != agentIP.String && c.ip.String() != ip.String {
		var wire int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_observation WHERE asset_id = ?1 AND field = 'mac' AND value = ?2 AND source <> 'agent'
			AND evidence IS NOT ?3 AND seen_at > coalesce((SELECT max(seen_at) FROM inv_observation WHERE asset_id = ?1 AND source = 'agent'), '')`,
			id, mac.String, chassisEvidence).Scan(&wire); err != nil {
			return "", fmt.Errorf("inventory: check the agent's device on the wire: %w", err)
		}
		if wire > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET agent_key = NULL, agent_ip = NULL WHERE id = ?`, id); err != nil {
				return "", fmt.Errorf("inventory: drop the agent's binding: %w", err)
			}
			s.log.WarnContext(ctx, "inventory: a sensor saw the burned-in MAC of the device an agent is bound to at another address after the agent's last report; the binding is dropped and the report goes by address",
				"device", id, "agent", c.agent, "device_mac", mac.String, "device_ip", ip.String, "agent_last_ip", agentIP.String, "report_ip", c.ip)
			return "", nil
		}
	}
	if err := s.claimIP(ctx, tx, o, id, c.ip, string(observe.Agent), c.seenAt); err != nil {
		return "", err
	}
	return id, setAgentIP(ctx, tx, id, c.ip)
}

// setAgentIP records the address the bound agent last reported from (keyHit's evidence).
func setAgentIP(ctx context.Context, tx *sql.Tx, id string, ip netip.Addr) error {
	if !ip.IsValid() {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET agent_ip = ? WHERE id = ?`, ip.String(), id); err != nil {
		return fmt.Errorf("inventory: record the agent's address: %w", err)
	}
	return nil
}

// bindAgent binds an agent to the device its report reached by address, so its later reports find the device when the address
// changes. Only a device that has no agent bound (a binding is never overwritten: a reused DHCP lease must not steal another node's
// device, #831; agent-intake releases the key of a node it deletes, ReleaseAgents) and that is this machine's: every MAC any
// source saw on it is one this agent reports in this batch (an address DHCP gave to a new machine still resolves to the old machine's
// row until a sensor sees the move). Nothing when the agent is bound to another device.
func bindAgent(ctx context.Context, tx *sql.Tx, id, agent string, macs []string) error {
	var held int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_asset WHERE agent_key = ? OR (id = ? AND agent_key IS NOT NULL)`, agent, id).Scan(&held); err != nil {
		return fmt.Errorf("inventory: check the agent's device: %w", err)
	}
	if held > 0 {
		return nil
	}
	seen, err := candidates(ctx, tx, `SELECT DISTINCT value FROM inv_observation WHERE asset_id = ? AND field = 'mac' AND evidence IS NOT ?`, id, chassisEvidence)
	if err != nil {
		return err
	}
	// a hand-added device known by its address only takes no agent whose cards are not every MAC seen at its address (#829)
	atAddr, err := candidates(ctx, tx, `SELECT s.mac FROM inv_hand_seen s JOIN inv_asset a ON a.id = s.asset_id WHERE s.asset_id = ? AND a.mac IS NULL`, id)
	if err != nil {
		return err
	}
	for _, m := range slices.Concat(seen, atAddr) {
		if !slices.Contains(macs, m) {
			return nil
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET agent_key = ?, agent_ip = ip WHERE id = ?`, agent, id); err != nil {
		return fmt.Errorf("inventory: bind the agent: %w", err)
	}
	return nil
}

// ReleaseAgents implements observe.AgentReleaser: agent-intake deleted these agents (re-enrolment, revoke,
// prune), so the devices bound to them are free for the next agent that reports on them.
func (s *Service) ReleaseAgents(ctx context.Context, agents []string) error {
	if len(agents) == 0 {
		return nil
	}
	return s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		for _, a := range agents {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET agent_key = NULL, agent_ip = NULL WHERE agent_key = ?`, a); err != nil {
				return fmt.Errorf("inventory: release an agent: %w", err)
			}
		}
		return nil
	})
}

// AgentDevice implements observe.AgentDevices: the agent bound to the device id, its address and its MAC; found is false when
// no device has that id. Read only.
func (s *Service) AgentDevice(ctx context.Context, id string) (observe.AgentDevice, bool, error) {
	var agent, ip, mac string
	var box, off bool
	err := s.db.Reader().QueryRowContext(ctx, `SELECT coalesce(agent_key, ''), coalesce(ip, ''), coalesce(mac, ''), is_box = 1, coalesce(agent_source, '') = 'off' FROM inv_asset WHERE id = ?`, id).Scan(&agent, &ip, &mac, &box, &off)
	if errors.Is(err, sql.ErrNoRows) {
		return observe.AgentDevice{}, false, nil
	}
	if err != nil {
		return observe.AgentDevice{}, false, fmt.Errorf("inventory: read device agent: %w", err)
	}
	d := observe.AgentDevice{Agent: agent, MAC: mac, IsBox: box, AgentOff: off && !box}
	if a, perr := netip.ParseAddr(ip); perr == nil {
		d.IP = a
	}
	return d, true, nil
}

// claimIP gives ip to the device and records the sighting that confirmed it (ip_confirmed_at, ipTrust). The address is taken from
// a device that holds it when that device is a discovered one or is bound to a MAC or an agent (#829: a hand-added device bound to its
// MAC is one machine like any other, and DHCP gives its address away like any other's); a hand-added device known by its address only
// keeps it at any age (#872: the person's row stays where they put it, and a machine first seen there long after,
// which binds nothing, is a new announced device without an address until the person merges or deletes the row), and the update is
// then a no-op. The box, and a hand-added device known by its address only, keep their own address against
// anything but an agent; a hand-added device bound to a MAC moves with that MAC (#829).
// The device that lost the address, and id when it had another one, are recorded in o (readdress): the write announces them, so a
// job holding the old address stops (#874).
func (s *Service) claimIP(ctx context.Context, tx *sql.Tx, o *outbox, id string, ip netip.Addr, source, seenAt string) error {
	if !ip.IsValid() {
		return nil
	}
	var cur sql.NullString
	var held bool
	if err := tx.QueryRowContext(ctx, `SELECT ip, is_box = 1 OR (origin = 'manual' AND mac IS NULL AND agent_key IS NULL) FROM inv_asset WHERE id = ?`, id).Scan(&cur, &held); err != nil {
		return fmt.Errorf("inventory: read device: %w", err)
	}
	if held && source != string(observe.Agent) {
		return nil
	}
	if cur.Valid && cur.String == ip.String() {
		return confirmIP(ctx, tx, id, ip, seenAt)
	}
	x, ok, err := extraByIP(ctx, tx, ip.String())
	if err != nil {
		return err
	}
	demoted := "" // when the old main address answered last: it becomes an address of the main card (a main_card row)
	second, err := secondAddress(ctx, tx, id, cur, x, ok, source, seenAt, s.clock())
	if err != nil {
		return err
	}
	// INV-57: one of the device's other addresses is still that address (the device answers on it too); another device's other
	// address goes to this one, as a main address does
	switch {
	case ok && x.assetID == id && cur.Valid && (second || !x.mainCard):
		if second && !x.mac.Valid && !x.mainCard { // the main card answers there too: the row is that card's from now on
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset_address SET main_card = 1 WHERE id = ?`, x.id); err != nil {
				return fmt.Errorf("inventory: mark an address of the main card: %w", err)
			}
		}
		return touchExtra(ctx, tx, x.id, source, seenAt)
	case ok && x.assetID == id && cur.Valid:
		// an address of the main card where the card is seen while the main address has not answered since: the card went there (a
		// person re-addressed it, or the main address is the one it answers on less). That address becomes the main one (below), with
		// what a scan read there; the old main address stays an address of the card, so a sighting there later moves nothing back.
		if err := s.unbindAddress(ctx, tx, id, x.id); err != nil {
			return err
		}
		if err := s.releaseExtraIP(ctx, tx, nil, x); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT coalesce(ip_confirmed_at, last_seen) FROM inv_asset WHERE id = ?`, id).Scan(&demoted); err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
	case ok && x.assetID == id: // a device with no main address takes this one as its main address, with what a scan read there
		if err := s.unbindAddress(ctx, tx, id, x.id); err != nil {
			return err
		}
		if err := s.releaseExtraIP(ctx, tx, nil, x); err != nil {
			return err
		}
	case ok:
		if err := s.releaseExtraIP(ctx, tx, o, x); err != nil {
			return err
		}
	}
	taken, err := freeMainIP(ctx, tx, o, id, ip.String()) // the address is unique (inv_asset_ip_uq): one row at most
	if err != nil {
		return err
	}
	if second { // one card, two addresses: the main address stays, this one is another address of the card
		if taken { // a device that keeps its address (the box, a hand-added one known by it) holds it
			return nil
		}
		return addCardAddress(ctx, tx, id, ip, source, seenAt, seenAt)
	}
	res, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ip = ?, ip_confirmed_at = ? WHERE id = ? AND NOT EXISTS (SELECT 1 FROM inv_asset WHERE ip = ?)`,
		ip.String(), seenAt, id, ip.String())
	if err != nil {
		return fmt.Errorf("inventory: set IP: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 && cur.Valid { // it left its old address
		o.readdress(id)
		if demoted != "" {
			if old, err := netip.ParseAddr(cur.String); err == nil {
				return addCardAddress(ctx, tx, id, old, source, demoted, demoted)
			}
		}
	}
	return nil
}

// cardTogether is how close in time a card answering at two addresses shows that it has both: a move by DHCP or a person's re-addressing
// does not put one card at the old and the new address within it (a recorded DHCP move came 30 minutes after the last sighting at the
// old address), while a discovery sweep probes the addresses of a segment within minutes of each other.
const cardTogether = 10 * time.Minute

// secondAddress says whether a sighting of device id's main card at ip, which is not its main address cur, is one of the card's
// addresses rather than a move: a router or server with two addresses on one card, or one that answers ARP for another address, would
// otherwise move the main address at every sighting of the other one, and with it the address every list, page, run and SNMP read uses
// (a run of the device stops when its address changes). It is when the main address answered within cardTogether of this sighting (the
// card has both now), or when ip is already an address of the card (x, a main_card row of id) and the main address answered since the
// card was first seen there, within ipTrust. A main_card row whose main address has not answered since is where the card moved: claimIP
// makes it the main address. Never for an agent's report or a device an agent is bound to (the agent follows its machine: keyHit), a
// private MAC (a phone or laptop: it rotates, and moves), a device without a main address, or the box and a hand-added device known by
// its address only (claimIP keeps their address).
func secondAddress(ctx context.Context, tx *sql.Tx, id string, cur sql.NullString, x extraAddr, isRow bool, source, seenAt string, now time.Time) (bool, error) {
	if !cur.Valid || source == string(observe.Agent) {
		return false, nil
	}
	var confirmed, mac sql.NullString
	var agent bool
	if err := tx.QueryRowContext(ctx, `SELECT ip_confirmed_at, mac, agent_key IS NOT NULL FROM inv_asset WHERE id = ?`, id).Scan(&confirmed, &mac, &agent); err != nil {
		return false, fmt.Errorf("inventory: read device: %w", err)
	}
	if !confirmed.Valid || !mac.Valid || localMAC(mac.String) || agent {
		return false, nil
	}
	at, perr := time.Parse(time.RFC3339Nano, seenAt)
	if perr != nil { // a sighting time that does not parse proves nothing: the address moves as before
		return false, nil
	}
	if confirmed.String >= store.FormatTS(at.Add(-cardTogether)) {
		return true, nil
	}
	return isRow && x.assetID == id && x.mainCard && confirmed.String >= x.firstSeen && confirmed.String >= store.FormatTS(now.Add(-ipTrust)), nil
}

// confirmIP records that a sighting tied the device to its address ip at seenAt (ipTrust); nothing when the device is elsewhere.
func confirmIP(ctx context.Context, tx *sql.Tx, id string, ip netip.Addr, seenAt string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ip_confirmed_at = max(coalesce(ip_confirmed_at, ''), ?) WHERE id = ? AND ip = ?`, seenAt, id, ip.String()); err != nil {
		return fmt.Errorf("inventory: confirm the address: %w", err)
	}
	return nil
}

// insertObs appends an observation. An exact repeat of (device, field, source, value) moves seen_at forward
// and keeps the higher confidence; nothing else is ever changed (INV-1). Record alone deletes, by pruneObs (INV-16).
func insertObs(ctx context.Context, tx *sql.Tx, assetID, field, value, source string, conf float64, seenAt string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (asset_id, field, source, value) DO UPDATE SET seen_at = max(seen_at, excluded.seen_at), confidence = max(confidence, excluded.confidence)`,
		store.NewID("o"), assetID, field, value, source, conf, seenAt, seenAt)
	if err != nil {
		return fmt.Errorf("inventory: record observation: %w", err)
	}
	return nil
}

// insertPruned is insertObs followed by pruneObs: what Record does for every observation it takes.
func insertPruned(ctx context.Context, tx *sql.Tx, assetID, field, value, source string, conf float64, seenAt string) error {
	if err := insertObs(ctx, tx, assetID, field, value, source, conf, seenAt); err != nil {
		return err
	}
	return pruneObs(ctx, tx, assetID, field, source)
}

// pruneObs keeps the latest maxObsPerSeries rows of (device, field, source) and deletes the older ones (INV-16). The
// unique index inv_observation_uq starts with these three columns, so the statement reads at most one series.
func pruneObs(ctx context.Context, tx *sql.Tx, assetID, field, source string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = ? AND source = ? AND id NOT IN
		(SELECT id FROM inv_observation WHERE asset_id = ? AND field = ? AND source = ? ORDER BY seen_at DESC, id DESC LIMIT ?)`,
		assetID, field, source, assetID, field, source, maxObsPerSeries)
	if err != nil {
		return fmt.Errorf("inventory: prune observations: %w", err)
	}
	return nil
}

// RecomputeAsset folds the observations of a device into its current columns (DATA_MODEL 5.1 rule 3): per
// field the winner by source rank, confidence, seen_at, id. It is the only code that writes those columns, and
// it runs in the transaction of the insert and the audit row. It reports whether anything changed. The OS a network device states
// (or the OS a person set on it) is then a software line again (syncStatedOS): what decides it may have moved.
func (s *Service) RecomputeAsset(ctx context.Context, tx *sql.Tx, assetID string) (bool, error) {
	changed, err := s.recomputeColumns(ctx, tx, assetID)
	if err != nil {
		return false, err
	}
	if _, err := s.syncStatedOS(ctx, tx, assetID, s.now()); err != nil {
		return false, err
	}
	return changed, nil
}

func (s *Service) recomputeColumns(ctx context.Context, tx *sql.Tx, assetID string) (bool, error) {
	if _, err := s.lapseOS(ctx, tx, assetID); err != nil { // a newer OS read after a person's correction ends it (INV-52)
		return false, err
	}
	// The chassis MAC a join left is a mark, never the device's MAC.
	rows, err := tx.QueryContext(ctx, `SELECT id, field, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ? AND NOT (field = 'mac' AND evidence IS ?) AND source <> 'declared'`, assetID, chassisEvidence)
	if err != nil {
		return false, fmt.Errorf("inventory: read observations: %w", err)
	}
	var list []obs
	for rows.Next() {
		var o obs
		if err := rows.Scan(&o.id, &o.field, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("inventory: read observations: %w", err)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("inventory: read observations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	var isBox bool
	if err := tx.QueryRowContext(ctx, `SELECT is_box FROM inv_asset WHERE id = ?`, assetID).Scan(&isBox); err != nil {
		return false, fmt.Errorf("inventory: read device: %w", err)
	}
	if isBox { // the box's MAC is what an agent says; no sensor can set it
		list = slices.DeleteFunc(list, func(o obs) bool { return o.field == "mac" && o.source != string(observe.Agent) })
	}
	best := winners(list)
	dropContradictedOS(list, best) // nmap's OS guess never wins against the device's type (Android on a firewall)
	// A MAC another device already owns cannot become this device's MAC: take the best one that is free.
	if _, ok := best["mac"]; ok {
		cands := slices.DeleteFunc(slices.Clone(list), func(o obs) bool { return o.field != "mac" })
		slices.SortFunc(cands, func(a, b obs) int {
			switch {
			case better(a, b):
				return -1
			case better(b, a):
				return 1
			}
			return 0
		})
		delete(best, "mac")
		for _, c := range cands {
			var other string
			// a MAC of an address row is an interface of its own (INV-57), never a device's main MAC, this device's included
			err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE mac = ?1 AND id <> ?2 UNION ALL SELECT asset_id FROM inv_asset_address WHERE mac = ?1 LIMIT 1`,
				c.value, assetID).Scan(&other)
			if errors.Is(err, sql.ErrNoRows) {
				best["mac"] = c
				break
			} else if err != nil {
				return false, fmt.Errorf("inventory: check MAC: %w", err)
			}
		}
	}
	if err := s.storeDeclared(ctx, tx, assetID, best); err != nil { // a person's declared OS row is the OS when the matcher reads it so (INV-45)
		return false, err
	}
	var cur struct {
		kind, vendor, model, os, host, mac                   sql.NullString
		kindObs, vendorObs, modelObs, osObs, hostObs, macObs sql.NullString
		fragile, fragileManual                               bool
	}
	if err := tx.QueryRowContext(ctx, `SELECT kind, vendor, model, os, hostname, mac, kind_obs_id, vendor_obs_id, model_obs_id, os_obs_id, hostname_obs_id, mac_obs_id, fragile, fragile_manual
		FROM inv_asset WHERE id = ?`, assetID).Scan(&cur.kind, &cur.vendor, &cur.model, &cur.os, &cur.host, &cur.mac, &cur.kindObs, &cur.vendorObs, &cur.modelObs, &cur.osObs, &cur.hostObs, &cur.macObs, &cur.fragile, &cur.fragileManual); err != nil {
		return false, fmt.Errorf("inventory: read device: %w", err)
	}
	val := func(f string) (any, any) {
		if o, ok := best[f]; ok {
			return o.value, o.id
		}
		return nil, nil
	}
	kindV, kindID := val("kind")
	if kindV == nil {
		kindV = "unknown"
	}
	vendorV, vendorID := val("vendor")
	modelV, modelID := val("model")
	osV, osID := val("os")
	hostV, hostID := val("hostname")
	macV, macID := val("mac")
	fragile := cur.fragile
	if !cur.fragileManual {
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return false, err
		}
		fragile = slices.Contains(st.FragileKinds, devicetypes.ActsAs(kindV.(string))) // a type acts as one of the 13 kinds
	}
	same := func(ns sql.NullString, v any) bool {
		if v == nil {
			return !ns.Valid
		}
		return ns.Valid && ns.String == v.(string)
	}
	changed := cur.kind.String != kindV.(string) || !same(cur.vendor, vendorV) || !same(cur.model, modelV) || !same(cur.os, osV) || !same(cur.host, hostV) || !same(cur.mac, macV) ||
		!same(cur.kindObs, kindID) || !same(cur.vendorObs, vendorID) || !same(cur.modelObs, modelID) || !same(cur.osObs, osID) || !same(cur.hostObs, hostID) || !same(cur.macObs, macID) || fragile != cur.fragile
	if !changed {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET kind = ?, vendor = ?, model = ?, os = ?, hostname = ?, mac = ?,
		kind_obs_id = ?, vendor_obs_id = ?, model_obs_id = ?, os_obs_id = ?, hostname_obs_id = ?, mac_obs_id = ?, fragile = ? WHERE id = ?`,
		kindV, vendorV, modelV, osV, hostV, macV, kindID, vendorID, modelID, osID, hostID, macID, fragile, assetID); err != nil {
		return false, fmt.Errorf("inventory: recompute device: %w", err)
	}
	return true, nil
}
