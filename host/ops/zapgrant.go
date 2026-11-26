package ops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The host's own checks before the disruptive rules of zap.active (host-api §6.15c, host INV-31c). Core decides first (a person's
// scan, testing terms that include the disruptive checks, the gateway not in 100.64.0.0/10, the box's own proven IP); the host does
// not take its word for the two parts it can witness itself:
//
//   - a person's press: zap.authorize mints a grant when a person starts the scan (actor exposure:<person>, never exposure:system), for
//     the box's own IP. The grant is the host's random value, kept only in the host's memory, and holds for one active pass: that IP,
//     runs of that actor, at most ZapGrantPages pages within ZapGrantPass of the first one, until ZapGrantTTL after the press. A
//     scheduled scan never presses, so it has no grant, and a grant cannot be carried to another address or person (another run of the
//     same person on the same address can use it within those bounds: the host does not know which scan a run is of). Core still
//     labels the actor: the grant binds the run to a press core reported (and the host audited) at that time, not to the person's own
//     credential, which the host does not see;
//   - carrier-grade NAT: the host reads the box's default IPv4 gateway itself (/proc/net/route, as state/net) right before the run:
//     in 100.64.0.0/10, or not readable, refuses the disruptive rules (fail closed).
//
// A refusal does not end the run: the page gets the active scan proper without the disruptive rules and form posting, and the
// result says why (ZapActiveResult.DisruptiveRefused), which exposure shows on the page's line.

// zapGrant is one grant of zap.authorize.
type zapGrant struct {
	ip    netip.Addr
	actor string
	at    time.Time // the press
	until time.Time // ZapGrantTTL after the press
	first time.Time // the first page it ran the disruptive rules on (zero: none yet)
	pages int
}

// over says whether the grant's one active pass is over at now: its pages used, or its window since the first page gone.
func (g *zapGrant) over(now time.Time) bool {
	return !g.first.IsZero() && (g.pages >= api.ZapGrantPages || !now.Before(g.first.Add(api.ZapGrantPass)))
}

// zapSpentMax bounds the grants the host remembers as spent (only to say "spent" rather than "unknown" to a page that brings one).
const zapSpentMax = 64

// zapRetire takes a grant whose pass is over out of the grants at once, so it never holds a place a new press needs, and remembers it
// as spent until its lifetime ends. The caller holds zapMu.
func (o *Ops) zapRetire(value string, g *zapGrant, now time.Time) {
	delete(o.zapGrants, value)
	if o.zapSpent == nil {
		o.zapSpent = map[string]time.Time{}
	}
	for k, until := range o.zapSpent {
		if !now.Before(until) {
			delete(o.zapSpent, k)
		}
	}
	for len(o.zapSpent) >= zapSpentMax {
		oldest := ""
		for k, until := range o.zapSpent {
			if oldest == "" || until.Before(o.zapSpent[oldest]) {
				oldest = k
			}
		}
		delete(o.zapSpent, oldest)
	}
	o.zapSpent[value] = g.until
}

// zapGrantRE is a grant as the host mints it.
var zapGrantRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// zapPersonActor says whether an actor label names a person's press: exposure:<person>, never the box itself.
func zapPersonActor(actor string) bool {
	who, ok := strings.CutPrefix(actor, "exposure:")
	return ok && who != "" && !strings.EqualFold(who, "system")
}

func zapAuthorizeArgs(a *api.ZapAuthorizeArgs) (netip.Addr, error) {
	ip, err := netip.ParseAddr(a.IP)
	if err != nil || !ip.Is4() || ip.String() != a.IP || !egressip.IsPublicIPv4(ip) {
		return netip.Addr{}, server.Invalid(fieldIP, "must be a public IPv4 address")
	}
	return ip, nil
}

func (o *Ops) cmdZapAuthorize() server.Command {
	// Not a write command: it touches nothing on the box, only the host's memory of grants.
	return server.Define(server.Spec[api.ZapAuthorizeArgs]{
		Name: api.CmdZapAuthorize, Write: false, Timeout: time.Minute,
		Validate: func(a *api.ZapAuthorizeArgs) error { _, err := zapAuthorizeArgs(a); return err },
		Run: func(_ context.Context, rc *server.RunContext, a api.ZapAuthorizeArgs) (any, error) {
			ip, err := zapAuthorizeArgs(&a)
			if err != nil {
				return nil, err
			}
			return o.zapAuthorize(rc.Log, rc.Actor, ip)
		},
	})
}

// zapAuthorize mints a grant of the disruptive rules on ip for actor's press.
func (o *Ops) zapAuthorize(logf func(string), actor string, ip netip.Addr) (any, error) {
	if !zapPersonActor(actor) {
		return nil, refuse412(api.CodeZapGrantNotPerson, "Only a person's press of Scan now gets the disruptive rules; this request names no person.")
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fail(api.CodeZapFailed, "The host could not make a grant.")
	}
	g := hex.EncodeToString(b[:])
	now := o.d.Now()
	o.zapMu.Lock()
	defer o.zapMu.Unlock()
	if o.zapGrants == nil {
		o.zapGrants = map[string]*zapGrant{}
	}
	for k, v := range o.zapGrants { // expired ones go, and those whose pass is over give up their place
		switch {
		case !now.Before(v.until):
			delete(o.zapGrants, k)
		case v.over(now):
			o.zapRetire(k, v, now)
		}
	}
	for len(o.zapGrants) >= api.ZapGrantsMax { // still full: the oldest press makes room for this one, never the other way round
		oldest := ""
		for k, v := range o.zapGrants {
			if oldest == "" || v.at.Before(o.zapGrants[oldest].at) {
				oldest = k
			}
		}
		delete(o.zapGrants, oldest)
		logf("the oldest grant of the disruptive rules the host held was dropped to make room for this press")
	}
	until := now.Add(api.ZapGrantTTL)
	o.zapGrants[g] = &zapGrant{ip: ip, actor: actor, at: now, until: until}
	logf("the disruptive rules of the active web scan are granted on " + ip.String() + " for one active pass of " + actor + ", until " + until.UTC().Format(time.RFC3339))
	return api.ZapAuthorizeResult{Grant: g, ExpiresAt: until.UTC()}, nil
}

// zapDisruptiveRefusal is the host's own check right before a run that asks for the disruptive rules: "" when they run (and the page
// is counted on its grant), else the api.ZapRefused* code of why the page runs without them. A gateway refusal does not spend the
// grant.
func (o *Ops) zapDisruptiveRefusal(p zapPage, pass zapPass) string {
	now := o.d.Now()
	o.zapMu.Lock()
	defer o.zapMu.Unlock()
	if pass.grant == "" {
		return api.ZapRefusedGrantMissing
	}
	g := o.zapGrants[pass.grant]
	if g == nil {
		until, spent := o.zapSpent[pass.grant]
		switch {
		case spent && !now.Before(until):
			delete(o.zapSpent, pass.grant)
			return api.ZapRefusedGrantExpired
		case spent:
			return api.ZapRefusedGrantSpent
		}
		return api.ZapRefusedGrantUnknown
	}
	switch {
	case !now.Before(g.until):
		delete(o.zapGrants, pass.grant)
		return api.ZapRefusedGrantExpired
	case g.ip != p.ip || g.actor != pass.actor:
		return api.ZapRefusedGrantMismatch
	case g.over(now):
		o.zapRetire(pass.grant, g, now)
		return api.ZapRefusedGrantSpent
	}
	if why := o.zapGatewayRefusal(); why != "" {
		return why
	}
	if g.first.IsZero() {
		g.first = now
	}
	g.pages++
	if g.pages >= api.ZapGrantPages { // its last page: the grant gives up its place at once
		o.zapRetire(pass.grant, g, now)
	}
	return ""
}

// zapGatewayRefusal reads the box's default IPv4 gateway as state/net does: in 100.64.0.0/10 (carrier-grade NAT) or not readable,
// the disruptive rules do not run.
func (o *Ops) zapGatewayRefusal() string {
	r := o.defaultRoute()
	if r == nil {
		return api.ZapRefusedGatewayUnreadable
	}
	g, err := netip.ParseAddr(r.Gateway)
	switch {
	case err != nil || !g.Is4():
		return api.ZapRefusedGatewayUnreadable
	case zapSharedSpace.Contains(g):
		return api.ZapRefusedGatewayShared
	}
	return ""
}

// zapSharedSpace is the shared address space of carrier-grade NAT (RFC 6598).
var zapSharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// zapRefusalText is the run log's sentence of a refusal.
func zapRefusalText(code string) string {
	switch code {
	case api.ZapRefusedGrantMissing:
		return "no grant of a person's press came with the run"
	case api.ZapRefusedGrantUnknown:
		return "the host does not hold the grant of the press (it was never minted here, the host restarted since, or later presses took its place)"
	case api.ZapRefusedGrantExpired:
		return "the grant of the press expired"
	case api.ZapRefusedGrantSpent:
		return "the grant of the press was already used for its one active pass"
	case api.ZapRefusedGrantMismatch:
		return "the grant of the press is for another address or another person"
	case api.ZapRefusedGatewayShared:
		return "the box's default gateway is in 100.64.0.0/10 (carrier-grade NAT)"
	case api.ZapRefusedGatewayUnreadable:
		return "the host could not read the box's default gateway"
	}
	return code
}
