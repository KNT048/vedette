package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

var (
	notifyMu       sync.Mutex
	notifyServices = map[*store.DB]*notify.Service{}
)

// notifyUsers implements notify.Users over core/auth: approvers are named by user id, and the email-code count
// is the number of active accounts whose two-step method is "email" (INV-9). auth is read through deps at call
// time because notify is built before auth (auth takes notify's code mailer, see buildServices).
type notifyUsers struct{ d *deps }

func (u notifyUsers) Lookup(ctx context.Context, id string) (notify.User, bool, error) {
	got, err := u.d.Auth.GetUser(ctx, id)
	var ae *apierr.Error
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		return notify.User{}, false, nil
	}
	if err != nil {
		return notify.User{}, false, err
	}
	return notify.User{ID: got.ID, Email: got.Email, Role: string(got.Role), Active: !got.Disabled}, true, nil
}

func (u notifyUsers) EmailCodeUsers(ctx context.Context) (int, error) {
	all, err := u.d.Auth.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, x := range all {
		if !x.Disabled && x.TwofaMethod == "email" {
			n++
		}
	}
	return n, nil
}

// notifyDevices implements notify.DeviceDirectory over the inventory: the device as the Devices page names it, with its
// address when that is not the name already, so a notice says "srv01 (10.142.0.181)" and not an asset id.
type notifyDevices struct{ inv *inventory.Service }

func (a notifyDevices) DeviceName(ctx context.Context, assetID string) (string, bool, error) {
	st, err := a.DeviceStates(ctx, []string{assetID})
	if err != nil {
		return "", false, err
	}
	d, ok := st[assetID]
	if !ok {
		return "", false, nil
	}
	return labelled(d.Name, d.Address), true, nil
}

// labelled is a device's name with its address in brackets when that is not the name already (notify's deviceLabel).
func labelled(name, addr string) string {
	switch {
	case name == "":
		return addr
	case addr != "" && addr != name:
		return name + " (" + addr + ")"
	}
	return name
}

// DeviceStates is notify's view of devices for their unknown_device incidents: the name of the Devices page
// (inventory.DisplayName, the one naming rule), else the MAC, else the kind; the IP, else the MAC, as the address; whether
// and when it was approved (notify closes the device's incident on it). The values come from the network: plainText cleans them.
// One light batch read of inventory (DeviceRefs: no findings count, no software list) for one id (notify's handler of
// inventory.asset.updated, only for a device on an open new-device incident) or many (the hourly autoclose job).
func (a notifyDevices) DeviceStates(ctx context.Context, ids []string) (map[string]notify.DeviceState, error) {
	out := make(map[string]notify.DeviceState, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	refs, err := a.inv.DeviceRefs(ctx, ids)
	if err != nil {
		return nil, err
	}
	var names map[string]string
	for id, r := range refs {
		name, sure := refName(r)
		if !sure {
			if names == nil {
				if names, err = a.inv.Names(ctx); err != nil {
					return nil, err
				}
			}
			if name = names[id]; name == id { // Names gives the id when nothing names the device
				name = ""
			}
		}
		out[id] = deviceState(r, name)
	}
	return out, nil
}

// refName is inventory.DisplayName of a DeviceRef. DeviceRefs puts the kind in Display when the device has no software, and only a
// declared device names itself after its first software, so a declared device whose Display is its kind is not sure (sure=false):
// DeviceStates then asks inventory.Names, one light read of every device's name (rare: a product with no device has a name of its own).
func refName(r inventory.DeviceRef) (name string, sure bool) {
	f := r.NameFacts(r.Display)
	if r.Display == r.Kind {
		if r.Origin == "manual" && strings.TrimSpace(f.UserName+f.Hostname) == "" {
			return "", false
		}
		f.Product = ""
	}
	return inventory.DisplayName(f), true
}

// deviceState is DeviceStates of one device of the inventory, named name (refName).
func deviceState(r inventory.DeviceRef, name string) notify.DeviceState {
	mac := plainText(r.MAC, 64)
	st := notify.DeviceState{Name: plainText(name, 160), Address: mac, Approved: r.Approved}
	if _, err := netip.ParseAddr(r.IP); err == nil { // the inventory shows an em dash when the IP is unknown
		st.Address = r.IP
	}
	if st.Name == "" {
		st.Name = mac
	}
	if st.Name == "" {
		st.Name = plainText(r.Kind, 64)
	}
	if r.ApprovedAt != nil {
		st.ApprovedAt = *r.ApprovedAt
	}
	return st
}

// orgZone is notify's Zone: the organization time zone of core's general settings, read at every use so a change
// applies at once. A failed read answers "" and notify uses its default zone for that call.
func orgZone(d *deps) func(context.Context) string {
	return func(ctx context.Context) string {
		z, err := d.Core.OrgTimeZone(ctx)
		if err != nil {
			d.Log.WarnContext(ctx, "notify: reading the organization time zone failed; using the default", "error", err)
			return ""
		}
		return z
	}
}

// notifyApproverLinks is notify's Config.ApproverLinks (notify INV-13): whether the person proved this address in My account, as the
// response module keeps it. d.Response is read when asked (response is built after notify); a response that does not exist yet is an error, so
// notify skips the approver (fail closed). The error never holds the address.
type notifyApproverLinks struct{ d *deps }

func (l notifyApproverLinks) Linked(ctx context.Context, userID string, ch channel.Type, address string) (bool, error) {
	if l.d.Response == nil {
		return false, errResponseNotReady
	}
	return l.d.Response.Linked(ctx, userID, string(ch), address)
}

// ChatLinkToken is notify's Config.LinkCodes: response makes the token of the confirm link sent to a Zalo personal approver.
func (l notifyApproverLinks) ChatLinkToken(ctx context.Context, userID string, ch channel.Type, address string) (token, name string, err error) {
	if l.d.Response == nil {
		return "", "", errResponseNotReady
	}
	return l.d.Response.ChatLinkToken(ctx, userID, string(ch), address)
}

// DropChatLink is the other half of notify's Config.LinkCodes: an approver removed or given another Zalo loses the old proof.
func (l notifyApproverLinks) DropChatLink(ctx context.Context, actor, userID string, ch channel.Type, address string) error {
	if l.d.Response == nil {
		return errResponseNotReady
	}
	return l.d.Response.DropChatLink(ctx, actor, userID, string(ch), address)
}

// DropLinkToken is the third part of notify's Config.LinkCodes: a confirm link that could not be delivered leaves no token waiting.
func (l notifyApproverLinks) DropLinkToken(ctx context.Context, userID string, ch channel.Type, address, token string) error {
	if l.d.Response == nil {
		return errResponseNotReady
	}
	return l.d.Response.DropLinkToken(ctx, userID, string(ch), address, token)
}

// notifyHits implements notify.HitConnections over the honeypot's export of hits (the one public read that carries conn_count; honeypot
// is built after notify, so it is read when asked). A hit is found by its time: the incident's first_seen is the hit's ts, so one
// narrow window per hit.
type notifyHits struct{ d *deps }

func (h notifyHits) HitConnections(ctx context.Context, hits []notify.HitRef) (map[string]int, error) {
	if h.d.Honeypot == nil {
		return nil, errors.New("honeypot is not ready")
	}
	want := map[time.Time]map[string]bool{} // one export per distinct time, every id of that time in one pass
	for _, r := range hits {
		if want[r.At] == nil {
			want[r.At] = map[string]bool{}
		}
		want[r.At][r.ID] = true
	}
	out := map[string]int{}
	for at, ids := range want {
		w := &hitRows{ids: ids, out: out}
		if err := h.d.Honeypot.ExportHits(ctx, at, at, w); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// hitRows reads the JSON lines ExportHits writes as they come, keeping only id and conn_count of the wanted hits; no more than one
// line is held at a time and a line over maxHitRow is refused.
type hitRows struct {
	ids  map[string]bool
	out  map[string]int
	part []byte
}

const maxHitRow = 1 << 20

func (w *hitRows) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if len(w.part)+len(p) > maxHitRow {
				return 0, errors.New("honeypot hit row too long")
			}
			w.part = append(w.part, p...)
			break
		}
		w.part = append(w.part, p[:i]...)
		var row struct {
			ID        string `json:"id"`
			ConnCount int    `json:"conn_count"`
		}
		if json.Unmarshal(w.part, &row) == nil && w.ids[row.ID] {
			w.out[row.ID] = row.ConnCount
		}
		w.part, p = w.part[:0], p[i+1:]
	}
	return n, nil
}

// newNotify builds the notify service once per database, so the handlers, the deliver job, the event
// subscriptions and the code mailer share it (the Zalo personal adapter keeps its signed-in session and its
// sign-in pause in memory). Events go to and come from deps.Bus. buildServices calls it first with the real
// *deps: Users, Zone and Devices read d.Auth, d.Core and d.Inventory when asked, so notify can exist before
// auth, which takes notify's code mailer.
// BoxAddrs is the box-address provider (d.HostNet): the appliance's own addresses, which core's container cannot see, so no webhook can
// point at the box (issue #62). The token recorder is the response module (notifyTokens, read lazily
// because response is built after notify).
// notifySMTPLoopback is set by the tests of this package only (notify_wiring_test.go): their fake SMTP servers, and the e2e box's,
// listen on 127.0.0.1, which notify refuses as an SMTP server (in a container loopback is core itself).
var notifySMTPLoopback bool

// incidentResolvedSince is notify's ResolvedSince for a module that holds back repeats of an incident key (ids, logs, honeypot): whether the
// incident an event would count on was resolved at or after since with none of its key open. False while notify is off.
func incidentResolvedSince(d *deps) func(ctx context.Context, event string, data any, since time.Time) (bool, error) {
	return func(ctx context.Context, event string, data any, since time.Time) (bool, error) {
		if d.Reg != nil && !d.Reg.Enabled(notify.ModuleID) {
			return false, nil
		}
		return newNotify(d).ResolvedSince(ctx, event, data, since)
	}
}

func newNotify(d *deps) *notify.Service {
	notifyMu.Lock()
	defer notifyMu.Unlock()
	if s := notifyServices[d.DB]; s != nil {
		return s
	}
	c := notify.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Users: notifyUsers{d}, Log: d.Log, Clock: d.Clock,
		Zone: orgZone(d), BaseURL: d.BaseURL, Tokens: notifyTokens{d}, Decisions: responseDecisions{d}, BoxAddrs: machineAddrs(d), SelfAddrs: vedetteSelf(d),
		ApproverLinks: notifyApproverLinks{d}, LinkCodes: notifyApproverLinks{d}, SMTPLoopback: notifySMTPLoopback} // unknown only while a configured vedette-host has never answered (#157)
	if d.Inventory != nil {
		c.Devices = notifyDevices{d.Inventory}
	}
	c.Hits = notifyHits{d}
	c.Sessions = notifyHits{d}
	c.Findings = notifyFindings{d} // d.Findings and the feeds store are built after notify: read when asked
	c.Signals = notifySignals{d}
	if d.Reg != nil { // a nil *modreg.Registry inside the interface would not compare equal to nil, and OnChange would panic
		c.Modules = d.Reg
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		c.Bus = d.Bus
	}
	svc, err := notify.New(c)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	if d.Bus != nil {
		svc.Subscribe(d.Bus) // handlers ignore events while the module is off; the box lives as long as the process
	}
	notifyServices[d.DB] = svc
	return svc
}

// firstAnswerWait is how long a caller of notifyBoxAddrs waits for vedette-host's first answer since core started. The host
// answers state/net in milliseconds; one that does not answer within it leaves the set unknown.
const firstAnswerWait = 2 * time.Second

// notifyBoxAddrs is notify's Config.BoxAddrs over the shared cache of what vedette-host reports (feeds and logs use it too). Once the
// host has answered it reads the last known set and never waits for the host (notify asks at every webhook connection and save); a
// stale set is refreshed in the background, and a host that does not answer leaves the previous set in place. Before a configured
// host's first answer it waits up to firstAnswerWait for that answer (else the first webhook save after a start is a 503 only
// because nothing had asked the host yet); still unknown (known=false), notify refuses every webhook save and connection until it is
// known (fail closed, #157). Without a host (nil cache) the set is empty and known: the container's own interfaces, which notify
// reads itself, are all the box has.
func notifyBoxAddrs(c *hostNetCache) func() ([]netip.Addr, bool) {
	return func() ([]netip.Addr, bool) {
		ps, known := c.SnapshotKnownWithin(firstAnswerWait)
		var out []netip.Addr
		for _, p := range ps {
			out = append(out, p.Addr())
		}
		return out, known
	}
}

// notifyJobs is the Jobs func of the notify entry in wiredModules: the "deliver" job.
func notifyJobs(d deps) []jobs.Job { return newNotify(&d).Jobs() }

// homeFirstRun is findings.HomeSources.FirstRun over notify: the first-run summary Home shows, in the overview's words (findings
// imports neither notify nor its channel types).
func homeFirstRun(svc *notify.Service) func(ctx context.Context, since time.Time) (*findings.FirstRunSummary, error) {
	return func(ctx context.Context, since time.Time) (*findings.FirstRunSummary, error) {
		f, err := svc.FirstRunSummary(ctx, since)
		if err != nil || f == nil {
			return nil, err
		}
		ts := func(t time.Time) *string {
			if t.IsZero() {
				return nil
			}
			s := store.FormatTS(t)
			return &s
		}
		out := &findings.FirstRunSummary{ID: f.ID, Load: f.Load, Title: f.Title, MadeAt: store.FormatTS(f.At), State: f.State, SentAt: ts(f.SentAt),
			Channels: []string{}, DueAt: ts(f.DueAt), Quiet: f.Quiet, Link: f.Link, Later: f.Later}
		for _, c := range f.Channels {
			out.Channels = append(out.Channels, string(c))
		}
		if f.NotSent != nil {
			text, reason := f.NotSent.Text, string(f.NotSent.Reason)
			out.NotSent, out.Reason = &text, &reason
		}
		if f.LaterTitle != "" {
			out.LaterTitle = &f.LaterTitle
		}
		return out, nil
	}
}

// SourceHits implements notify.HitSessions over the same export: the hits of src from through to, oldest first, without test hits,
// at most limit (a trap session is minutes long; the honeypot caps its hits per source and hour).
func (h notifyHits) SourceHits(ctx context.Context, src string, from, to time.Time) ([]notify.SessionHit, error) {
	if h.d.Honeypot == nil {
		return nil, errors.New("honeypot is not ready")
	}
	w := &sourceRows{src: src, limit: 500}
	if err := h.d.Honeypot.ExportHits(ctx, from, to, w); err != nil {
		return nil, err
	}
	return w.out, nil
}

// sourceRows reads the JSON lines ExportHits writes, keeping the hits of one source address, one line held at a time (maxHitRow).
type sourceRows struct {
	src   string
	limit int
	out   []notify.SessionHit
	part  []byte
}

func (w *sourceRows) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if len(w.part)+len(p) > maxHitRow {
				return 0, errors.New("honeypot hit row too long")
			}
			w.part = append(w.part, p...)
			break
		}
		w.part = append(w.part, p[:i]...)
		var row struct {
			ID      string          `json:"id"`
			TS      string          `json:"ts"`
			Kind    string          `json:"kind"`
			Service *string         `json:"service"`
			Label   string          `json:"label"`
			SrcIP   string          `json:"src_ip"`
			IsTest  json.RawMessage `json:"is_test"`
		}
		if json.Unmarshal(w.part, &row) == nil && row.SrcIP == w.src && !jsonTrue(row.IsTest) && len(w.out) < w.limit {
			at, _ := time.Parse(time.RFC3339Nano, row.TS)
			hit := notify.SessionHit{ID: row.ID, At: at, Kind: row.Kind, Label: row.Label}
			if row.Service != nil {
				hit.Service = *row.Service
			}
			w.out = append(w.out, hit)
		}
		w.part, p = w.part[:0], p[i+1:]
	}
	return n, nil
}

// jsonTrue is a JSON value that says yes: true or a number other than 0 (SQLite keeps a flag as an integer).
func jsonTrue(v json.RawMessage) bool {
	s := string(bytes.TrimSpace(v))
	return s == "true" || (s != "" && s != "0" && s != "false" && s != "null" && s != "0.0")
}
