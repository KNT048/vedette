package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn/write"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/modreg"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/logs"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
	"github.com/knt048/vedette/modules/response"
)

// Adapters between the response module's ports and the modules that provide them. They live here because only the binary
// knows both sides (modules/response imports no other module's service, rules/modules.md; only the stdlib-only address check
// modules/logs/signature, D-384).

// ---- core/auth -> response.Users ----

type responseUsers struct{ d *deps }

func (u responseUsers) Lookup(ctx context.Context, id string) (response.User, bool, error) {
	got, err := u.d.Auth.GetUser(ctx, id)
	if e, ok := apierr.As(err); ok && e.Status == 404 {
		return response.User{}, false, nil
	}
	if err != nil {
		return response.User{}, false, err
	}
	return response.User{ID: got.ID, Name: got.Name, Email: got.Email, Role: string(got.Role), TwoStep: got.TwofaMethod != "", Disabled: got.Disabled}, true, nil
}

// ---- core/auth -> response.TwoStep ----

// responseTwoStep checks the two-step code of the person approving (core/auth.VerifyTwoStep, D-98); its errors pass through unchanged.
type responseTwoStep struct{ d *deps }

func (t responseTwoStep) Verify(ctx context.Context, userID, code, purpose, summary string) error {
	_, err := t.d.Auth.VerifyTwoStep(ctx, userID, code, purpose, summary)
	return err
}

// ---- notify -> response.Notifier and response.Webhooks ----

type responseNotifier struct {
	n   *notify.Service
	now func() time.Time
	reg *modreg.Registry // nil in tests that build it by hand: notify counts as on
}

// off is true while the notify module is off (SYS-5): its channels and approvers do not exist then, so an approval link cannot decide.
func (r responseNotifier) off() bool { return r.reg != nil && !r.reg.Enabled(notify.ModuleID) }

var channelNames = map[string]string{"slack": "Slack", "telegram": "Telegram", "zalo": "Zalo OA", "zalo-personal": "Zalo (personal)", "email": "Email", "webhook": "Webhook"}

func (r responseNotifier) Channels(ctx context.Context) ([]response.NotifyChannel, error) {
	if r.off() {
		return nil, nil
	}
	v, err := r.n.Channels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]response.NotifyChannel, 0, len(v.Channels))
	for _, c := range v.Channels {
		out = append(out, response.NotifyChannel{Type: string(c.Type), Label: channelLabel(c), Configured: c.Configured, Enabled: c.Enabled, Approvals: c.Approvals, Approvers: len(c.Approvers)})
	}
	return out, nil
}

func channelLabel(c notify.Channel) string {
	if c.Type == "slack" && c.Fields["label"] != "" {
		return "Slack " + c.Fields["label"]
	}
	return channelNames[string(c.Type)]
}

// Approvers lists the people saved as approvers on a channel (notify.ApprovalChannels: enabled, configured, approvals on).
func (r responseNotifier) Approvers(ctx context.Context, ch string) ([]response.Approver, error) {
	if r.off() {
		return nil, nil
	}
	all, err := r.n.ApprovalChannels(ctx)
	if err != nil {
		return nil, err
	}
	var out []response.Approver
	for _, c := range all {
		if string(c.Type) != ch {
			continue
		}
		for _, a := range c.Approvers {
			out = append(out, response.Approver{UserID: a.UserID, Address: a.Address})
		}
	}
	return out, nil
}

// RequestApproval hands the request to notify.SendApprovalRequest (D-96 (2)) and returns the labels of the channels where at least one
// message arrived. A message that failed is an error as well, so response can say so in its log line; the request itself stays open.
func (r responseNotifier) RequestApproval(ctx context.Context, m response.ApprovalMessage) ([]string, error) {
	types := make([]channel.Type, len(m.Channels))
	for i, t := range m.Channels {
		types[i] = channel.Type(t)
	}
	sev := notify.Medium
	switch m.Risk {
	case response.RiskHigh:
		sev = notify.High
	case response.RiskLow:
		sev = notify.Low
	}
	labels := map[string]string{} // read before the send: the budget may end while it runs, and a label read after would find nothing
	if v, err := r.n.Channels(context.WithoutCancel(ctx)); err == nil {
		for _, c := range v.Channels {
			labels[string(c.Type)] = channelLabel(c)
		}
	}
	sent, err := r.n.SendApprovalRequest(ctx, notify.ApprovalRequest{ID: m.RequestID, Title: m.Title, What: m.What, Action: "Review the change, then approve or reject it. The link works once and ends with the request.",
		Severity: sev, Risk: notify.Risk(m.Risk), Expires: m.Expires, Channels: types, InAppOnly: m.InAppOnly, NoChatButtons: m.NoChatButtons})
	if err != nil {
		// These fail before anything is sent. Any other error may come from writing notify's record of messages that already left.
		if errors.Is(err, notify.ErrModuleOff) || errors.Is(err, notify.ErrApprovalUnavailable) || errors.Is(err, notify.ErrInvalidNotice) || errors.Is(err, ctx.Err()) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", response.ErrSendUnsure, err)
	}
	var out []string
	failed := 0
	for _, v := range sent {
		if !v.OK {
			failed++
			continue
		}
		l := labels[string(v.Channel)]
		if l == "" {
			l = string(v.Channel)
		}
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	if failed > 0 {
		return out, fmt.Errorf("%d of %d message(s) could not be sent", failed, len(sent))
	}
	return out, nil
}

// ---- notify <-> response: approval links ----

// responseLinks lets response check the links notify signed (notify.VerifyApprovalLink: MAC only, never makes a key).
type responseLinks struct{ n *notify.Service }

func (l responseLinks) ID(token string) ([]byte, error) {
	id, err := notify.ParseApprovalToken(token)
	if err != nil {
		return nil, response.ErrLinkInvalid
	}
	return id[:], nil
}

func (l responseLinks) Verify(ctx context.Context, token string, b response.LinkBinding, keyID string) error {
	_, err := l.n.VerifyApprovalLink(ctx, token, notify.Binding{RequestID: b.RequestID, UserID: b.UserID, Channel: b.Channel, ExpiresAt: b.ExpiresAt}, keyID)
	if errors.Is(err, notify.ErrTokenInvalid) {
		return response.ErrLinkInvalid
	}
	return err
}

// notifyTokens is notify.TokenRecorder over the response service: the record of every link and reply code is kept by response (D-96 (1)).
// d.Response is read when asked: notify is built before response.
type notifyTokens struct{ d *deps }

var errResponseNotReady = errors.New("vedette: the response module is not ready to record approval tokens")

func (t notifyTokens) RecordToken(ctx context.Context, id notify.TokenID, b notify.Binding, keyID, address string) error {
	if t.d.Response == nil {
		return errResponseNotReady
	}
	return t.d.Response.RecordLink(ctx, response.LinkRecord{ID: id[:], RequestID: b.RequestID, UserID: b.UserID, Channel: b.Channel, Address: address, KeyID: keyID, ExpiresAt: b.ExpiresAt})
}

func (t notifyTokens) RecordReplyCode(ctx context.Context, c notify.ReplyCode) error {
	if t.d.Response == nil {
		return errResponseNotReady
	}
	return t.d.Response.RecordReplyCode(ctx, response.ReplyCodeRecord{RequestID: c.RequestID, UserID: c.UserID, Address: c.Address, Approve: c.Approve, CodeHash: c.CodeHash, ExpiresAt: c.ExpiresAt})
}

// responseDecisions is notify.Decisions over the response service: a chat listener of notify calls it after it checked the platform, and response
// maps the sender and keeps every gate (D-96 (5), INV-3). d.Response is read when asked: notify is built before response. A refusal comes back as
// a DecisionResult whose Status is the code of the refusal (approver_not_listed, in_app_required ...) and whose Message is the reply for the
// person; only "approved", "pending" and "rejected" are decisions that were recorded (notify CONTRACT POST-8).
type responseDecisions struct{ d *deps }

func (r responseDecisions) Decide(ctx context.Context, c notify.Decision) (notify.DecisionResult, error) {
	if r.d.Response == nil {
		return notify.DecisionResult{}, errResponseNotReady
	}
	out, err := r.d.Response.DecideFromChat(ctx, response.ChatDecision{Channel: string(c.Channel), ExternalID: c.ExternalID, RequestID: c.RequestID, Approve: c.Approve, Code: c.Code})
	if ae, ok := apierr.As(err); ok {
		return notify.DecisionResult{Status: ae.Code, Message: ae.Message}, nil
	}
	if err != nil {
		return notify.DecisionResult{}, err
	}
	return notify.DecisionResult{Status: out.Status, Message: out.Message, RequestID: out.RequestID}, nil
}

// LinkChat hands response a link code that arrived from a chat ID (Zalo personal, D-243); refusals come back as Status/Message like Decide.
func (r responseDecisions) LinkChat(ctx context.Context, c notify.Decision) (notify.DecisionResult, error) {
	if r.d.Response == nil {
		return notify.DecisionResult{}, errResponseNotReady
	}
	out, err := r.d.Response.LinkFromChat(ctx, response.ChatDecision{Channel: string(c.Channel), ExternalID: c.ExternalID, Code: c.Code})
	if ae, ok := apierr.As(err); ok {
		return notify.DecisionResult{Status: ae.Code, Message: ae.Message}, nil
	}
	if err != nil {
		return notify.DecisionResult{}, err
	}
	return notify.DecisionResult{Status: out.Status, Message: out.Message}, nil
}

// Message queues a short text as an incident notice: every enabled channel whose minimum severity it meets gets it.
func (r responseNotifier) Message(ctx context.Context, id, title, text string) error {
	return r.n.Publish(ctx, notify.Notice{ID: id, Kind: notify.KindIncident, Severity: notify.Medium, Title: title, What: text, At: r.now()})
}

type responseWebhooks struct{ n *notify.Service }

func (w responseWebhooks) Target(ctx context.Context) (response.WebhookTarget, bool, error) {
	u, key, ok, err := w.n.WebhookTarget(ctx)
	return response.WebhookTarget{URL: u, SigningKey: key}, ok, err
}

// ---- inventory and findings -> response.Directory ----

type responseDirectory struct {
	inv *inventory.Service
	fnd *findings.Service
}

func (r responseDirectory) Device(ctx context.Context, id string) (response.DeviceInfo, bool, error) {
	d, err := r.inv.Device(ctx, id)
	if errors.Is(err, inventory.ErrNotFound) {
		return response.DeviceInfo{}, false, nil
	}
	if err != nil {
		return response.DeviceInfo{}, false, err
	}
	return deviceInfo(d), true, nil
}

// DevicesOfKind lists every inventory device of the kinds (the gateways: router, firewall), uncapped (inventory.DevicesOfKind, not
// Devices: that one stops at 2000 rows, newest first, and would drop the oldest device, the gateway). An unreadable inventory is an
// error: response refuses the action rather than go on without them.
func (r responseDirectory) DevicesOfKind(ctx context.Context, kinds ...string) ([]response.DeviceInfo, error) {
	l, err := r.inv.DevicesOfKind(ctx, kinds)
	if err != nil {
		return nil, err
	}
	out := make([]response.DeviceInfo, 0, len(l))
	for _, d := range l {
		if !d.TrustedKind() { // D-177: a kind only a passive frame claimed (SSDP, LLDP, DHCP, mDNS) is a hint, not a gateway nobody may block
			continue
		}
		i := response.DeviceInfo{ID: d.ID, IP: d.IP, Kind: d.Kind}
		if d.IP == "—" { // unknown address
			i.IP = ""
		}
		if i.Name = i.IP; d.Hostname != nil && *d.Hostname != "" {
			i.Name = *d.Hostname
		}
		if d.MAC != nil {
			i.MAC = *d.MAC
		}
		out = append(out, i)
	}
	return out, nil
}

func deviceInfo(d inventory.Device) response.DeviceInfo {
	out := response.DeviceInfo{ID: d.ID, IP: d.IP, Kind: d.Kind, Approved: d.Approved}
	if d.IP == "—" { // unknown address
		out.IP = ""
	}
	out.Name = out.IP
	if d.Hostname != nil && *d.Hostname != "" {
		out.Name = *d.Hostname
	}
	if d.MAC != nil {
		out.MAC = *d.MAC
	}
	if d.Vendor != nil {
		out.Vendor = d.Vendor.Value
	}
	out.Seen, _ = time.Parse(time.RFC3339, d.FirstSeen)
	return out
}

// Finding answers the fields a trigger needs. Every finding the box holds comes from the exploited-vulnerability list
// (findings matches the CISA KEV list only), so kev is true; the firewall virtual IP of the trigger is not known without a
// firewall read (part 13b) and stays empty.
func (r responseDirectory) Finding(ctx context.Context, id string) (response.FindingInfo, bool, error) {
	rec, err := r.fnd.Get(ctx, id)
	if errors.Is(err, findings.ErrNotFound) {
		return response.FindingInfo{}, false, nil
	}
	if err != nil {
		return response.FindingInfo{}, false, err
	}
	return response.FindingInfo{ID: rec.ID, AssetID: rec.AssetID, CVE: rec.CVE, Severity: string(rec.Severity), Status: string(rec.Status), KEV: true}, true, nil
}

// ---- core/conn/write -> response.Executor ----

// responseExecutor is the only holder of the writer (FORBID-1): it turns a step of an approved item into core/conn/write's Step and
// the writer's answer into response's. Nothing else in the binary names the writer package.
type responseExecutor struct{ w *write.Writer }

func (e responseExecutor) Execute(ctx context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	r := e.w.Do(ctx, write.Step{ConnectionID: s.ConnectionID, ConnFP: s.ConnFP, ByIdentity: s.ByIdentity, ConnIdentity: s.ConnIdentity, Phase: s.Phase, Tool: s.Tool, Lines: s.Lines, Method: s.Method, URL: s.URL,
		Body: s.Body, Headers: s.Headers, Args: s.Args})
	return response.DeviceResult{Status: response.StepStatus(r.Status), Detail: r.Detail, Output: r.Output}, nil
}

// newResponse builds the response service. serve calls it once, in buildServices, after the services it reads (core/auth, notify,
// inventory, findings, core/conn). Device actions run through core/conn/write: an approved item reaches its device over the
// connection, with a check before and a read-back (D-94, D-95).
func newResponse(d *deps) (*response.Service, error) {
	cfg, err := responseConfig(d)
	if err != nil {
		return nil, err
	}
	svc, err := response.New(cfg)
	if err != nil {
		return nil, err
	}
	if d.Bus != nil {
		svc.Subscribe(d.Bus) // handlers ignore events while the module is off
	}
	return svc, nil
}

// decoyIPs is what responseBoxAddrs asks for the decoy addresses: the honeypot's DecoyIPsRead.
type decoyIPs interface {
	DecoyIPsRead(ctx context.Context) ([]netip.Addr, error)
}

// lateDecoys is the honeypot of deps, read when asked: it is built after response, and there may be none.
type lateDecoys struct{ d *deps }

func (l lateDecoys) DecoyIPsRead(ctx context.Context) ([]netip.Addr, error) {
	if l.d.Honeypot == nil {
		return nil, nil
	}
	return l.d.Honeypot.DecoyIPsRead(ctx)
}

var errHostNetUnknown = errors.New("vedette-host has not reported the addresses of the box yet")

// responseBoxAddrs is response's Config.BoxAddrs: what vedette-host reports for the appliance (the shared cache: read without waiting once the host has answered, else up to firstAnswerWait, D-408) and the
// decoy addresses of the honeypot, the same sources as core/conn's boxSources. A set that is not known (a configured host that has never answered,
// an unreadable honeypot record) is an error, so response refuses instead of checking against a smaller set (D-179 (8), as notify since #157).
func responseBoxAddrs(host func() ([]netip.Addr, bool), decoys decoyIPs) func() ([]netip.Addr, error) {
	return func() ([]netip.Addr, error) {
		out, known := host()
		if !known {
			return nil, errHostNetUnknown
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // Config.BoxAddrs has no context; the honeypot read is one short query
		defer cancel()
		more, err := decoys.DecoyIPsRead(ctx)
		if err != nil {
			return nil, err
		}
		return append(out, more...), nil
	}
}

// responseBoxMACs is response's Config.BoxMACs: the MACs of the decoys and cards that vedette-host reports.
func responseBoxMACs(h *hostMACs) func() ([]string, error) {
	return func() ([]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), hostNetTimeout)
		defer cancel()
		return h.Get(ctx)
	}
}

// responseMailer is response's Config.Mailer (D-191): a link code goes out through notify's code mailer, the SMTP path of the sign-in and
// step-up codes. The step-up message says what is asked, so the code cannot be taken for a sign-in code.
type responseMailer struct{ m notify.CodeMailer }

func (r responseMailer) Available(ctx context.Context) bool { return r.m.Available(ctx) }

func (r responseMailer) SendLinkCode(ctx context.Context, to, code string) error {
	return r.m.SendStepUpCode(ctx, to, code, "link this email address to your Vedette account, so approval links sent to it count as you")
}

// responseConfig is the configuration of the response service: every port wired to the module that provides it.
func responseConfig(d *deps) (response.Config, error) {
	n := newNotify(d)
	cfg := response.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Users: responseUsers{d}, TwoStep: responseTwoStep{d}, Log: d.Log, Clock: d.Clock,
		Notifier: responseNotifier{n: n, now: d.Clock, reg: d.Reg}, Links: responseLinks{n}, Webhooks: responseWebhooks{n}, Directory: responseDirectory{inv: d.Inventory, fnd: d.Findings},
		Mailer: responseMailer{n.CodeMailer()}, BaseURL: d.BaseURL} // the block list address a firewall pulls (empty on loopback: a relative path)
	cfg.BoxAddrs = responseBoxAddrs(notifyBoxAddrs(d.HostNet), lateDecoys{d}) // D-179 (6), (8): the decoys and the host's addresses are the box too, so an action aimed at one is never_touch
	cfg.MachineAddrs, cfg.SelfAddrs = machineAddrs(d), vedetteSelf(d)         // D-446 for webhook_call, as notify's webhook channel
	var hostState netStateReader
	if d.HostSocket != "" {
		hostState = hostclient.New(d.HostSocket)
	}
	hm := &hostMACs{r: hostState, now: d.Clock, report: infraReport(d)} // D-450 review: new gateways, resolvers and gateway MACs are reported
	cfg.BoxMACs = responseBoxMACs(hm)
	cfg.HostInfra = func() ([]response.HostInfra, error) { // D-325: the box's gateway and DNS servers are never-touch too
		ctx, cancel := context.WithTimeout(context.Background(), hostNetTimeout)
		defer cancel()
		return hm.Infra(ctx)
	}
	if d.Conn != nil { // a nil *conn.Service inside the interface would not compare equal to nil
		cfg.Connections = responseConnections{d.Conn}
		w, err := write.New(write.Config{Conns: d.Conn})
		if err != nil {
			return cfg, err
		}
		cfg.Executor = responseExecutor{w}
	}
	if d.AI != nil && d.Findings != nil && d.Inventory != nil { // plans for open critical findings (13b-11): the AI has no tool, response checks every proposal
		cfg.Planner = responsePlanner{svc: d.AI, facts: d.AIFacts, log: d.Log}
		cfg.Critical = responseCritical{fnd: d.Findings, inv: findingsInventory{d.Inventory}}.list
	}
	if d.AI != nil { // config_read evidence: a read the box itself recorded, at most 24 hours old, through the connection it names (D-311)
		cfg.Evidence.ConfigRead = aiConfigRead(d.AI)
	}
	// ioc_hit evidence: a known-bad connection the Logs module recorded (L4, D-213), with no connection (D-337); Logs off = not found
	if lg := logsService(*d); lg != nil {
		cfg.Evidence.IocHit = logsIocEvidence(lg, func() bool { return d.Reg == nil || d.Reg.Enabled("logs") })
	}
	if d.Reg != nil {
		cfg.Modules = d.Reg
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		cfg.Bus = d.Bus
	}
	if lg := logsService(*d); lg != nil { // nil without a logs.db (a test that builds deps by hand)
		cfg.LogCounts = responseLogCounts{svc: lg, reg: d.Reg}
	}
	return cfg, nil
}

// responseLogCounts is response's read port of the Logs module for the log_threshold trigger (#332, D-287, D-288): the declared
// sources (logs.Service.SourceNames, the narrow read of logs_sources), logs.Service.Counts and logs.Service.TopAddresses. The
// Logs module off answers no source (and Counts, TopAddresses an error), so the trigger makes no event (SYS-5), like any trigger
// whose module is off.
type responseLogCounts struct {
	svc *logs.Service
	reg interface{ Enabled(id string) bool }
}

func (r responseLogCounts) off() bool { return r.reg != nil && !r.reg.Enabled("logs") }

func (r responseLogCounts) Sources(ctx context.Context) ([]response.LogSource, error) {
	if r.off() {
		return nil, nil
	}
	v, err := r.svc.SourceNames(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]response.LogSource, 0, len(v))
	for _, s := range v {
		out = append(out, response.LogSource{ID: s.ID, Name: s.Name})
	}
	return out, nil
}

func (r responseLogCounts) Counts(ctx context.Context, sourceID, signature string, window time.Duration) (int, error) {
	if r.off() {
		return 0, response.ErrLogsOff
	}
	return r.svc.Counts(ctx, sourceID, signature, window)
}

func (r responseLogCounts) TopAddresses(ctx context.Context, sourceID, signature string, window time.Duration, n int) ([]response.LogAddress, error) {
	if r.off() {
		return nil, response.ErrLogsOff
	}
	v, err := r.svc.TopAddresses(ctx, sourceID, signature, window, n)
	if err != nil {
		return nil, err
	}
	out := make([]response.LogAddress, 0, len(v))
	for _, a := range v {
		out = append(out, response.LogAddress{Addr: a.Addr, Count: a.Count})
	}
	return out, nil
}

// responseJobs is the Jobs func of the response entry in wiredModules: the "evaluate" and "sweep" jobs.
func responseJobs(d deps) []jobs.Job { return d.Response.Jobs() }
