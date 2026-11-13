package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Zalo personal set-up (D-447): a real QR sign-in, the account's friends and groups for the recipient and the approvers, and the code
// an approver replies with to prove their Zalo account. The sign-in lives in memory, one at a time for the whole box (each sign-in is a
// new web session of the account, and Zalo may lock an account that signs in often): it waits ZaloQRLife for the scan and the
// confirmation, and a finished one waits zaloLoginKeep for Save, then it is dropped. Starts are rationed per box.

const (
	zaloLoginKeep     = 10 * time.Minute // a finished sign-in waits this long for Save
	zaloLoginStart    = 45 * time.Second // the QR code itself: four requests to id.zalo.me
	zaloLoginFinish   = 45 * time.Second // checksession, userinfo and the first sign-in after the confirmation
	zaloLoginGap      = 30 * time.Second // between two starts
	zaloLoginsPerHour = 5
	zaloLookups       = 20 // contact lists and look-ups per zaloLookupEvery, per box
	zaloLookupEvery   = 10 * time.Minute
	zaloCodeDMs       = 10               // link-code messages per zaloLookupEvery, per box: a save that adds many approvers does not burst them (D-46)
	zaloCodeLife      = 10 * time.Minute // response keeps the code that long (D-191)
	zaloCodeSendWait  = 30 * time.Second
	zaloQueryMax      = 200
)

// ZaloLogin is the state of the signed-in administrator's QR sign-in (GET /notify/zalo/login). State: none, waiting (show QR), scanned
// (Name is who scanned it), signed_in (Name is the account), expired, declined, failed (Error says why).
type ZaloLogin struct {
	State     string               `json:"state"`
	QR        *channel.ZaloQRImage `json:"qr"`
	Name      string               `json:"name"`
	Error     string               `json:"error"`
	ExpiresAt *string              `json:"expires_at"`
}

// ZaloContacts is the account's friends and groups (GET /notify/zalo/contacts).
type ZaloContacts struct {
	Friends []channel.ZaloContact `json:"friends"`
	Groups  []channel.ZaloContact `json:"groups"`
}

// ZaloFound is the person or group behind a look-up (POST /notify/zalo/resolve). Member is false for a group the account is not in.
type ZaloFound struct {
	channel.ZaloContact
	Member bool `json:"member"`
}

// ZaloApprover is the link state of one approver of the Zalo personal channel (GET /notify/zalo/approvers): linked, sending (the confirm
// link is on its way), waiting (sent, not confirmed yet), not_sent (never sent, failed, or expired; Error says which). Self marks the
// administrator asking; BoxAccount, that the address is the box's own signed-in Zalo account (the QR sign-in proved it is theirs, as far
// as the box last signed in). Only when both hold is no message sent: the answer of POST …/code carries the confirm page (Link) and they
// confirm it in their session. Any other address of their own gets the message like everyone's (D-447 review round 2).
type ZaloApprover struct {
	UserID     string  `json:"user_id"`
	Address    string  `json:"address"`
	Name       string  `json:"name"`
	State      string  `json:"state"`
	SentAt     *string `json:"sent_at"`
	Error      string  `json:"error"`
	Self       bool    `json:"self"`
	BoxAccount bool    `json:"box_account"`
	Link       string  `json:"link,omitempty"`
}

// zaloQRFlow is one QR sign-in (channel.ZaloQR); a test replaces how it starts (Service.zaloStartQR).
type zaloQRFlow interface {
	QR() channel.ZaloQRImage
	WaitScan(ctx context.Context) (string, error)
	WaitConfirm(ctx context.Context) error
	Finish(ctx context.Context) (channel.ZaloSignedIn, error)
}

func startZaloQR(ctx context.Context, c *http.Client) (zaloQRFlow, error) {
	q, err := channel.StartZaloQR(ctx, c)
	if err != nil {
		return nil, err
	}
	return q, nil
}

type zaloLoginRun struct {
	owner   string // email of the administrator
	state   string
	qr      channel.ZaloQRImage
	name    string
	errText string
	ends    time.Time // waiting/scanned: the code's end; signed_in: when it is dropped
	signed  channel.ZaloSignedIn
	stop    context.CancelFunc
}

func (r *zaloLoginRun) live(now time.Time) bool {
	switch r.state {
	case "starting", "waiting", "scanned", "signed_in":
		return now.Before(r.ends)
	}
	return false
}

type zaloCodeSent struct {
	address string
	at      time.Time
	sending bool
	errText string
}

// zaloSetup is the in-memory state of the set-up: the one sign-in, the rations, the codes sent per approver (user ID).
type zaloSetup struct {
	mu      sync.Mutex
	cur     *zaloLoginRun
	starts  []time.Time
	lookups []time.Time
	dms     []time.Time
	codes   map[string]zaloCodeSent
	bg      sync.WaitGroup // code sends after a save
}

// ration keeps the times of the last hour (or of per) and says whether one more is allowed; retry is when the oldest leaves the window.
func ration(l *[]time.Time, now time.Time, n int, per time.Duration) (ok bool, retry time.Duration) {
	*l = slices.DeleteFunc(*l, func(t time.Time) bool { return now.Sub(t) >= per })
	if len(*l) >= n {
		return false, per - now.Sub((*l)[0])
	}
	*l = append(*l, now)
	return true, 0
}

func retryErr(status int, code, msg string, wait time.Duration) error {
	secs := int((wait + time.Second - 1) / time.Second)
	return apierr.New(status, code, fmt.Sprintf(msg, (secs+59)/60)).With("retry_after", secs)
}

// StartZaloLogin starts a QR sign-in for the administrator who (POST /notify/zalo/login). Another administrator's sign-in in progress is
// 409 login_busy; more than one start in 30 s or 5 in an hour is 429 (repeated sign-ins can get the account locked, D-46).
func (s *Service) StartZaloLogin(ctx context.Context, who string) (ZaloLogin, error) {
	st, now := &s.zalo, s.now() // the rations run on the service clock; the timers of a sign-in on the wall clock
	st.mu.Lock()
	if r := st.cur; r != nil && r.owner != who && r.live(time.Now()) {
		st.mu.Unlock()
		return ZaloLogin{}, apierr.New(http.StatusConflict, "login_busy", "Another administrator is signing in to Zalo now. Try again in a few minutes.")
	}
	if n := len(st.starts); n > 0 && now.Sub(st.starts[n-1]) < zaloLoginGap {
		wait := zaloLoginGap - now.Sub(st.starts[n-1])
		st.mu.Unlock()
		secs := int((wait + time.Second - 1) / time.Second)
		return ZaloLogin{}, apierr.New(http.StatusTooManyRequests, "login_too_soon", fmt.Sprintf("Wait %d seconds before asking for a new QR code.", secs)).With("retry_after", secs)
	}
	if ok, wait := ration(&st.starts, now, zaloLoginsPerHour, time.Hour); !ok {
		st.mu.Unlock()
		return ZaloLogin{}, retryErr(http.StatusTooManyRequests, "too_many_logins", "Zalo may lock an account that signs in too often. Try again in %d minutes.", wait)
	}
	if st.cur != nil && st.cur.stop != nil {
		st.cur.stop()
	}
	base, stop := context.WithCancel(context.WithoutCancel(ctx))
	run := &zaloLoginRun{owner: who, state: "starting", ends: time.Now().Add(zaloLoginStart), stop: stop}
	st.cur = run
	st.mu.Unlock()

	sctx, cancel := context.WithTimeout(base, zaloLoginStart)
	qr, err := s.zaloStartQR(sctx, s.cfg.HTTPClient)
	cancel()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.cur != run { // cancelled, or replaced by a newer start of the same administrator
		stop()
		return ZaloLogin{State: "none"}, nil
	}
	if err != nil {
		stop()
		run.state, run.errText = "failed", userText(err)
		s.noteZaloLogin(ctx, who, "no QR code: "+run.errText)
		return ZaloLogin{}, apierr.New(http.StatusBadGateway, "zalo_unreachable", "Zalo did not give a QR code: "+run.errText+" Try again in a minute.")
	}
	run.state, run.qr, run.ends = "waiting", qr.QR(), time.Now().Add(channel.ZaloQRLife)
	s.zalo.bg.Go(func() { s.driveZaloLogin(base, stop, run, qr) })
	return run.view(), nil
}

// driveZaloLogin waits for the scan and the confirmation, then finishes the sign-in. A run that was replaced or cancelled changes nothing.
func (s *Service) driveZaloLogin(base context.Context, stop context.CancelFunc, run *zaloLoginRun, qr zaloQRFlow) {
	defer stop()
	set := func(f func()) bool {
		s.zalo.mu.Lock()
		defer s.zalo.mu.Unlock()
		if s.zalo.cur != run {
			return false
		}
		f()
		return true
	}
	qctx, cancel := context.WithDeadline(base, run.ends)
	defer cancel()
	name, err := qr.WaitScan(qctx)
	if err == nil && set(func() { run.state, run.name = "scanned", name }) {
		err = qr.WaitConfirm(qctx)
	}
	var signed channel.ZaloSignedIn
	if err == nil {
		fctx, fcancel := context.WithTimeout(base, zaloLoginFinish)
		signed, err = qr.Finish(fctx)
		fcancel()
	}
	if base.Err() != nil { // cancelled: not a result
		return
	}
	note := ""
	ok := set(func() {
		switch {
		case err == nil:
			run.state, run.name, run.signed, run.ends = "signed_in", signed.Name, signed, time.Now().Add(zaloLoginKeep)
			note = "signed in as " + signed.Name
		case errors.Is(err, channel.ErrZaloQRExpired):
			run.state, note = "expired", "the QR code expired"
		case errors.Is(err, channel.ErrZaloQRDeclined):
			run.state, note = "declined", "declined in the Zalo app"
		default:
			run.state, run.errText = "failed", userText(err)
			note = "failed: " + run.errText
		}
	})
	if ok {
		s.noteZaloLogin(base, run.owner, note)
	}
}

func (s *Service) noteZaloLogin(ctx context.Context, who, detail string) {
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		return s.record(ctx, tx, who, "notify.zalo_login", string(channel.ZaloPersonal), clip("QR sign-in: "+detail, 400))
	})
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: zalo-personal: a sign-in could not be noted", "error", err.Error())
	}
}

func (r *zaloLoginRun) view() ZaloLogin {
	v := ZaloLogin{State: r.state, Name: r.name, Error: r.errText}
	if r.state == "starting" {
		v.State = "waiting"
	}
	if r.state == "waiting" || r.state == "scanned" {
		q := r.qr
		v.QR = &q
		at := store.FormatTS(r.ends)
		v.ExpiresAt = &at
	}
	return v
}

// ZaloLoginState is GET /notify/zalo/login: the sign-in of who, or state none.
func (s *Service) ZaloLoginState(who string) ZaloLogin {
	s.zalo.mu.Lock()
	defer s.zalo.mu.Unlock()
	r := s.zalo.cur
	if r == nil || r.owner != who {
		return ZaloLogin{State: "none"}
	}
	if r.state == "signed_in" && !time.Now().Before(r.ends) {
		s.zalo.cur = nil
		return ZaloLogin{State: "none"}
	}
	return r.view()
}

// CancelZaloLogin is DELETE /notify/zalo/login: the sign-in of who ends (a finished one is dropped unsaved).
func (s *Service) CancelZaloLogin(who string) {
	s.zalo.mu.Lock()
	defer s.zalo.mu.Unlock()
	if r := s.zalo.cur; r != nil && r.owner == who {
		r.stop()
		s.zalo.cur = nil
	}
}

// signedIn returns who's finished sign-in, if any (Save takes its session).
func (s *Service) signedIn(who string) (*zaloLoginRun, bool) {
	s.zalo.mu.Lock()
	defer s.zalo.mu.Unlock()
	r := s.zalo.cur
	if r == nil || r.owner != who || r.state != "signed_in" || !time.Now().Before(r.ends) {
		return nil, false
	}
	return r, true
}

// dropLogin forgets run once its session was saved.
func (s *Service) dropLogin(run *zaloLoginRun) {
	s.zalo.mu.Lock()
	defer s.zalo.mu.Unlock()
	if s.zalo.cur == run {
		s.zalo.cur = nil
	}
}

// zaloAccount is the session the look-ups use: who's finished sign-in, else the saved channel's (its sender: same session and pause).
func (s *Service) zaloAccount(ctx context.Context, who string) (channel.Sender, error) {
	if r, ok := s.signedIn(who); ok {
		return r.signed.Account, nil
	}
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.ZaloPersonal)
	if err != nil {
		return nil, err
	}
	if !c.Configured || c.SecretID == "" {
		return nil, apierr.New(http.StatusConflict, "no_session", "Sign in with the QR code first: finding groups and people needs the Zalo account.")
	}
	return s.savedSender(ctx, c, nil)
}

func (s *Service) takeLookup() error {
	s.zalo.mu.Lock()
	ok, wait := ration(&s.zalo.lookups, s.now(), zaloLookups, zaloLookupEvery)
	s.zalo.mu.Unlock()
	if !ok {
		return retryErr(http.StatusTooManyRequests, "too_many_lookups", "Too many Zalo look-ups in a short time (Zalo may lock the account). Try again in %d minutes.", wait)
	}
	return nil
}

// zaloAPIError says what a failed look-up means for the administrator.
func zaloAPIError(err error) error {
	if _, ok := apierr.As(err); ok {
		return err
	}
	var ce *channel.ConfigError
	switch {
	case errors.Is(err, channel.ErrZaloNotFound):
		return apierr.New(http.StatusNotFound, "not_found", "Nothing was found. Check the link or the number; a person can hide from search by phone number in Zalo's privacy settings.")
	case errors.As(err, &ce) && ce.Code == "bad_query":
		return badRequest("bad_query", ce.Msg)
	case errors.Is(err, errSecretUnreadable):
		return apierr.New(http.StatusConflict, "no_session", "The saved Zalo session cannot be read. Sign in with the QR code again.")
	}
	return apierr.New(http.StatusBadGateway, "zalo_failed", "Zalo did not answer the look-up: "+userText(err))
}

// ListZaloContacts is GET /notify/zalo/contacts.
func (s *Service) ListZaloContacts(ctx context.Context, who string) (ZaloContacts, error) {
	acct, err := s.zaloAccount(ctx, who)
	if err != nil {
		return ZaloContacts{}, zaloAPIError(err)
	}
	if err := s.takeLookup(); err != nil {
		return ZaloContacts{}, err
	}
	f, g, err := channel.ZaloContacts(ctx, acct)
	if err != nil {
		return ZaloContacts{}, zaloAPIError(err)
	}
	if f == nil {
		f = []channel.ZaloContact{}
	}
	if g == nil {
		g = []channel.ZaloContact{}
	}
	return ZaloContacts{Friends: f, Groups: g}, nil
}

const badQueryMsg = "Enter a group invite link (https://zalo.me/g/…), a phone number such as 0912345678, or a Zalo ID."

// ResolveZalo is POST /notify/zalo/resolve: a group invite link, a phone number, or a numeric Zalo ID (taken as a person, no look-up).
func (s *Service) ResolveZalo(ctx context.Context, who, query string) (ZaloFound, error) {
	q := strings.TrimSpace(query)
	_, link := channel.ZaloInviteLink(q)
	_, phone := channel.ZaloPhone(q)
	switch {
	case len(q) == 0 || len(q) > zaloQueryMax:
		return ZaloFound{}, badRequest("bad_query", badQueryMsg)
	case !link && !phone && zaloIDRE.MatchString(q):
		return ZaloFound{ZaloContact: channel.ZaloContact{ID: q}, Member: true}, nil
	case !link && !phone:
		return ZaloFound{}, badRequest("bad_query", badQueryMsg)
	}
	acct, err := s.zaloAccount(ctx, who)
	if err != nil {
		return ZaloFound{}, zaloAPIError(err)
	}
	if err := s.takeLookup(); err != nil {
		return ZaloFound{}, err
	}
	if link {
		g, member, err := channel.ZaloGroupByLink(ctx, acct, q)
		if err != nil {
			return ZaloFound{}, zaloAPIError(err)
		}
		return ZaloFound{ZaloContact: g, Member: member}, nil
	}
	p, err := channel.ZaloFindPhone(ctx, acct, q)
	if err != nil {
		return ZaloFound{}, zaloAPIError(err)
	}
	return ZaloFound{ZaloContact: p, Member: true}, nil
}

// ZaloApprovers is GET /notify/zalo/approvers: each saved approver of the Zalo personal channel and whether their Zalo is linked; who is
// the administrator asking (their own row is Self).
func (s *Service) ZaloApprovers(ctx context.Context, who string) ([]ZaloApprover, error) {
	list, err := loadApprovers(ctx, s.cfg.DB.Reader(), channel.ZaloPersonal)
	if err != nil {
		return nil, err
	}
	box := s.knownBoxAccount(ctx)
	out := make([]ZaloApprover, 0, len(list))
	for _, a := range list {
		out = append(out, s.approverState(ctx, a, who, box))
	}
	return out, nil
}

// knownBoxAccount is the uid of the box's own Zalo account as the saved channel's last sign-in named it, without the network ("" unknown).
func (s *Service) knownBoxAccount(ctx context.Context) string {
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.ZaloPersonal)
	if err != nil || !c.Configured || c.SecretID == "" {
		return ""
	}
	snd, err := s.savedSender(ctx, c, nil)
	if err != nil {
		return ""
	}
	return channel.ZaloKnownSelf(snd)
}

// isBoxAccount says whether address is the box's own signed-in Zalo account, signing in if needed; an error is no (the message is sent).
func (s *Service) isBoxAccount(ctx context.Context, c channelRow, address string) bool {
	snd, err := s.savedSender(ctx, c, nil)
	if err != nil {
		return false
	}
	self, err := s.zaloSelf(ctx, snd)
	return err == nil && self != "" && self == address
}

// isUser says whether the user userID is the administrator who (an email); an error or no such user is no.
func (s *Service) isUser(ctx context.Context, userID, who string) bool {
	u, ok, err := s.cfg.Users.Lookup(ctx, userID)
	return err == nil && ok && strings.EqualFold(u.Email, who)
}

func (s *Service) approverState(ctx context.Context, a Approver, who, box string) ZaloApprover {
	v := ZaloApprover{UserID: a.UserID, Address: a.Address, Name: a.Name, State: "not_sent", Self: s.isUser(ctx, a.UserID, who), BoxAccount: box != "" && box == a.Address}
	if s.cfg.ApproverLinks != nil {
		if ok, err := s.cfg.ApproverLinks.Linked(ctx, a.UserID, channel.ZaloPersonal, a.Address); err == nil && ok {
			v.State = "linked"
			return v
		}
	}
	s.zalo.mu.Lock()
	rec, ok := s.zalo.codes[a.UserID]
	s.zalo.mu.Unlock()
	if !ok || rec.address != a.Address {
		return v
	}
	if !rec.at.IsZero() {
		at := store.FormatTS(rec.at)
		v.SentAt = &at
	}
	switch {
	case rec.sending:
		v.State = "sending"
	case rec.errText != "":
		v.Error = rec.errText
	case time.Since(rec.at) < zaloCodeLife:
		v.State = "waiting"
	default:
		v.Error = "The link expired. Send a new one."
	}
	return v
}

// SendZaloCode is POST /notify/zalo/approvers/{user_id}/code: a new confirm link for that approver (the old one stops working), sent to
// their Zalo. Only for the administrator's own row whose address is the box's own signed-in Zalo account is nothing sent: the answer
// carries the link (Link) and they confirm it in this session, through the same page and check as anyone (D-447). Their own row with any
// other Zalo gets the message, so a wrongly picked friend never becomes their identity without that account's link being opened.
func (s *Service) SendZaloCode(ctx context.Context, actor, userID string) (ZaloApprover, error) {
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.ZaloPersonal)
	if err != nil {
		return ZaloApprover{}, err
	}
	if !zaloReady(c) {
		return ZaloApprover{}, apierr.New(http.StatusConflict, "channel_not_ready", `Save the Zalo (personal) channel turned on, with "Approve actions from this channel", first.`)
	}
	list, err := loadApprovers(ctx, s.cfg.DB.Reader(), channel.ZaloPersonal)
	if err != nil {
		return ZaloApprover{}, err
	}
	i := slices.IndexFunc(list, func(a Approver) bool { return a.UserID == userID })
	if i < 0 {
		return ZaloApprover{}, apierr.New(http.StatusNotFound, "not_listed", "This person is not an approver on the Zalo channel. Save the channel first.")
	}
	a := list[i]
	if s.isUser(ctx, a.UserID, actor) && s.isBoxAccount(ctx, c, a.Address) {
		token, err := s.linkToken(ctx, a)
		if err != nil {
			return ZaloApprover{}, err
		}
		if err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
			return s.record(ctx, tx, actor, "notify.zalo_link_code", string(channel.ZaloPersonal), clip("a confirm link was made for the administrator's own Zalo "+a.Address+" (no message sent)", 400))
		}); err != nil {
			return ZaloApprover{}, err
		}
		v := s.approverState(ctx, a, actor, a.Address)
		v.Link = zaloLinkPath(token)
		return v, nil
	}
	if err := s.sendLinkCode(ctx, actor, c, a); err != nil {
		return ZaloApprover{}, err
	}
	return s.approverState(ctx, a, actor, s.knownBoxAccount(ctx)), nil
}

func zaloLinkPath(token string) string { return "/link/zalo?c=" + url.QueryEscape(token) }

// linkToken asks response for the token of a new confirm link (D-191: single use, 10 minutes, five wrong tries; a new one replaces the
// old). A refusal of response (a new link too soon, already linked, Response off) is returned as it is.
func (s *Service) linkToken(ctx context.Context, a Approver) (string, error) {
	if s.cfg.LinkCodes == nil {
		return "", apierr.New(http.StatusServiceUnavailable, "link_unavailable", "Approvers cannot be linked now: the Response module is off.")
	}
	token, _, err := s.cfg.LinkCodes.ChatLinkToken(ctx, a.UserID, channel.ZaloPersonal, a.Address)
	return token, err
}

// sendLinkCode sends a new confirm link to the approver's Zalo from the channel's account: "open this link and sign in to Vedette as
// <name>". Only that person, signed in, can confirm it (response ConfirmLink). The link needs the address people open Vedette at
// (Config.BaseURL). A failed send is kept as the approver's state. The token is never logged nor audited.
func (s *Service) sendLinkCode(ctx context.Context, actor string, c channelRow, a Approver) error {
	if s.cfg.LinkCodes == nil {
		return apierr.New(http.StatusServiceUnavailable, "link_unavailable", "Approvers cannot be linked now: the Response module is off.")
	}
	if s.baseURL() == "" {
		err := apierr.New(http.StatusServiceUnavailable, "no_base_url", "Vedette does not know the address people open it at, so no confirm link can be sent.")
		s.markCode(a, zaloCodeSent{address: a.Address, errText: err.Message})
		return err
	}
	s.zalo.mu.Lock()
	ok, wait := ration(&s.zalo.dms, s.now(), zaloCodeDMs, zaloLookupEvery)
	s.zalo.mu.Unlock()
	if !ok {
		err := retryErr(http.StatusTooManyRequests, "too_many_codes", "Too many links were sent from this Zalo account in a short time (Zalo may lock it). Send again in %d minutes.", wait)
		s.markCode(a, zaloCodeSent{address: a.Address, errText: refusalText(err)})
		return err
	}
	s.markCode(a, zaloCodeSent{address: a.Address, sending: true})
	token, name, err := s.cfg.LinkCodes.ChatLinkToken(ctx, a.UserID, channel.ZaloPersonal, a.Address)
	if err != nil {
		s.markCode(a, zaloCodeSent{address: a.Address, errText: "No link was made: " + refusalText(err)})
		return err
	}
	sent := s.deliverLink(ctx, c, a, s.link(zaloLinkPath(token)), name)
	s.markCode(a, sent)
	detail := "a confirm link was sent to Zalo " + a.Address
	if sent.errText != "" {
		detail = "a confirm link could not be sent to Zalo " + a.Address + ": " + sent.errText
	}
	if u, ok, uerr := s.cfg.Users.Lookup(ctx, a.UserID); uerr == nil && ok {
		detail += " (approver " + u.Email + ")"
	}
	return s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		return s.record(ctx, tx, actor, "notify.zalo_link_code", string(channel.ZaloPersonal), clip(detail, 400))
	})
}

func (s *Service) deliverLink(ctx context.Context, c channelRow, a Approver, link, name string) zaloCodeSent {
	out := zaloCodeSent{address: a.Address, at: time.Now()}
	snd, err := s.savedSender(ctx, c, nil)
	if err == nil {
		var d channel.Sender
		if d, err = s.zaloTo(snd, a.Address); err == nil {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), zaloCodeSendWait)
			who := clip(name, 64)
			text := "Vedette: open this link and sign in to Vedette as " + who + " to link this Zalo account to " + who + ": " + link +
				" It works once, within 10 minutes. If you are not " + who + ", ignore this message."
			_, err = d.Send(sctx, channel.Message{Kind: channel.KindReply, Severity: "info", Title: text})
			cancel()
		}
	}
	if err != nil {
		out.errText = userText(err)
	}
	return out
}

func refusalText(err error) string {
	if ae, ok := apierr.As(err); ok {
		return ae.Message
	}
	return "the link could not be made."
}

func (s *Service) markCode(a Approver, rec zaloCodeSent) {
	s.zalo.mu.Lock()
	defer s.zalo.mu.Unlock()
	if s.zalo.codes == nil {
		s.zalo.codes = map[string]zaloCodeSent{}
	}
	s.zalo.codes[a.UserID] = rec
}

// sendLinkCodesLater sends the codes of approvers a save added or gave a new Zalo, after the save, one after the other (each is a real
// message from the account). The dialog shows them as sending until each is done.
func (s *Service) sendLinkCodesLater(ctx context.Context, actor string, c channelRow, list []Approver) {
	if len(list) == 0 || s.cfg.LinkCodes == nil {
		return
	}
	for _, a := range list {
		s.markCode(a, zaloCodeSent{address: a.Address, sending: true})
	}
	bg := context.WithoutCancel(ctx)
	s.zalo.bg.Go(func() {
		for _, a := range list {
			if s.isUser(bg, a.UserID, actor) && s.isBoxAccount(bg, c, a.Address) { // the box's own account: they confirm in their session
				s.zalo.mu.Lock()
				delete(s.zalo.codes, a.UserID)
				s.zalo.mu.Unlock()
				continue
			}
			if err := s.sendLinkCode(bg, actor, c, a); err != nil {
				s.cfg.Log.DebugContext(bg, "notify: zalo-personal: a link code was not sent", "error", err.Error())
			}
		}
	})
}

// zaloIDRE is a Zalo user or group ID typed as it is.
var zaloIDRE = approverAddr[channel.ZaloPersonal].re
