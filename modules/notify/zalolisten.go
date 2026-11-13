package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/modules/notify/channel"
)

// Approvals by Zalo personal reply codes, the receive half (slice 4b, D-243; docs/specs/approval-tokens.md 7, 7.1). EXPERIMENTAL: the
// message connection of the Zalo web client is reverse-engineered and not yet checked against a real account. The job "zalo-listen"
// opens it OUT over the channel's session (no inbound port, FORBID-4) while the module is on, the Zalo personal channel is configured,
// enabled and takes approvals, and the Decisions port and the token recorder are wired (the conditions under which codes are sent at
// all, replycode.go; while it is disconnected or waiting, replies are not read). A direct text that has the form of a reply code goes
// to Decisions with the sender's user ID; response matches the code against the records of that sender and keeps every gate. Nothing
// else a sender writes decides or links anything: a Zalo account becomes an approver's only through the confirm link (D-447).
// notify answers privately, only a listed approver, and only a few times per approver.

const (
	zaloListenJob    = "zalo-listen"
	zaloListenEvery  = 30 * time.Second // the scheduler starts the listener again after it stopped
	zaloWatchEvery   = 30 * time.Second // how often a live connection checks that its channel is unchanged
	zaloWorkers      = telegramWorkers
	zaloHealthy      = 10 * time.Minute // a connection that lived this long clears the failure count
	zaloRetryMax     = 30 * time.Minute // the longest wait between failed connections (D-46: an account that misbehaves can be locked)
	zaloReplacedWait = 10 * time.Minute // after another client took the account over: do not take it back at once
	zaloAnswerWait   = 20 * time.Second // one private answer: it may wait for a send in progress and sign in
	zaloNotesPerHour = 20               // audit rows for messages from non-approvers, in all
	zaloNoteEvery    = 24 * time.Hour   // per sender
	zaloNoteSenders  = 1000             // senders remembered for zaloNoteEvery
	zaloAnswers      = 5                // private answers per approver per zaloAnswerEvery; more replies are not answered
	zaloAnswerEvery  = 10 * time.Minute
)

var errZaloChanged = errors.New("notify: zalo-personal: the channel changed")

// zaloInbox is an open message connection (channel.ZaloConn); a test replaces how it is opened (Service.zaloListen).
type zaloInbox interface {
	Run(ctx context.Context, take func(channel.ZaloText)) error
	Close()
}

func openZaloInbox(ctx context.Context, snd channel.Sender) (zaloInbox, error) {
	c, err := channel.ZaloListen(ctx, snd)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// approvalsReady says whether the Zalo personal channel takes approvals now.
func approvalsReady(c channelRow) bool { return c.Configured && c.Enabled && c.Approvals }

// listenZalo is the Run of the job "zalo-listen". It returns nil when nothing is to be read, the channel changed or ctx ended, and an
// error (never with the session in it) when the connection could not be opened or ended badly. Between failed connections it waits
// 30 s doubling to 30 minutes, after a takeover by another client 10 minutes, during a sign-in pause until the pause ends; the waits
// survive the restarts of the job (s.zaloRetry).
func (s *Service) listenZalo(ctx context.Context) error {
	if s.cfg.Decisions == nil || s.cfg.Tokens == nil {
		return nil
	}
	c, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.ZaloPersonal)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("notify: zalo listener: %w", err)
	}
	if !approvalsReady(c) || !s.zaloRetry.due(c.Rev, time.Now()) {
		return nil
	}
	started := time.Now()
	err = s.serveZalo(ctx, c)
	if ctx.Err() != nil || errors.Is(err, errZaloChanged) {
		return nil
	}
	s.zaloRetry.after(err, time.Since(started), time.Now())
	if err != nil {
		return fmt.Errorf("notify: zalo listener: %w", err)
	}
	return nil
}

// serveZalo runs one connection until it ends, the channel changes or ctx ends.
func (s *Service) serveZalo(ctx context.Context, c channelRow) error {
	snd, err := s.savedSender(ctx, c, nil) // the cached sender: the listener shares its session and its sign-in pause
	if err != nil {
		return err
	}
	conn, err := s.zaloListen(ctx, snd)
	if err != nil {
		return err
	}
	defer conn.Close()
	cctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go s.watchChannel(cctx, cancel, channel.ZaloPersonal, c.Rev, approvalsReady, zaloWatchEvery, errZaloChanged)
	sem := make(chan struct{}, zaloWorkers)
	var wg sync.WaitGroup
	defer wg.Wait()
	err = conn.Run(cctx, func(m channel.ZaloText) { s.takeZaloText(ctx, snd, c, m, sem, &wg) })
	if cause := context.Cause(cctx); ctx.Err() == nil && errors.Is(cause, errZaloChanged) {
		return errZaloChanged
	}
	return err
}

// takeZaloText handles one direct text on the read loop; Decide and the answer run on a worker. A text that is not a reply code
// decides nothing: from a sender who is not a listed approver it is noted in the audit log with the sender's user ID (that is how an
// admin finds the user ID of a new approver), from an approver it is ignored. A reply code from anyone goes to Decide (response refuses
// and logs a sender who is not listed, spec 7.1); only a listed approver gets an answer, so a stranger cannot make the box write to
// accounts of their choosing.
func (s *Service) takeZaloText(ctx context.Context, snd channel.Sender, c channelRow, m channel.ZaloText, sem chan struct{}, wg *sync.WaitGroup) {
	approvers, err := loadApprovers(ctx, s.cfg.DB.Reader(), channel.ZaloPersonal)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: zalo-personal: a reply could not be checked", "error", err.Error())
		return
	}
	listed := slices.ContainsFunc(approvers, func(a Approver) bool { return a.Address == m.From })
	if m.ID != "" && !s.zaloSeen.add(m.ID) { // Zalo may deliver a message again (a reconnect): take it once
		return
	}
	code, approve, isCode := normReplyCode(m.Text)
	if !isCode { // nothing else decides or links anything (D-447: a Zalo account is linked by a confirm link, never by a reply)
		if !listed {
			s.noteZaloStranger(ctx, m)
		}
		return
	}
	// The channel may have been turned off or changed since the connection opened (the watcher looks every 30 s): decide nothing then.
	now, err := loadChannel(ctx, s.cfg.DB.Reader(), channel.ZaloPersonal)
	if err != nil || !approvalsReady(now) || now.Rev != c.Rev {
		return
	}
	select {
	case sem <- struct{}{}:
	default: // every worker is busy (each answer is a real Zalo message): dropped; the approver sends it again or decides in Vedette
		s.cfg.Log.DebugContext(ctx, "notify: zalo-personal: every worker is busy, a reply was dropped")
		return
	}
	wg.Go(func() {
		defer func() { <-sem }()
		s.decideZaloCode(ctx, snd, m.From, code, approve, listed)
	})
}

func (s *Service) decideZaloCode(ctx context.Context, snd channel.Sender, from, code string, approve, listed bool) {
	dctx, cancel := context.WithTimeout(ctx, decideBudget)
	res, err := s.cfg.Decisions.Decide(dctx, Decision{Channel: channel.ZaloPersonal, ExternalID: from, Approve: approve, Code: code})
	cancel()
	text := res.Message
	switch {
	case err != nil:
		s.cfg.Log.WarnContext(ctx, "notify: zalo-personal: the decision could not be recorded", "error", err.Error())
		text = answerFailed
	case text == "" && recordedDecision(res.Status):
		text = answerTaken
	case text == "":
		text = answerRefused
	}
	if listed {
		s.answerZalo(ctx, snd, from, text, res.Status)
	}
	if err == nil && recordedDecision(res.Status) && idRE.MatchString(res.RequestID) {
		s.publishDecided(ctx, res.RequestID, res.Status, from, channel.ZaloPersonal)
	}
}

// answerZalo sends the private answer to the approver who replied, through the channel's session; it still runs when ctx ended. A
// "rate_limited" refusal is not answered, nor more than zaloAnswers answers per approver in zaloAnswerEvery: each answer is a real
// message from the box's account, and a flood of them is what gets a personal account locked (D-46).
func (s *Service) answerZalo(ctx context.Context, snd channel.Sender, to, text, status string) {
	if status == "rate_limited" || !s.zaloAnswerBudget.due(to, time.Now()) {
		return
	}
	d, err := s.zaloTo(snd, to)
	if err != nil {
		return
	}
	actx, stop := context.WithTimeout(context.WithoutCancel(ctx), zaloAnswerWait)
	defer stop()
	if _, err := d.Send(actx, channel.Message{Kind: channel.KindReply, Severity: "info", Title: text}); err != nil {
		s.cfg.Log.DebugContext(ctx, "notify: zalo-personal: a reply could not be answered", "error", err.Error())
	}
}

// normReplyCode is the normalisation of spec 7.1: ASCII white space trimmed at both ends, ASCII letters upper-cased, then the form
// A-/R- and 6 characters of the alphabet. Anything else is not a code.
func normReplyCode(s string) (code string, approve, ok bool) {
	s = strings.Trim(s, " \t\n\v\f\r")
	if len(s) != 8 {
		return "", false, false
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	if (b[0] != 'A' && b[0] != 'R') || b[1] != '-' {
		return "", false, false
	}
	for _, c := range b[2:] {
		if !strings.ContainsRune(replyAlphabet, rune(c)) {
			return "", false, false
		}
	}
	return string(b), b[0] == 'A', true
}

// noteZaloStranger writes one audit row "notify.zalo_message" for a message from a sender who is not an approver on the channel: at
// most once a day per sender and 20 rows an hour in all, so a stranger cannot flood the log.
func (s *Service) noteZaloStranger(ctx context.Context, m channel.ZaloText) {
	if !s.zaloNotes.due(m.From, time.Now()) {
		return
	}
	detail := "Zalo user ID " + m.From + " sent a message to the account of the Zalo (personal) channel. It is not an approver on that channel."
	if m.Name != "" {
		detail += " Shown name: " + m.Name + "."
	}
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		return s.record(ctx, tx, systemUser, "notify.zalo_message", m.From, clip(detail, 400))
	})
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: zalo-personal: a message could not be noted", "error", err.Error())
	}
}

// zaloRetry is the wait of the listener between connections, for one revision of the channel: saving the channel starts afresh. It
// never gives up (codes keep going out while the channel takes approvals): at worst it tries every 30 minutes.
type zaloRetry struct {
	mu    sync.Mutex
	rev   int64
	fails int
	next  time.Time
}

func (r *zaloRetry) due(rev int64, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rev != r.rev {
		r.rev, r.fails, r.next = rev, 0, time.Time{}
	}
	return !now.Before(r.next)
}

// after records how a connection ended.
func (r *zaloRetry) after(err error, lived time.Duration, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var be *channel.BackoffError
	switch {
	case errors.Is(err, channel.ErrZaloReplaced):
		r.next = now.Add(zaloReplacedWait)
		return
	case errors.As(err, &be): // the channel's sign-ins are paused (the alert sender's state): wait it out, not a failure of the listener
		r.next = be.Until
		return
	case lived >= zaloHealthy:
		r.fails, r.next = 0, time.Time{}
		return
	}
	r.fails++
	d := zaloListenEvery
	for i := 1; i < r.fails && d < zaloRetryMax; i++ {
		d *= 2
	}
	r.next = now.Add(min(d, zaloRetryMax))
}

// zaloBudget allows a few events per key in a window (the private answers of the listener).
type zaloBudget struct {
	mu   sync.Mutex
	seen map[string][]time.Time
}

func (b *zaloBudget) due(key string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen == nil {
		b.seen = map[string][]time.Time{}
	}
	keep := b.seen[key][:0]
	for _, t := range b.seen[key] {
		if now.Sub(t) < zaloAnswerEvery {
			keep = append(keep, t)
		}
	}
	if len(keep) >= zaloAnswers {
		b.seen[key] = keep
		return false
	}
	b.seen[key] = append(keep, now)
	return true
}

// zaloNotes rations the audit rows of noteZaloStranger.
type zaloNotes struct {
	mu     sync.Mutex
	last   map[string]time.Time
	hour   time.Time
	inHour int
}

func (n *zaloNotes) due(from string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.last == nil {
		n.last = map[string]time.Time{}
	}
	if t, ok := n.last[from]; ok && now.Sub(t) < zaloNoteEvery {
		return false
	}
	if now.Sub(n.hour) >= time.Hour {
		n.hour, n.inHour = now, 0
	}
	if n.inHour >= zaloNotesPerHour {
		return false
	}
	if len(n.last) >= zaloNoteSenders {
		for k, t := range n.last {
			if now.Sub(t) >= zaloNoteEvery {
				delete(n.last, k)
			}
		}
		if len(n.last) >= zaloNoteSenders {
			return false
		}
	}
	n.last[from] = now
	n.inHour++
	return true
}
