package notify_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// fakeLinks is the ApproverLinks port: it records what it was asked.
type fakeLinks struct {
	mu     sync.Mutex
	linked bool
	err    error
	asked  [][3]string
}

func (f *fakeLinks) Linked(_ context.Context, userID string, ch channel.Type, address string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, [3]string{userID, string(ch), address})
	return f.linked, f.err
}

// sendToOneApprover sends a request with one email approver and returns the number of mails and the audit detail of the skip.
func sendToOneApprover(t *testing.T, links *fakeLinks) (mails int, skipDetail string, e *env) {
	t.Helper()
	opts := []func(*notify.Config){}
	if links != nil {
		opts = append(opts, func(c *notify.Config) { c.ApproverLinks = links })
	}
	e = newEnv(t, opts...)
	s := newFakeSMTP(t)
	e.email(s, func(in *notify.ChannelInput) {
		in.Approvals = true
		in.Approvers = []notify.Approver{{UserID: "u-op", Address: "it@acme.example"}}
	})
	if _, err := e.svc.SendApprovalRequest(e.ctx(), e.approvalReq("req-l7", channel.Email)); err != nil {
		t.Fatal(err)
	}
	_ = e.db.Reader().QueryRowContext(e.ctx(), `SELECT COALESCE(MAX(detail), '') FROM core_audit WHERE action = 'notify.approval_skipped'`).Scan(&skipDetail)
	return len(s.messages()), skipDetail, e
}

func TestContract_INV7_ApproverLinks_NilPortKeepsTodaysBehaviour(t *testing.T) {
	mails, detail, _ := sendToOneApprover(t, nil)
	if mails != 1 || detail != "" {
		t.Fatalf("mails = %d, skip = %q", mails, detail)
	}
}

func TestContract_INV7_ApproverLinks_LinkedApproverIsSentTheMessage(t *testing.T) {
	mails, detail, _ := sendToOneApprover(t, &fakeLinks{linked: true})
	if mails != 1 || detail != "" {
		t.Fatalf("mails = %d, skip = %q", mails, detail)
	}
}

func TestContract_INV7_ApproverLinks_UnlinkedApproverIsSkippedWithTheReason(t *testing.T) {
	mails, detail, e := sendToOneApprover(t, &fakeLinks{})
	if mails != 0 || detail != "req-l7: the approver has not linked this address in My account" {
		t.Fatalf("mails = %d, skip = %q", mails, detail)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.approval_skipped' AND target = 'u-op'`); n != 1 {
		t.Fatalf("skip audited %d times", n)
	}
	if len(e.tokens.recs) != 0 {
		t.Fatal("a token was made for a skipped approver")
	}
}

func TestContract_INV7_ApproverLinks_ErrorFailsClosed(t *testing.T) {
	mails, detail, e := sendToOneApprover(t, &fakeLinks{linked: true, err: errors.New("db down")})
	if mails != 0 || detail != "req-l7: the link could not be checked" {
		t.Fatalf("mails = %d, skip = %q", mails, detail)
	}
	if len(e.tokens.recs) != 0 {
		t.Fatal("a token was made when the link could not be checked")
	}
}

func TestContract_INV7_ApproverLinks_AsksAboutTheApprover(t *testing.T) {
	l := &fakeLinks{linked: true}
	sendToOneApprover(t, l)
	if len(l.asked) != 1 || l.asked[0] != [3]string{"u-op", "email", "it@acme.example"} {
		t.Fatalf("asked = %v", l.asked)
	}
}
