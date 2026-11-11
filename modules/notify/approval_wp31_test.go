package notify_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/notify/channel"
)

// D-175: response decides whether a chat message may carry buttons (NoChatButtons); notify obeys, and an approval message holds the
// text of the whole change (up to MaxApprovalWhat), not the 1000 characters of an alert.
func TestWP31_NoChatButtonsAndTheWholeChangeInTheMessage(t *testing.T) {
	var l []string
	for i := range 60 {
		l = append(l, fmt.Sprintf("show clock %02d", i))
	}
	what := strings.Join(l, "\n") + "\nLAST-LINE-OF-THE-CHANGE" // well over 1000 characters

	te := newTGEnv(t)
	req := te.approvalReq("act-1", channel.Telegram)
	req.What = what
	req.NoChatButtons = true
	if _, err := te.svc.SendApprovalRequest(te.ctx(), req); err != nil {
		t.Fatal(err)
	}
	te.tg.mu.Lock()
	_, has := te.tg.sends[0]["reply_markup"]
	text, _ := te.tg.sends[0]["text"].(string)
	te.tg.mu.Unlock()
	if has || te.count(`SELECT COUNT(*) FROM notify_tg_button`) != 0 {
		t.Fatal("buttons were sent although response said none")
	}
	if !strings.Contains(text, "LAST-LINE-OF-THE-CHANGE") || !strings.Contains(text, "This message has no buttons") || len([]rune(text)) > 4096 {
		t.Fatalf("the message (%d characters) is cut or has no pointer to Vedette:\n%s", len([]rune(text)), text)
	}

	te2 := newTGEnv(t)
	req = te2.approvalReq("act-2", channel.Telegram)
	req.What = what
	if _, err := te2.svc.SendApprovalRequest(te2.ctx(), req); err != nil {
		t.Fatal(err)
	}
	te2.tg.mu.Lock()
	_, has = te2.tg.sends[0]["reply_markup"]
	text, _ = te2.tg.sends[0]["text"].(string)
	te2.tg.mu.Unlock()
	if !has || !strings.Contains(text, "LAST-LINE-OF-THE-CHANGE") {
		t.Fatalf("without the flag the buttons stay (%v) and the whole change is in the text", has)
	}
}
