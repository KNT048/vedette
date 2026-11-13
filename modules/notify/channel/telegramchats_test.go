package channel

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseTelegramChatsKeepsOnlyWellFormedChatsNewestFirst(t *testing.T) {
	t.Parallel()
	var sb strings.Builder
	sb.WriteString(`{"ok":true,"result":[`)
	for i := 1; i <= 14; i++ { // fourteen distinct chats: only the ten newest come back
		sb.WriteString(`{"update_id":` + strconv.Itoa(i) + `,"message":{"chat":{"id":` + strconv.Itoa(100000+i) + `,"type":"private","first_name":"P` + strconv.Itoa(i) + `"}}},`)
	}
	sb.WriteString(`{"update_id":20,"message":{"chat":{"id":"123456","type":"private","first_name":"idAsString"}}},` + // a string id: refused
		`{"update_id":21,"message":{"chat":{"id":1.5e10,"type":"private","first_name":"float"}}},` +
		`{"update_id":22,"message":{"chat":{"id":99999,"type":"bot","first_name":"unknown type"}}},` +
		`{"update_id":23,"message":{"chat":{"id":-1001234567890,"type":"supergroup","title":"\u202e\u0000Ops` + strings.Repeat("x", 200) + `","username":"bad name!"}}},` +
		`"garbage",{"update_id":24}]}`)
	got, err := ParseTelegramChats([]byte(sb.String()))
	if err != nil || len(got) != maxChats {
		t.Fatalf("got %d chats, %v", len(got), err)
	}
	g := got[0]
	if g.ID != "-1001234567890" || g.Kind != "supergroup" || g.Username != "" || !strings.HasPrefix(g.Name, "Ops") || len([]rune(g.Name)) > maxChatName {
		t.Errorf("group = %+v", g)
	}
	if got[1].Name != "P14" || got[9].Name != "P6" {
		t.Errorf("order = %q … %q", got[1].Name, got[9].Name)
	}
}

func TestParseTelegramChatsFailsClosed(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{"not json": `<html>`, "not ok": `{"ok":false,"description":"x"}`, "no result": `{"ok":true}`,
		"too big": `{"ok":true,"result":[],"x":"` + strings.Repeat("a", maxChatsBody) + `"}`} {
		if got, err := ParseTelegramChats([]byte(body)); err == nil || got != nil {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}
