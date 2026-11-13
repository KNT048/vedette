package channel

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// Finding the Chat ID (D-491): the box asks getUpdates once, WITHOUT an offset, so Telegram confirms nothing and the approval poller
// loses no update. Only chat.id, its type and a shown name come back; everything else Telegram sends is dropped.

const (
	maxChats     = 10 // chats offered to the customer, newest first
	maxChatName  = 64 // runes of a shown name
	maxChatsBody = maxUpdatesBody
)

// TelegramChat is a chat the bot has seen: ID as Telegram writes it (a private chat is positive, a group negative), Kind one of
// private, group, supergroup, channel, Name the person's name or the group's title and Username its public name without @.
type TelegramChat struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type tgChat struct {
	ID        json.RawMessage `json:"id"`
	Type      string          `json:"type"`
	Title     string          `json:"title"`
	Username  string          `json:"username"`
	FirstName string          `json:"first_name"`
	LastName  string          `json:"last_name"`
}

// tgSeen is every place a getUpdates update names a chat: a message (also edited, or in a channel), the bot being added or removed,
// a button press.
type tgSeen struct {
	UpdateID      *int64                  `json:"update_id"`
	Message       *struct{ Chat *tgChat } `json:"message"`
	EditedMessage *struct{ Chat *tgChat } `json:"edited_message"`
	ChannelPost   *struct{ Chat *tgChat } `json:"channel_post"`
	MyChatMember  *struct{ Chat *tgChat } `json:"my_chat_member"`
	CallbackQuery *struct {
		Message *struct{ Chat *tgChat } `json:"message"`
	} `json:"callback_query"`
}

func (u tgSeen) chat() *tgChat {
	for _, m := range []*struct{ Chat *tgChat }{u.Message, u.EditedMessage, u.ChannelPost, u.MyChatMember} {
		if m != nil && m.Chat != nil {
			return m.Chat
		}
	}
	if u.CallbackQuery != nil && u.CallbackQuery.Message != nil {
		return u.CallbackQuery.Message.Chat
	}
	return nil
}

// FindChats lists the chats of the updates Telegram holds for the bot, newest first, at most ten. It sends no offset (nothing is
// confirmed) and asks for no waiting; allowed_updates names the kinds that show a chat, plus callback_query so a later approval poller (which relies on the stored list) loses nothing. The answer is untrusted: see ParseTelegramChats.
func (b *TelegramBot) FindChats(ctx context.Context) ([]TelegramChat, error) {
	args := map[string]any{"timeout": 0, "limit": maxUpdates, "allowed_updates": []string{"message", "edited_message", "channel_post", "my_chat_member", "callback_query"}}
	ans, err := b.call(ctx, "getUpdates", args, defaultTimeout, maxChatsBody+1)
	if err != nil {
		return nil, err
	}
	return ParseTelegramChats(ans)
}

// ParseTelegramChats reads a getUpdates answer (fail-closed: too big, not JSON or not ok is an error) into the distinct chats whose
// id, type and names have their documented form, newest update first. An update that cannot be read is skipped.
func ParseTelegramChats(body []byte) ([]TelegramChat, error) {
	if len(body) > maxChatsBody {
		return nil, &ProviderError{Channel: Telegram, Reason: "the updates answer is too big"}
	}
	var env struct {
		OK          bool              `json:"ok"`
		Result      []json.RawMessage `json:"result"`
		Description string            `json:"description"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, &ProviderError{Channel: Telegram, Reason: "the updates answer could not be read"}
	}
	if !env.OK || env.Result == nil {
		return nil, &ProviderError{Channel: Telegram, Reason: "the updates answer was not ok: " + reasonFrom([]byte(env.Description))}
	}
	if len(env.Result) > maxUpdates {
		return nil, &ProviderError{Channel: Telegram, Reason: "the updates answer has too many updates"}
	}
	type seen struct {
		at   int64
		chat TelegramChat
	}
	best := map[string]seen{}
	for i, raw := range env.Result {
		var u tgSeen
		if json.Unmarshal(raw, &u) != nil {
			continue
		}
		c := u.chat()
		if c == nil {
			continue
		}
		at := int64(i) // the list is in update order; a good update_id only refines it
		if u.UpdateID != nil && *u.UpdateID >= 0 && *u.UpdateID < 1<<62 {
			at = *u.UpdateID
		}
		out, ok := checkChat(*c)
		if !ok {
			continue
		}
		if old, dup := best[out.ID]; !dup || at >= old.at {
			best[out.ID] = seen{at, out}
		}
	}
	all := make([]seen, 0, len(best))
	for _, s := range best {
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at > all[j].at })
	if len(all) > maxChats {
		all = all[:maxChats]
	}
	out := make([]TelegramChat, 0, len(all))
	for _, s := range all {
		out = append(out, s.chat)
	}
	return out, nil
}

// checkChat keeps a chat whose id is a number the channel accepts as Chat ID and whose type is known; names are cleaned to one line.
func checkChat(c tgChat) (TelegramChat, bool) {
	id := string(c.ID)
	if !telegramChatIDRE.MatchString(id) || !telegramChatRE.MatchString(id) {
		return TelegramChat{}, false
	}
	switch c.Type {
	case "private", "group", "supergroup", "channel":
	default:
		return TelegramChat{}, false
	}
	user := c.Username
	if user != "" && !telegramUserRE.MatchString(user) {
		user = ""
	}
	name := c.Title
	if c.Type == "private" {
		name = strings.TrimSpace(Line(c.FirstName, maxChatName) + " " + Line(c.LastName, maxChatName))
	}
	return TelegramChat{ID: id, Kind: c.Type, Name: Line(name, maxChatName), Username: user}, true
}
