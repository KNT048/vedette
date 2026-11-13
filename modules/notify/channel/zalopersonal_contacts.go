package channel

// Finding the recipient and the approvers of the Zalo personal channel (D-447): the account's friends and groups, a group behind an invite
// link, a person behind a phone number. Read from zca-js v2.2.0 (MIT) src/apis/getAllFriends.ts, getAllGroups.ts, getGroupInfo.ts,
// getGroupLinkInfo.ts and findUser.ts, re-implemented here. Every answer is untrusted: ids must be digits, names are cleaned and cut,
// lists are capped.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

const (
	zaloMaxContacts  = 2000     // friends asked for and kept
	zaloMaxGroups    = 300      // groups kept
	zaloGroupBatch   = 50       // groups per getmg-v2 request
	zaloContactsBody = 4 << 20  // one contact-list answer
	zaloNameMax      = 64       // runes of a shown name
	zaloNotFoundCode = 216      // findUser: zca-js does not treat it as an error; no account (or it cannot be found by phone)
	zaloContactLimit = 16 << 20 // decrypted contact list, base64 text included
)

// ErrZaloNotFound means there is no Zalo account or group behind a phone number or an invite link.
var ErrZaloNotFound = errors.New("notify: zalo-personal: not found")

// ZaloContact is a person or a group the box's account can send to. Members is the size of a group (0 = not given).
type ZaloContact struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Group   bool   `json:"group"`
	Members int    `json:"members"`
}

var zaloInviteRE = regexp.MustCompile(`^(?i:https?://)?(?i:zalo\.me)/g/([A-Za-z0-9]{6,40})/?$`)

// ZaloInviteLink reads a group invite link (zalo.me/g/<code>, with or without https://) and returns it as https://zalo.me/g/<code>.
func ZaloInviteLink(s string) (string, bool) {
	m := zaloInviteRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return "https://zalo.me/g/" + m[1], true
}

// ZaloPhone reads a Vietnamese phone number (0 and 9 digits, or 84 / +84 and 9 digits; spaces, dots and dashes are ignored) and returns
// it as Zalo searches it: 84 and 9 digits.
func ZaloPhone(s string) (string, bool) {
	s = strings.NewReplacer(" ", "", ".", "", "-", "").Replace(strings.TrimSpace(s))
	if !zaloPhoneRE.MatchString(s) {
		return "", false
	}
	if s = strings.TrimPrefix(s, "+"); strings.HasPrefix(s, "0") {
		s = "84" + s[1:]
	}
	return s, true
}

// NewZaloAccount is a Zalo personal session without a recipient: it lists contacts and makes direct senders (ZaloPersonalTo), and its
// own Send refuses. It is how a QR sign-in is used before the channel is saved.
func NewZaloAccount(session secrets.Value, client *http.Client) (Sender, error) {
	sess, err := parseZaloSession(session.Reveal())
	if err != nil {
		return nil, cfgErr("bad_session", "The Zalo session is not usable. Sign in to Zalo again.")
	}
	return &zaloPersonalSender{raw: session, sess: sess, jar: append([]zaloCookie(nil), sess.cookies...), client: clientOrDefault(client),
		loginBase: zaloPersonalLoginBase, now: time.Now, sem: make(chan struct{}, 1)}, nil
}

// query runs fn once the session is signed in, one call at a time with the sends, under the sign-in pause of Send: a refused session
// (HTTP 401/403, or an error_code on the whole request) pauses sign-ins, except the first refusal of a reused session, which signs in
// once and runs fn once more. fn gets whether the sign-in was fresh.
func (z *zaloPersonalSender) query(ctx context.Context, fn func(fresh bool) error) error {
	select {
	case z.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-z.sem }()
	retried := false
	for {
		fresh := z.li == nil || z.now().Sub(z.li.at) > zaloLoginTTL
		if fresh {
			if now := z.now(); now.Before(z.notBefore) {
				return &BackoffError{Channel: ZaloPersonal, Until: z.notBefore}
			}
			if err := z.signIn(ctx); err != nil {
				z.fail()
				return err
			}
		}
		err := fn(fresh)
		var pe *ProviderError
		var se *StatusError
		switch {
		case err == nil:
			z.failures = 0
			return nil
		case errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden):
			z.li = nil
			z.fail()
			return err
		case errors.As(err, &pe) && pe.requestRefused && !fresh && !retried:
			z.li, retried = nil, true
		case errors.As(err, &pe) && pe.requestRefused:
			z.li = nil
			z.fail()
			return err
		default:
			return err
		}
	}
}

func accountOf(snd Sender) (*zaloPersonalSender, error) {
	z, ok := snd.(*zaloPersonalSender)
	if !ok {
		return nil, errors.New("notify: zalo-personal: contacts need a Zalo personal session")
	}
	return z, nil
}

// service returns the checked base URL of one service of the sign-in answer.
func (z *zaloPersonalSender) service(name string) (string, error) {
	if b := z.li.svc[name]; b != "" {
		return b, nil
	}
	return "", badAnswer("the sign-in answer named no " + name + " service")
}

// get sends a signed-in GET with the encrypted params (when given) and opens the answer.
func (z *zaloPersonalSender) get(ctx context.Context, base, path string, params any) (json.RawMessage, error) {
	q := url.Values{"zpw_ver": {strconv.Itoa(zaloAPIVersion)}, "zpw_type": {strconv.Itoa(zaloAPIType)}}
	if params != nil {
		plain, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		enc, err := zaloEncrypt(z.li.key, plain)
		if err != nil {
			return nil, err
		}
		q.Set("params", enc)
	}
	body, err := z.callN(ctx, http.MethodGet, base+path+"?"+q.Encode(), nil, zaloContactsBody)
	if err != nil {
		return nil, err
	}
	return openZaloAnswerN(body, z.li.key, zaloContactLimit, z.hide()...)
}

// ZaloContacts lists the friends and the groups of the account of snd (a Zalo personal sender or NewZaloAccount), at most 2000 friends
// and 300 groups, each list sorted by name.
func ZaloContacts(ctx context.Context, snd Sender) (friends, groups []ZaloContact, err error) {
	z, err := accountOf(snd)
	if err != nil {
		return nil, nil, err
	}
	err = z.query(ctx, func(bool) error {
		friends, groups = nil, nil
		profile, err := z.service("profile")
		if err != nil {
			return err
		}
		data, err := z.get(ctx, profile, "/api/social/friend/getfriends", map[string]any{
			"incInvalid": 1, "page": 1, "count": zaloMaxContacts, "avatar_size": 120, "actiontime": 0, "imei": z.sess.imei})
		if err != nil {
			return err
		}
		if friends, err = parseZaloFriends(data); err != nil {
			return err
		}
		ids, err := z.groupIDs(ctx)
		if err != nil {
			return err
		}
		groups, err = z.groupInfo(ctx, ids)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	byName := func(l []ZaloContact) {
		sort.SliceStable(l, func(i, j int) bool { return strings.ToLower(l[i].Name) < strings.ToLower(l[j].Name) })
	}
	byName(friends)
	byName(groups)
	return friends, groups, nil
}

// groupIDs lists the ids of the account's groups (getlg/v4), sorted, at most zaloMaxGroups.
func (z *zaloPersonalSender) groupIDs(ctx context.Context) ([]string, error) {
	poll, err := z.service("group_poll")
	if err != nil {
		return nil, err
	}
	data, err := z.get(ctx, poll, "/api/group/getlg/v4", nil)
	if err != nil {
		return nil, err
	}
	return parseZaloGroupIDs(data)
}

// groupInfo reads the names of groups (getmg-v2), zaloGroupBatch at a time. A group the answer leaves out is listed by its id.
func (z *zaloPersonalSender) groupInfo(ctx context.Context, ids []string) ([]ZaloContact, error) {
	base, err := z.service("group")
	if err != nil {
		return nil, err
	}
	out := make([]ZaloContact, 0, len(ids))
	for i := 0; i < len(ids); i += zaloGroupBatch {
		batch := ids[i:min(i+zaloGroupBatch, len(ids))]
		ver := map[string]int{}
		for _, id := range batch {
			ver[id] = 0
		}
		vm, _ := json.Marshal(ver) // a map of strings to ints always marshals
		plain, _ := json.Marshal(map[string]string{"gridVerMap": string(vm)})
		enc, err := zaloEncrypt(z.li.key, plain)
		if err != nil {
			return nil, err
		}
		body, err := z.callN(ctx, http.MethodPost, base+"/api/group/getmg-v2?"+url.Values{"zpw_ver": {strconv.Itoa(zaloAPIVersion)}, "zpw_type": {strconv.Itoa(zaloAPIType)}}.Encode(),
			strings.NewReader(url.Values{"params": {enc}}.Encode()), zaloContactsBody)
		if err != nil {
			return nil, err
		}
		data, err := openZaloAnswerN(body, z.li.key, zaloContactLimit, z.hide()...)
		if err != nil {
			return nil, err
		}
		got, err := parseZaloGroupInfo(data, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// ZaloGroupByLink finds the group behind an invite link (getGroupLinkInfo) and says whether the account is a member of it: a group
// message only reaches a group the account is in.
func ZaloGroupByLink(ctx context.Context, snd Sender, link string) (g ZaloContact, member bool, err error) {
	z, err := accountOf(snd)
	if err != nil {
		return g, false, err
	}
	norm, ok := ZaloInviteLink(link)
	if !ok {
		return g, false, cfgErr("bad_query", "A group invite link looks like https://zalo.me/g/abcdef123.")
	}
	err = z.query(ctx, func(bool) error {
		base, err := z.service("group")
		if err != nil {
			return err
		}
		data, err := z.get(ctx, base, "/api/group/link/ginfo", map[string]any{"link": norm, "avatar_size": 120, "member_avatar_size": 120, "mpage": 1})
		if err != nil {
			return notFound(err)
		}
		if g, err = parseZaloGroupLink(data); err != nil {
			return err
		}
		ids, err := z.groupIDs(ctx)
		if err != nil {
			return err
		}
		member = sort.SearchStrings(ids, g.ID) < len(ids) && ids[sort.SearchStrings(ids, g.ID)] == g.ID
		return nil
	})
	return g, member, err
}

// ZaloFindPhone finds the person behind a phone number (findUser). ErrZaloNotFound when there is none, or the owner does not let people
// find them by phone number.
func ZaloFindPhone(ctx context.Context, snd Sender, phone string) (ZaloContact, error) {
	z, err := accountOf(snd)
	if err != nil {
		return ZaloContact{}, err
	}
	p, ok := ZaloPhone(phone)
	if !ok {
		return ZaloContact{}, cfgErr("bad_query", "A phone number looks like 0912345678 or +84912345678.")
	}
	var c ZaloContact
	err = z.query(ctx, func(bool) error {
		base, err := z.service("friend")
		if err != nil {
			return err
		}
		data, err := z.get(ctx, base, "/api/friend/profile/get", map[string]any{"phone": p, "avatar_size": 240, "language": z.sess.language, "imei": z.sess.imei, "reqSrc": 40})
		if err != nil {
			return notFound(err)
		}
		c, err = parseZaloFoundUser(data)
		return err
	})
	return c, err
}

// notFound turns Zalo's "not found" (216, in either envelope) into ErrZaloNotFound, so it does not count as a refused session.
func notFound(err error) error {
	var pe *ProviderError
	if errors.As(err, &pe) && pe.Code == zaloNotFoundCode {
		return ErrZaloNotFound
	}
	return err
}

// zaloID reads an id given as a number or a string of digits; "" when it is not one.
func zaloID(raw json.RawMessage) string {
	id := strings.Trim(string(raw), `"`)
	if !zaloPersonalUserRE.MatchString(id) || strings.Trim(id, "0") == "" {
		return ""
	}
	return id
}

// zaloName is the first non-empty name, cleaned and cut to zaloNameMax runes.
func zaloName(names ...string) string {
	for _, n := range names {
		if n = Line(n, zaloNameMax); n != "" {
			return n
		}
	}
	return ""
}

// parseZaloServices takes the services ZaloContacts and the lookups use from the sign-in answer, each checked like the chat service.
// One that is missing or not a Zalo chat host is left out (the call that needs it then fails, a send does not).
func parseZaloServices(data json.RawMessage) map[string]string {
	var info struct {
		Map map[string][]string `json:"zpw_service_map_v3"`
	}
	out := map[string]string{}
	if json.Unmarshal(data, &info) != nil {
		return out
	}
	for _, name := range []string{"profile", "friend", "group_poll", "group"} {
		if l := info.Map[name]; len(l) > 0 {
			if b, err := zaloServiceBase(l[0]); err == nil {
				out[name] = b
			}
		}
	}
	return out
}

// ---- the answers of the look-ups, decrypted (untrusted: fuzzed in zalopersonal_fuzz_test.go) ----

// parseZaloFriends reads getfriends: a list of {userId, displayName, zaloName}; entries without a digit id are left out, at most zaloMaxContacts.
func parseZaloFriends(data json.RawMessage) ([]ZaloContact, error) {
	var list []struct {
		UserID      json.RawMessage `json:"userId"`
		DisplayName string          `json:"displayName"`
		ZaloName    string          `json:"zaloName"`
	}
	if json.Unmarshal(data, &list) != nil {
		return nil, badAnswer("the friend list was not understood")
	}
	var out []ZaloContact
	for _, f := range list {
		if id := zaloID(f.UserID); id != "" && len(out) < zaloMaxContacts {
			out = append(out, ZaloContact{ID: id, Name: zaloName(f.DisplayName, f.ZaloName)})
		}
	}
	return out, nil
}

// parseZaloGroupIDs reads getlg/v4: the keys of gridVerMap that are digit ids, sorted, at most zaloMaxGroups.
func parseZaloGroupIDs(data json.RawMessage) ([]string, error) {
	var all struct {
		Map map[string]json.RawMessage `json:"gridVerMap"`
	}
	if json.Unmarshal(data, &all) != nil {
		return nil, badAnswer("the group list was not understood")
	}
	ids := make([]string, 0, len(all.Map))
	for id := range all.Map {
		if zaloPersonalUserRE.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids[:min(len(ids), zaloMaxGroups)], nil
}

// parseZaloGroupInfo reads getmg-v2 for the groups asked (batch, already checked): a group the answer leaves out keeps its id as its name.
func parseZaloGroupInfo(data json.RawMessage, batch []string) ([]ZaloContact, error) {
	var info struct {
		Map map[string]struct {
			Name        string `json:"name"`
			TotalMember int    `json:"totalMember"`
		} `json:"gridInfoMap"`
	}
	if json.Unmarshal(data, &info) != nil {
		return nil, badAnswer("the group details were not understood")
	}
	out := make([]ZaloContact, 0, len(batch))
	for _, id := range batch {
		g := info.Map[id]
		out = append(out, ZaloContact{ID: id, Name: zaloName(g.Name, ""), Group: true, Members: max(g.TotalMember, 0)})
	}
	return out, nil
}

// parseZaloGroupLink reads link/ginfo: the group's id, name and size; no digit id is ErrZaloNotFound.
func parseZaloGroupLink(data json.RawMessage) (ZaloContact, error) {
	var info struct {
		GroupID     json.RawMessage `json:"groupId"`
		Name        string          `json:"name"`
		TotalMember int             `json:"totalMember"`
	}
	if json.Unmarshal(data, &info) != nil || zaloID(info.GroupID) == "" {
		return ZaloContact{}, ErrZaloNotFound
	}
	return ZaloContact{ID: zaloID(info.GroupID), Name: zaloName(info.Name, ""), Group: true, Members: max(info.TotalMember, 0)}, nil
}

// parseZaloFoundUser reads friend/profile/get: the person's uid and name; no digit uid is ErrZaloNotFound.
func parseZaloFoundUser(data json.RawMessage) (ZaloContact, error) {
	var u struct {
		UID         json.RawMessage `json:"uid"`
		ZaloName    string          `json:"zalo_name"`
		DisplayName string          `json:"display_name"`
	}
	if json.Unmarshal(data, &u) != nil || zaloID(u.UID) == "" {
		return ZaloContact{}, ErrZaloNotFound
	}
	return ZaloContact{ID: zaloID(u.UID), Name: zaloName(u.DisplayName, u.ZaloName)}, nil
}
