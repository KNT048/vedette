package notify

import (
	"context"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// An incident stores the names its devices had when it opened, in its device list and in the words of its title, what and action
// ("… fired a signature at Hewlett Packard (192.0.2.67)"). A device is renamed later: by a person, by what Vedette learns of it, or by
// a better naming rule after an update. The pages and the report read an incident with the name Devices gives each device now
// (currentNames); a device that is gone keeps the name the incident stored. The messages already sent are what they were: an incident's
// previews (what each channel received) keep the stored words.

// currentNames gives the incidents of list the current names of their devices (one batch read of the inventory). Without the port, or
// when it fails, the stored names stay (one log line, no error to the page).
func (s *Service) currentNames(ctx context.Context, list []Incident) {
	if s.cfg.Devices == nil || len(list) == 0 {
		return
	}
	var ids []string
	for _, i := range list {
		for _, d := range i.Devices {
			if d.ID != "" && !slices.Contains(ids, d.ID) {
				ids = append(ids, d.ID)
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	states, err := s.cfg.Devices.DeviceStates(ctx, ids)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "notify: current device names are not available, showing the stored ones", "error", err)
		return
	}
	for k := range list {
		renameIncident(&list[k], states)
	}
}

// renameIncident puts the current name of each device of i (states) in its device list, title, what and action. The stored name is
// either the device's name or its label (name and address, deviceLabel); the current one takes the same form.
func renameIncident(i *Incident, states map[string]DeviceState) {
	var pairs [][2]string
	for k, d := range i.Devices {
		st, ok := states[d.ID]
		if !ok || strings.TrimSpace(st.Name) == "" {
			continue // the device is gone, or nothing names it now: the stored name stays
		}
		cur := currentName(d.Name, st)
		if cur == d.Name || cur == "" {
			continue
		}
		pairs = append(pairs, [2]string{d.Name, cur})
		i.Devices[k].Name = cur
	}
	if len(pairs) == 0 {
		return
	}
	i.Title = clip(replaceNames(i.Title, pairs), 200)
	i.What = replaceNames(i.What, pairs)
	i.Action = replaceNames(i.Action, pairs)
}

// currentName is the name of st in the form of stored: the label (name and address) when the stored name was one, else the name.
func currentName(stored string, st DeviceState) string {
	if label := deviceLabel(st); st.Address != "" && strings.HasSuffix(stored, ")") && strings.Contains(stored, " (") {
		return label
	}
	return clip(strings.TrimSpace(st.Name), 200)
}

// replaceNames replaces, left to right, each whole occurrence of an old name of pairs ({old, new}) in text: one that does not
// continue a word or a dotted name on either side ("Dell" is not replaced in "Dellwood" nor in "Dell.Remote.Access"). At one place
// the longest old name wins, and a replaced name is never read again, so two devices whose names contain each other stay apart.
func replaceNames(text string, pairs [][2]string) string {
	if text == "" || len(pairs) == 0 {
		return text
	}
	pairs = slices.Clone(pairs)
	slices.SortStableFunc(pairs, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	var b strings.Builder
	for i := 0; i < len(text); {
		done := false
		if wordStart(text, i) {
			for _, p := range pairs {
				if p[0] != "" && strings.HasPrefix(text[i:], p[0]) && wordEnd(text, i+len(p[0])) {
					b.WriteString(p[1])
					i += len(p[0])
					done = true
					break
				}
			}
		}
		if !done {
			_, n := utf8.DecodeRuneInString(text[i:])
			b.WriteString(text[i : i+n])
			i += n
		}
	}
	return b.String()
}

// nameChar is a rune that continues a name: a letter, a digit, '-' or '_'.
func nameChar(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' }

// wordStart says whether a name may start at byte i of text: not right after a name rune or a dot.
func wordStart(text string, i int) bool {
	if i == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(text[:i])
	return !nameChar(r) && r != '.'
}

// wordEnd says whether a name may end at byte i of text: not right before a name rune, nor before a dot that a name rune follows, nor
// before a space and a capitalised word (the name would be the start of a longer one: "Hewlett Packard" in "Hewlett Packard Enterprise").
func wordEnd(text string, i int) bool {
	if i >= len(text) {
		return true
	}
	r, n := utf8.DecodeRuneInString(text[i:])
	if nameChar(r) || i+n >= len(text) {
		return !nameChar(r)
	}
	next, _ := utf8.DecodeRuneInString(text[i+n:])
	switch r {
	case '.':
		return !nameChar(next)
	case ' ':
		return !unicode.IsUpper(next)
	}
	return true
}
