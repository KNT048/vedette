package main

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify"
)

// Sizes of the texts of a vulnerability notice. notify accepts up to 4000 characters; a message is read on a phone,
// so the adapter stays well under that. The KEV texts come from a feed on the internet: data, not instructions.
const (
	noticeTitleMax   = 200
	noticeProductMax = 120
	noticeNameMax    = 200
	noticeActionMax  = 600
)

// notifyFindings implements notify.FindingDirectory (S-ALERT-1) from three sources, none of them read by table:
// the findings module (the record: device, CVE, severity), the feeds KEV entry through findingsFeeds (name, product,
// the action CISA requires) and the inventory device names through notifyDevices. findings and feeds are read
// through deps at call time: notify is built before them (see buildServices).
type notifyFindings struct{ d *deps }

func (n notifyFindings) Finding(ctx context.Context, id string) (notify.FindingInfo, bool, error) {
	if n.d.Findings == nil {
		return notify.FindingInfo{}, false, nil
	}
	rec, err := n.d.Findings.Get(ctx, id)
	if errors.Is(err, findings.ErrNotFound) { // deleted between the event and now (the device went away)
		return notify.FindingInfo{}, false, nil
	}
	if err != nil {
		return notify.FindingInfo{}, false, err
	}
	var kev findings.KevInfo
	if fs, err := feedsService(*n.d); err == nil {
		got, err := findingsFeeds{st: fs.Store()}.KevInfo(ctx, []string{rec.CVE})
		if err != nil {
			return notify.FindingInfo{}, false, err
		}
		kev = got[rec.CVE]
	}
	info := notify.FindingInfo{CVE: plainText(rec.CVE, 40), Severity: notify.Severity(rec.Severity)}
	info.Product = plainText(kev.Display, noticeProductMax)
	if info.Product == "" {
		info.Product = "A product on your network"
	}
	info.Title = plainText(info.Product+" is being exploited ("+info.CVE+")", noticeTitleMax)
	list := "CISA"
	if kev.Source == findings.SourceVulnCheck {
		list = "VulnCheck KEV" // its entries are never called CISA's, and VulnCheck asks for its name wherever its data is shown (D-557)
	}
	what := list + " lists " + info.CVE + " as exploited in real attacks."
	if name := plainText(kev.Name, noticeNameMax); name != "" {
		what = list + " lists " + info.CVE + " (" + name + ") as exploited in real attacks."
	}
	info.What = what + " A device in your inventory runs " + info.Product + "."
	info.Action = plainText(kev.RequiredAction, noticeActionMax)
	if info.Action == "" {
		info.Action = "Open the finding in Vedette and follow its steps: update the software, or limit who can reach the device."
	}
	if n.d.Inventory == nil {
		return info, true, nil // no device name: notify sends nothing for a finding that matched no device
	}
	name, ok, err := notifyDevices{n.d.Inventory}.DeviceName(ctx, rec.AssetID)
	if err != nil {
		return notify.FindingInfo{}, false, err
	}
	if ok && name != "" {
		info.Devices = []string{plainText(name, 120)}
	}
	return info, true, nil
}

// plainText makes feed text safe to show: control characters and line breaks become spaces, invisible format characters
// (Unicode Cf) go, runs of spaces collapse, and the result is cut to max characters. Adapters render it as text, never as markup.
func plainText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r) || r == utf8.RuneError:
			return ' '
		case unicode.Is(unicode.Cf, r): // invisible format characters: bidi overrides (U+202E), zero-width ones (D-552 review LOW-4)
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > limit {
		return strings.TrimSpace(string(r[:limit-1])) + "…"
	}
	return s
}
