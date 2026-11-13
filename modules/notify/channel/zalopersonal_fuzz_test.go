package channel

import (
	"encoding/json"
	"regexp"
	"testing"
	"unicode/utf8"
)

// The answers of a QR sign-in and of the look-ups come from Zalo and are untrusted (rules/security.md): whatever they hold, the parsers
// do not panic, keep only digit ids, and cap names and lists. `go test` runs the seeds; `go test -fuzz` explores further.

var qrPathRE = regexp.MustCompile(`^(M\d+ \d+h\d+v1h-\d+z)*$`)

func FuzzZaloQRPath(f *testing.F) {
	f.Add(qrPNGBytes())
	f.Add([]byte("\x89PNG\r\n\x1a\n"))
	f.Add([]byte("<svg/>"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		img, err := zaloQRPath(raw)
		if err != nil {
			return
		}
		if img.Size < 21+8 || img.Size > zaloQRMaxSide+8 || !qrPathRE.MatchString(img.Path) {
			t.Fatalf("redrawn as size %d path %.80q", img.Size, img.Path)
		}
	})
}

func checkContact(t *testing.T, c ZaloContact) {
	t.Helper()
	if !zaloPersonalUserRE.MatchString(c.ID) || utf8.RuneCountInString(c.Name) > zaloNameMax || !utf8.ValidString(c.Name) || c.Members < 0 {
		t.Fatalf("contact %+v", c)
	}
}

func FuzzZaloLookupAnswers(f *testing.F) {
	f.Add(`[{"userId":"7000000001","displayName":"An","zaloName":"x"},{"userId":12,"displayName":"\u202e"}]`)
	f.Add(`{"gridVerMap":{"8000000001":"1","nope":"1"},"gridInfoMap":{"8000000001":{"name":"IT","totalMember":-3}}}`)
	f.Add(`{"groupId":8000000009,"name":"Night shift","totalMember":12,"uid":"7000000005","zalo_name":"Chi"}`)
	f.Add(`null`)
	f.Fuzz(func(t *testing.T, s string) {
		data := json.RawMessage(s)
		if l, err := parseZaloFriends(data); err == nil {
			if len(l) > zaloMaxContacts {
				t.Fatalf("%d friends", len(l))
			}
			for _, c := range l {
				checkContact(t, c)
			}
		}
		if ids, err := parseZaloGroupIDs(data); err == nil {
			if len(ids) > zaloMaxGroups {
				t.Fatalf("%d groups", len(ids))
			}
			for _, id := range ids {
				if !zaloPersonalUserRE.MatchString(id) {
					t.Fatalf("group id %q", id)
				}
			}
			if l, err := parseZaloGroupInfo(data, ids); err == nil {
				for _, c := range l {
					checkContact(t, c)
				}
			}
		}
		if c, err := parseZaloGroupLink(data); err == nil {
			checkContact(t, c)
		}
		if c, err := parseZaloFoundUser(data); err == nil {
			checkContact(t, c)
		}
	})
}
