package notify

import (
	"strings"
	"testing"
)

func TestParseButtonData(t *testing.T) {
	nonce := "AbC-_0123zZ"
	for data, want := range map[string]struct {
		id      string
		approve bool
		ok      bool
	}{
		"a:act-1:" + nonce:                           {"act-1", true, true},
		"r:act-1:" + nonce:                           {"act-1", false, true},
		"a:ai:p-1:" + nonce:                          {"ai:p-1", true, true}, // a request id may hold ":"
		"A:act-1:" + nonce:                           {},
		"a:act-1:" + nonce[:10]:                      {},
		"a:act-1-" + nonce:                           {},
		"a::" + nonce:                                {},
		"a:act-1:" + nonce[:10] + "=":                {},
		"a:" + strings.Repeat("x", 51) + ":" + nonce: {}, // 65 bytes
		"": {},
	} {
		id, n, approve, ok := parseButtonData(data)
		if ok != want.ok || id != want.id || approve != want.approve || (ok && n != nonce) {
			t.Errorf("%q: %q %q %v %v", data, id, n, approve, ok)
		}
	}
	if maxButtonRequestID != 50 {
		t.Fatalf("maxButtonRequestID = %d", maxButtonRequestID)
	}
}

func FuzzParseButtonData(f *testing.F) {
	f.Add("a:act-1:AbC-_0123zZ")
	f.Add("r:ai:p-1:AbC-_0123zZ")
	f.Add("a::::::::::::::::")
	f.Fuzz(func(t *testing.T, data string) {
		id, nonce, approve, ok := parseButtonData(data)
		if !ok {
			if id != "" || nonce != "" || approve {
				t.Fatal("values with ok=false")
			}
			return
		}
		if !idRE.MatchString(id) || !nonceRE.MatchString(nonce) || len(data) > 64 {
			t.Fatalf("an unchecked value came out of %q: %q %q", data, id, nonce)
		}
		prefix := "r:"
		if approve {
			prefix = "a:"
		}
		if prefix+id+":"+nonce != data {
			t.Fatalf("%q does not rebuild from %q %q %v", data, id, nonce, approve)
		}
	})
}
